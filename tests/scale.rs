// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result, ensure};
use confidential_cluster_operator_test_lib::*;
use ignition_config::v3_6::{Config, Resource as IgnitionResource};
use k8s_openapi::api::core::v1::{ConfigMap, Node, ObjectReference, Secret};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use k8s_openapi::{ByteString, api::apps::v1::Deployment};
use kube::api::{ListParams, ObjectMeta, Patch};
use kube::{Api, ResourceExt, core::Expression, runtime::wait::await_condition};
use serde_json::json;
use trusted_cluster_operator_test_utils::tls::renew_certificate;
use std::{collections::BTreeMap, time::Duration};
use tokio::{process::Command, time::timeout};
use trusted_cluster_operator_lib::certificates::Certificate;
use trusted_cluster_operator_lib::trustee_certs::{TRUSTEE_CERTS_CONFIG_MAP, TrusteeCerts};
use trusted_cluster_operator_lib::{
    ApprovedImage, ApprovedImageSpec, MACHINE_NODE_LABEL, endpoints::*, get_env,
};
use trusted_cluster_operator_test_utils::virt::{NodeBackend, sh_exec};
use trusted_cluster_operator_test_utils::*;

const MAPI_NS: &str = "openshift-machine-api";
const MAPI_ROLE: &str = "machineconfiguration.openshift.io/role";
const MACHINESET_LABEL: &str = "machine.openshift.io/cluster-api-machineset";
const MACHINEROLE_LABEL: &str = "machine.openshift.io/cluster-api-machine-role";

const NODE_ROLE_PREFIX: &str = "node-role.kubernetes.io/";

const AZURE_RESOURCE_ENV: &str = "AZURE_RESOURCE_ID";
const BOOTC_IMAGE_ENV: &str = "BOOTC_IMAGE";
const BOOTC_APPROVED_IMAGE: &str = "scale-bootc";
const TRUSTEE_CERT: &str = "trustee-cert";
const MANAGED_TRUSTEE_TLS: &str = "trustee-serving-tls";

trait TeePlatform {
    fn add_tee_options(
        &self,
        provider_spec: &mut BTreeMap<String, serde_json::Value>,
        ign_secret_name: String,
    ) -> Result<()>;
}

struct Azure {}

impl TeePlatform for Azure {
    fn add_tee_options(
        &self,
        provider_spec: &mut BTreeMap<String, serde_json::Value>,
        ign_secret_name: String,
    ) -> Result<()> {
        let resource_id = Some(get_env(AZURE_RESOURCE_ENV)?);
        let image = AzureMachineProviderSpecImage {
            resource_id,
            ..Default::default()
        };
        let image_value = serde_json::to_value(image)?;
        provider_spec.insert("image".to_string(), image_value);

        let security_profile = AzureMachineProviderSpecSecurityProfile {
            settings: Some(AzureMachineProviderSpecSecurityProfileSettings {
                confidential_vm: Some(AzureMachineProviderSpecSecurityProfileSettingsConfidentialVm {
                    uefi_settings: AzureMachineProviderSpecSecurityProfileSettingsConfidentialVmUefiSettings {
                        secure_boot: Some(AzureMachineProviderSpecSecurityProfileSettingsConfidentialVmUefiSettingsSecureBoot::Enabled),
                        virtualized_trusted_platform_module: Some(AzureMachineProviderSpecSecurityProfileSettingsConfidentialVmUefiSettingsVirtualizedTrustedPlatformModule::Enabled),
                    }
                }),
                security_type: AzureMachineProviderSpecSecurityProfileSettingsSecurityType::ConfidentialVm,
                trusted_launch: None,
            }),
            ..Default::default()
        };
        let sec_value = serde_json::to_value(security_profile)?;
        provider_spec.insert("securityProfile".to_string(), sec_value);

        let os_disk_key = "osDisk";
        let ctx = format!("ProviderSpec had no {os_disk_key}");
        let os_disk_raw = provider_spec.get(os_disk_key).context(ctx)?;
        let mut os_disk: AzureMachineProviderSpecOsDisk =
            serde_json::from_value(os_disk_raw.clone())?;
        let managed_disk = os_disk.managed_disk.get_or_insert_default();
        let disk_security_profile = managed_disk.security_profile.get_or_insert_default();
        disk_security_profile.security_encryption_type = Some(AzureMachineProviderSpecOsDiskManagedDiskSecurityProfileSecurityEncryptionType::VmGuestStateOnly);
        let os_disk_value = serde_json::to_value(os_disk)?;
        provider_spec.insert(os_disk_key.to_string(), os_disk_value);

        let vm_size_value = serde_json::Value::String("Standard_DC4ads_v5".to_string());
        provider_spec.insert("vmSize".to_string(), vm_size_value);

        let accel_value = serde_json::Value::Bool(false);
        provider_spec.insert("acceleratedNetworking".to_string(), accel_value);

        let user_data_secret = AzureMachineProviderSpecUserDataSecret {
            name: Some(ign_secret_name),
            ..Default::default()
        };
        let user_data_value = serde_json::to_value(user_data_secret)?;
        provider_spec.insert("userDataSecret".to_string(), user_data_value);

        Ok(())
    }
}

struct OpenShiftNode {
    node_name: String,
}

#[async_trait::async_trait]
impl NodeBackend for OpenShiftNode {
    async fn ssh_exec(&self, command: &str) -> Result<String> {
        let mut cmd = Command::new("oc");
        cmd.args(["debug", &format!("node/{}", self.node_name)]);
        cmd.args(["-n", "default", "--", "nsenter", "-at1"]);
        cmd.args(["sh", "-c", command]);
        sh_exec(&mut cmd).await
    }
}

fn create_mcp_object(machineset_name: &str) -> MachineConfigPool {
    let match_expressions = MachineConfigPoolMachineConfigSelectorMatchExpressions {
        key: MAPI_ROLE.to_string(),
        operator: "In".to_string(),
        values: Some(vec!["worker".to_string(), machineset_name.to_string()]),
    };
    MachineConfigPool {
        metadata: ObjectMeta {
            name: Some(machineset_name.to_string()),
            ..Default::default()
        },
        spec: MachineConfigPoolSpec {
            machine_config_selector: Some(MachineConfigPoolMachineConfigSelector {
                match_expressions: Some(vec![match_expressions]),
                ..Default::default()
            }),
            node_selector: Some(MachineConfigPoolNodeSelector {
                match_labels: Some(BTreeMap::from([(
                    format!("{NODE_ROLE_PREFIX}{machineset_name}"),
                    String::new(),
                )])),
                ..Default::default()
            }),
            ..Default::default()
        },
        ..Default::default()
    }
}

async fn create_mcp(test_ctx: &TestContext, machineset_name: &str, mc_name: &str) -> Result<()> {
    let mcp = create_mcp_object(machineset_name);
    let mcps: Api<MachineConfigPool> = Api::all(test_ctx.client().clone());
    test_ctx.info(format!("Creating MachineConfigPool {machineset_name}"));
    mcps.create(&Default::default(), &mcp).await?;

    let has_mc = |mcp: Option<&MachineConfigPool>| {
        let chk_mc = |mc: &ObjectReference| mc.name.as_ref().map(|n| n == mc_name).unwrap_or(false);
        let chk_srcs = |srcs: &Vec<ObjectReference>| srcs.iter().any(chk_mc);
        let chk_conf =
            |conf: &MachineConfigPoolStatusConfiguration| conf.source.as_ref().map(chk_srcs);
        let chk_st = |st: &MachineConfigPoolStatus| st.configuration.as_ref().and_then(chk_conf);
        let chk_pool = |p: &MachineConfigPool| p.status.as_ref().and_then(chk_st);
        mcp.and_then(chk_pool).unwrap_or(false)
    };
    let mc_in = await_condition(mcps.clone(), machineset_name, has_mc);
    let ctx = format!("waiting for mcp {machineset_name} to have mc {mc_name} as config source");
    let duration = scaled_duration(60);
    timeout(duration, mc_in).await.context(ctx)??;
    test_ctx.info(format!(
        "MachineConfigPool {machineset_name} has registered {mc_name} as config source"
    ));

    let is_updated = |mcp: Option<&MachineConfigPool>| {
        let chk_cond = |c: &Condition| c.type_ == "Updated" && c.status == "True";
        let chk_conds = |cs: &Vec<Condition>| cs.iter().any(chk_cond);
        let chk_st = |st: &MachineConfigPoolStatus| st.conditions.as_ref().map(chk_conds);
        let chk_pool = |p: &MachineConfigPool| p.status.as_ref().and_then(chk_st);
        mcp.and_then(chk_pool).unwrap_or(false)
    };
    let mcp_updated = await_condition(mcps.clone(), machineset_name, is_updated);
    let ctx = format!("waiting for mcp {machineset_name} to be updated");
    timeout(duration, mcp_updated).await.context(ctx)??;
    test_ctx.info(format!("MachineConfigPool {machineset_name} is updated"));
    Ok(())
}

fn add_register_server(
    config: &mut Config,
    register_server_url: String,
    register_server_cert: String,
) -> Result<()> {
    let resource = |s: String| IgnitionResource {
        source: Some(s),
        ..Default::default()
    };

    config.ignition.version = "3.6.0".to_string();

    let inner = config.ignition.config.as_mut();
    let ctx = "Ignition from MAPI had no merge";
    let merge = inner.and_then(|c| c.merge.as_mut()).context(ctx)?;
    merge.push(resource(register_server_url));

    let sec = config.ignition.security.as_mut();
    let cas = sec
        .and_then(|s| s.tls.as_mut())
        .and_then(|t| t.certificate_authorities.as_mut())
        .context("Ignition from MAPI had no CAs")?;
    cas.push(resource(register_server_cert));
    Ok(())
}

async fn extend_ign_secret(test_ctx: &TestContext, existing_secret_name: &str) -> Result<String> {
    let client = test_ctx.client();
    let ns = test_ctx.namespace();
    let secrets: Api<Secret> = Api::namespaced(client.clone(), MAPI_NS);
    let existing_secret = secrets.get(existing_secret_name).await?;

    let user_data_key = "userData";
    let ctx = "user data secret had no data";
    let existing_data = existing_secret.data.context(ctx)?;
    let existing_json = existing_data.get(user_data_key).context(ctx)?;
    let mut user_data: Config = serde_json::from_slice(&existing_json.0)?;

    let port = Some(REGISTER_SERVER_PORT);
    let register_server_url = get_cluster_url(client, ns, REGISTER_SERVER_SERVICE, port).await?;
    let reg_server_addr = format!("https://{register_server_url}/{REGISTER_SERVER_RESOURCE}");
    let root_pem = get_encoded_root_pem(client.clone(), ns).await?;
    add_register_server(&mut user_data, reg_server_addr, root_pem)?;
    let json = ByteString(serde_json::to_vec(&user_data)?);

    let new_secret_name = format!("{existing_secret_name}-cocl");
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(new_secret_name.clone()),
            namespace: Some(MAPI_NS.to_string()),
            ..Default::default()
        },
        data: Some(BTreeMap::from([(user_data_key.to_string(), json)])),
        ..Default::default()
    };

    test_ctx.info(format!(
        "Creating user data secret {new_secret_name} based on {existing_secret_name}"
    ));
    secrets.create(&Default::default(), &secret).await?;

    Ok(new_secret_name)
}

fn adapt_machineset(
    mset: &mut MachineSet,
    machineset_name: &str,
    ign_secret_name: String,
) -> Result<()> {
    let mset_name = mset.metadata.name.clone().unwrap();
    mset.metadata = ObjectMeta {
        name: Some(machineset_name.to_string()),
        ..Default::default()
    };
    mset.spec.replicas = Some(0);

    let mset_selector = mset.spec.selector.get_or_insert_default();
    let mset_match_labels = mset_selector.match_labels.get_or_insert_default();
    mset_match_labels.insert(MACHINESET_LABEL.to_string(), machineset_name.to_string());
    let mset_template = mset.spec.template.get_or_insert_default();
    let mset_template_meta = mset_template.metadata.get_or_insert_default();
    let mset_template_labels = mset_template_meta.labels.get_or_insert_default();
    mset_template_labels.insert(MACHINESET_LABEL.to_string(), machineset_name.to_string());
    let mset_template_spec = mset_template.spec.get_or_insert_default();
    let mset_template_spec_meta = mset_template_spec.metadata.get_or_insert_default();
    let mset_template_spec_labels = mset_template_spec_meta.labels.get_or_insert_default();
    let node_label = format!("{NODE_ROLE_PREFIX}{machineset_name}");
    mset_template_spec_labels.insert(node_label, String::new());

    mset_template_spec_labels.insert(MACHINE_NODE_LABEL.to_string(), String::new());

    let mset_spec = mset_template.spec.get_or_insert_default();
    let raw_mset_provider_spec = mset_spec.provider_spec.get_or_insert_default();
    let mset_provider_spec = raw_mset_provider_spec.value.get_or_insert_default();

    let platform = match mset_provider_spec.get("kind") {
        Some(serde_json::Value::String(s)) if s == "AzureMachineProviderSpec" => Azure {},
        Some(s) => panic!("unsupported MachineSet provider: {s}"),
        None => panic!("MachineSet {mset_name} had no provider",),
    };
    platform.add_tee_options(mset_provider_spec, ign_secret_name)
}

struct ScaleContext {
    machineset_name: String,
    mc_name: String,
    test_ctx: TestContext,
}

impl ScaleContext {
    async fn new(test_ctx: TestContext) -> Result<Self> {
        let client = test_ctx.client();
        let ns = test_ctx.namespace();
        let machineset_name = format!("worker-cvm-{ns}");
        let mc_name = format!("99-{machineset_name}");

        let bootc_image = get_env(BOOTC_IMAGE_ENV)?;
        let mc = MachineConfig {
            metadata: ObjectMeta {
                name: Some(mc_name.clone()),
                labels: Some(BTreeMap::from([
                    (MAPI_ROLE.to_string(), machineset_name.clone()),
                    (MACHINESET_LABEL.to_string(), machineset_name.clone()),
                ])),
                ..Default::default()
            },
            spec: MachineConfigSpec {
                os_image_url: Some(bootc_image.clone()),
                ..Default::default()
            },
        };
        let machineconfigs: Api<MachineConfig> = Api::all(client.clone());
        test_ctx.info("Creating MachineConfig to override upgrade image");
        machineconfigs.create(&Default::default(), &mc).await?;
        create_mcp(&test_ctx, &machineset_name, &mc_name).await?;

        let images: Api<ApprovedImage> = Api::namespaced(client.clone(), ns);
        let image = ApprovedImage::new(
            BOOTC_APPROVED_IMAGE,
            ApprovedImageSpec { image: bootc_image },
        );
        images.create(&Default::default(), &image).await?;
        let info = format!("Waiting for ApprovedImage {BOOTC_APPROVED_IMAGE} to be Committed");
        test_ctx.info(&info);
        let chk = approved_image_has_committed_condition;
        let done = await_condition(images, BOOTC_APPROVED_IMAGE, chk);
        timeout(scaled_duration(300), done).await.context(info)??;

        let existing_secret_name = format!("{machineset_name}-user-data-managed");
        let secrets: Api<Secret> = Api::namespaced(client.clone(), MAPI_NS);
        wait_for_resource_created(&secrets, &existing_secret_name, scaled_timeout(600)).await?;
        let cocl_ign_secret_name = extend_ign_secret(&test_ctx, &existing_secret_name).await?;

        let machinesets: Api<MachineSet> = Api::namespaced(client.clone(), MAPI_NS);
        let sel = Expression::Equal(MACHINEROLE_LABEL.to_string(), "worker".to_string());
        let lp = ListParams::default().labels_from(&sel.into());
        let existing_msets = machinesets.list(&lp).await?;
        let ctx = "No existing worker machinesets found";
        let mut mset = existing_msets.items.first().context(ctx)?.clone();
        let mset_name = mset.metadata.name.clone().unwrap();
        adapt_machineset(&mut mset, &machineset_name, cocl_ign_secret_name)?;

        let info = format!("Creating MachineSet {machineset_name}, derived from {mset_name}");
        test_ctx.info(info);
        machinesets.create(&Default::default(), &mset).await?;

        Ok(Self {
            machineset_name,
            mc_name,
            test_ctx,
        })
    }

    async fn has_replicas(&self, replicas: i32, duration: Duration) -> Result<()> {
        let has_replicas = |mset: Option<&MachineSet>| {
            let chk_st = |st: &MachineSetStatus| st.ready_replicas.unwrap_or(0) == replicas;
            let chk_mset = |s: &MachineSet| s.status.as_ref().map(chk_st);
            mset.and_then(chk_mset).unwrap_or(false)
        };

        let machinesets: Api<MachineSet> = Api::namespaced(self.test_ctx.client().clone(), MAPI_NS);
        let machineset_name = &self.machineset_name;
        let replicas_ready = await_condition(machinesets, machineset_name, has_replicas);

        self.test_ctx.info(format!(
            "Waiting for MachineSet {machineset_name} to have desired number of replicas ({replicas})"
        ));
        let ctx = format!("MachineSet {machineset_name} did not have desired replicas",);
        timeout(duration, replicas_ready).await.context(ctx)??;
        let info = format!("MachineSet {machineset_name} achieved desired replicas");
        self.test_ctx.info(info);

        Ok(())
    }

    async fn scale_machineset(&self, count: u32) -> Result<()> {
        let machinesets: Api<MachineSet> = Api::namespaced(self.test_ctx.client().clone(), MAPI_NS);
        let patch = Patch::Merge(json!({
            "spec": {
                "replicas": count
            }
        }));
        self.test_ctx
            .info(format!("Updating MachineSet replicas to {count}"));
        machinesets
            .patch(&self.machineset_name, &Default::default(), &patch)
            .await?;
        Ok(())
    }

    async fn node(&self) -> Result<Node> {
        let client = self.test_ctx.client();
        let machineset_name = &self.machineset_name;
        let machines: Api<Machine> = Api::namespaced(client.clone(), MAPI_NS);
        let label = format!("{MACHINESET_LABEL}={machineset_name}");
        let list = machines.list(&ListParams::default().labels(&label)).await?;
        let machine = list
            .items
            .first()
            .with_context(|| format!("No machines found for MachineSet {machineset_name}"))?;
        let node_name = machine
            .status
            .as_ref()
            .and_then(|status| status.node_ref.as_ref())
            .and_then(|node_ref| node_ref.name.as_deref())
            .with_context(|| format!("MachineSet {machineset_name}'s Machine has no node name"))?;
        let nodes: Api<Node> = Api::all(client.clone());
        nodes
            .get(node_name)
            .await
            .with_context(|| format!("Getting node {node_name}"))
    }

    async fn cleanup(self) -> Result<()> {
        let client = self.test_ctx.client();
        let machineset_name = &self.machineset_name;
        let secret_name = format!("{machineset_name}-user-data-managed-cocl");

        self.test_ctx.info("Cleaning up");
        let machinesets: Api<MachineSet> = Api::namespaced(client.clone(), MAPI_NS);
        let machineconfigs: Api<MachineConfig> = Api::all(client.clone());
        let mcps: Api<MachineConfigPool> = Api::all(client.clone());
        let secrets: Api<Secret> = Api::namespaced(client.clone(), MAPI_NS);
        let approvedimages: Api<ApprovedImage> =
            Api::namespaced(client.clone(), self.test_ctx.namespace());

        let dp = Default::default();
        machinesets.delete(machineset_name, &dp).await?;
        machineconfigs.delete(&self.mc_name, &dp).await?;
        mcps.delete(machineset_name, &dp).await?;
        secrets.delete(&secret_name, &dp).await?;
        let duration = scaled_duration(60);
        wait_for_resource_deleted(&machinesets, machineset_name, duration).await?;
        self.test_ctx
            .info(format!("MachineSet {machineset_name} has been deleted"));
        wait_for_resource_deleted(&machineconfigs, &self.mc_name, duration).await?;
        self.test_ctx
            .info(format!("MachineConfig {} has been deleted", self.mc_name));
        wait_for_resource_deleted(&mcps, machineset_name, duration).await?;
        self.test_ctx.info(format!(
            "MachineConfigPool {machineset_name} has been deleted"
        ));
        wait_for_resource_deleted(&secrets, &secret_name, duration).await?;
        self.test_ctx
            .info(format!("Secret {secret_name} has been deleted"));
        approvedimages.delete(BOOTC_APPROVED_IMAGE, &dp).await?;
        wait_for_resource_deleted(&approvedimages, BOOTC_APPROVED_IMAGE, duration).await?;
        self.test_ctx.info(format!(
            "ApprovedImage {BOOTC_APPROVED_IMAGE} has been deleted"
        ));

        self.test_ctx.cleanup().await
    }
}

named_test!(
    async fn test_scale() -> anyhow::Result<()> {
        let test_ctx = setup!().await?;
        let scale_ctx = ScaleContext::new(test_ctx.clone()).await?;

        scale_ctx.scale_machineset(1).await?;
        scale_ctx.has_replicas(1, scaled_duration(900)).await?;

        let node_name = scale_ctx.node().await?.name_any();

        let backend = OpenShiftNode {
            node_name: node_name.clone(),
        };
        test_ctx.info(format!("Verifying encrypted root on node {node_name}"));
        let ns = test_ctx.namespace();
        let root_key = backend.get_root_key(test_ctx.client().clone(), ns).await?;
        let ctx = format!("Node {node_name} should have an encrypted root device");
        let result = backend.verify_encrypted_root(&root_key).await;
        result.context(ctx)?;
        test_ctx.info(format!("Node {node_name}: encrypted root verified"));

        scale_ctx.cleanup().await
    }
);

named_test!(
    async fn test_parallel_replicas() -> anyhow::Result<()> {
        let test_ctx = setup!().await?;
        let scale_ctx = ScaleContext::new(test_ctx.clone()).await?;

        scale_ctx.scale_machineset(2).await?;
        scale_ctx.has_replicas(2, scaled_duration(900)).await?;
        scale_ctx.cleanup().await
    }
);

named_test!(
    async fn test_operator_restart() -> anyhow::Result<()> {
        let test_ctx = setup!().await?;
        let scale_ctx = ScaleContext::new(test_ctx.clone()).await?;

        scale_ctx.scale_machineset(1).await?;
        scale_ctx.has_replicas(1, scaled_duration(900)).await?;

        test_ctx.info("Restarting trusted-cluster-operator");
        let deployments: Api<Deployment> =
            Api::namespaced(test_ctx.client().clone(), test_ctx.namespace());
        deployments.restart("trusted-cluster-operator").await?;

        scale_ctx.scale_machineset(0).await?;
        scale_ctx.has_replicas(0, scaled_duration(60)).await?;
        scale_ctx.scale_machineset(1).await?;
        scale_ctx.has_replicas(1, scaled_duration(900)).await?;

        scale_ctx.cleanup().await
    }
);

fn serving_certificate(secret: &Secret) -> Option<&ByteString> {
    secret
        .data
        .as_ref()?
        .get("tls.crt")
        .filter(|cert| !cert.0.is_empty())
}

async fn verify_tls_update(scale_ctx: &ScaleContext) -> Result<()> {
    let test_ctx = &scale_ctx.test_ctx;
    scale_ctx.scale_machineset(1).await?;
    scale_ctx.has_replicas(1, scaled_duration(900)).await?;

    let client = test_ctx.client();
    let ns = test_ctx.namespace();
    let original_node = scale_ctx.node().await?;
    let node_name = original_node.name_any();

    let certs: Api<Certificate> = Api::namespaced(client.clone(), ns);
    let secrets: Api<Secret> = Api::namespaced(client.clone(), ns);
    let source = certs.get(TRUSTEE_CERT).await?.spec.secret_name;
    let original = secrets.get(&source).await?;
    let original_cert = serving_certificate(&original).context("Trustee Secret has no tls.crt")?;

    test_ctx.info("Renewing the Trustee serving certificate");
    renew_certificate(client, ns, TRUSTEE_CERT).await?;
    let rotated = await_condition(secrets.clone(), &source, |secret: Option<&Secret>| {
        secret
            .and_then(serving_certificate)
            .is_some_and(|cert| cert != original_cert)
    });
    let rotated = timeout(scaled_duration(120), rotated)
        .await
        .context("Waiting for the Trustee certificate to renew")??;
    let renewed_cert = rotated
        .as_ref()
        .and_then(serving_certificate)
        .context("Renewed Trustee Secret has no tls.crt")?;

    let staged = await_condition(secrets, MANAGED_TRUSTEE_TLS, |secret: Option<&Secret>| {
        secret.and_then(serving_certificate) == Some(renewed_cert)
    });
    timeout(scaled_duration(300), staged)
        .await
        .context("Waiting for the managed Trustee Secret to contain the renewed certificate")??;

    let maps: Api<ConfigMap> = Api::namespaced(client.clone(), ns);
    // The operator clears want_cert after the Deployment has rolled out the managed Secret.
    let rolled_out = await_condition(maps, TRUSTEE_CERTS_CONFIG_MAP, |map: Option<&ConfigMap>| {
        map.and_then(|map| map.data.as_ref())
            .and_then(|data| TrusteeCerts::from_config_map_data(data).ok())
            .is_some_and(|certs| certs.want_cert.is_none())
    });
    timeout(scaled_duration(300), rolled_out)
        .await
        .context("Waiting for Trustee to roll out the renewed certificate")??;

    let nodes: Api<Node> = Api::all(client.clone());
    let node = nodes.get(&node_name).await?;
    ensure!(
        node.metadata.uid == original_node.metadata.uid,
        "Node {node_name} was replaced during certificate rotation"
    );
    let boot_id = node
        .status
        .and_then(|status| status.node_info)
        .map(|info| info.boot_id)
        .filter(|id| !id.is_empty())
        .with_context(|| format!("Node {node_name} has no boot ID"))?;
    let backend = OpenShiftNode {
        node_name: node_name.clone(),
    };
    test_ctx.info(format!(
        "Rebooting node {node_name} after the Trustee certificate rollout"
    ));
    // Give the debug command time to exit before the host goes down.
    timeout(
        scaled_duration(120),
        backend.ssh_exec("systemd-run --on-active=10s systemctl reboot"),
    )
    .await
    .with_context(|| format!("Waiting to schedule reboot on node {node_name}"))??;
    let ready =
        await_condition(nodes, &node_name, |current: Option<&Node>| {
            current
                .filter(|current| current.metadata.uid == node.metadata.uid)
                .and_then(|current| current.status.as_ref())
                .is_some_and(|status| {
                    status
                        .node_info
                        .as_ref()
                        .is_some_and(|info| !info.boot_id.is_empty() && info.boot_id != boot_id)
                        && status.conditions.iter().flatten().any(|condition| {
                            condition.type_ == "Ready" && condition.status == "True"
                        })
                })
        });
    timeout(scaled_duration(900), ready)
        .await
        .with_context(|| format!("Waiting for node {node_name} to reboot and become Ready"))??;
    test_ctx.info(format!("Node {node_name} is Ready after reboot"));
    Ok(())
}

// TODO also test machines being rebooted early
named_test!(
    async fn test_tls_update() -> anyhow::Result<()> {
        let test_ctx = setup!().await?;
        let scale_ctx = ScaleContext::new(test_ctx).await?;
        let result = verify_tls_update(&scale_ctx).await;
        result.and(scale_ctx.cleanup().await)
    }
);
