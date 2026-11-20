# Confidential Clusters integration tests

The integration tests evaluate if the operator performs as expected with OpenShift MachineSets. It creates real confidential MachineSet replicas on supported backends.

Environment variables from the [upstream tests](https://github.com/trusted-execution-clusters/operator/tree/main/tests) are also supported:
- `$TEST_NAMESPACE_PREFIX`
- `$TRUSTEE_IMAGE`
- `$OPERATOR_IMAGE`, `$RELATED_IMAGE_COMPUTE_PCRS`, `$RELATED_IMAGE_REGISTRATION_SERVER`, `$RELATED_IMAGE_ATTESTATION_KEY_REGISTER` or alternatively `$REGISTRY` and `$TAG`

Additionally,
- on Azure, `$AZURE_RESOURCE_ID` should be a bootable image with trustee-attester, formatted `/resourcegroups/…/images/…/versions/…`
- `$BOOTC_IMAGE` should be set to a reference to a bootc image built from the same image as the bootable image to prevent updates. This reference should be specified with a hash, not a tag, e.g. `quay.io/…/…@sha256:…`.

## Usage

```
$ make VIRT_PROIDER=azure REGISTRY=… TAG=… BOOTC_IMAGE=… AZURE_RESOURCE_ID=… scale-tests
```

## Supported backends (auto-detected)

- Azure (requires `VIRT_PROVIDER=azure` to be set to avoid AK registration)
