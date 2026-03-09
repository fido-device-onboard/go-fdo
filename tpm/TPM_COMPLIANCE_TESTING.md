# TPM Compliance Testing

Tests in this package verify compliance with **"Securing FDO Credentials in the TPM v1.0"**, the authoritative specification for how FDO credentials must be stored and managed in a TPM. The specification is available at:

<https://fidoalliance.org/specifications/download-iot-specifications/>

## Overview

The go-fdo library includes several categories of TPM tests:

| Category | File | Build Tag | Runs by Default |
|----------|------|-----------|-----------------|
| Simulator unit tests | `tpm_test.go` | none | Yes |
| Spec compliance suite | `spec_compliance_test.go` | `spec_compliance_test` | No |
| Hardware integration | `hardware_test.go` | `hardware_tpm` | No |

## Spec Compliance Tests

All spec compliance tests are consolidated in `spec_compliance_test.go` with a single entry point: `TestSpecCompliance`. These tests exercise NV index definitions, data structures, key derivation, cryptographic operations, and attribute verification per the specification.

### Running

```bash
cd tpm

# Run against hardware TPM (default — tries /dev/tpmrm0 then /dev/tpm0)
go test -v -tags=spec_compliance_test -run TestSpecCompliance -count=1

# Run against software simulator
FDO_TPM=sim go test -v -tags=spec_compliance_test -run TestSpecCompliance -count=1

# Run a specific phase
FDO_TPM=sim go test -v -tags=spec_compliance_test -run TestSpecCompliance/Phase3 -count=1

# Disable P-384 tests
FDO_TPM=sim FDO_TPM_P384=0 go test -v -tags=spec_compliance_test -run TestSpecCompliance -count=1

# Hardware TPM where Platform hierarchy is locked (e.g. Linux userspace)
FDO_TPM_OWNER_HIERARCHY=1 go test -v -tags=spec_compliance_test -run TestSpecCompliance -count=1
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FDO_TPM` | (hardware) | **Default is real hardware TPM.** Tests FAIL if no hardware TPM is accessible. Set to `sim` to explicitly opt in to the software simulator. |
| `FDO_TPM_P384` | `1` (enabled) | Set to `0` to skip P-384/SHA-384 test variants |
| `FDO_TPM_OWNER_HIERARCHY` | (off) | Set to `1` to use Owner hierarchy instead of Platform for Profile A/B. Required on Linux userspace where Platform hierarchy is locked after boot. PlatformCreate will be false — not fully spec-compliant. |

**Design principle:** Tests never silently skip, auto-fallback, or do hidden workarounds. A passing result always means the tests actually exercised a real TPM (or the simulator was explicitly requested). If hardware is unavailable, platform hierarchy is locked, or any other requirement isn't met, the test **fails** with a clear error message telling you exactly what to do.

## Hardware Integration Test

The `hardware_test.go` test validates end-to-end FDO device credential operations on real TPM hardware.

### Prerequisites

1. **TPM Hardware**: Must have a TPM device available

   ```bash
   ls -la /dev/tpm*
   # Should show /dev/tpm0 and/or /dev/tpmrm0
   ```

2. **Permissions**: Need sudo access to TPM devices

### Running

```bash
sudo -E go test -v -tags=hardware_tpm ./tpm -run TestTPMDeviceHardware
```

### What It Validates

1. **TPM Connectivity**: Can connect to TPM Resource Manager (`/dev/tpmrm0`)
2. **Key Generation**: P256 EC keys can be generated in hardware
3. **Cryptographic Operations**: HMAC SHA256/SHA384 using TPM keys
4. **Digital Signing**: TPM keys can sign and verify data
5. **FDO Integration**: Can create proper `tpm.DeviceCredential` structures

## Troubleshooting

### Permission Denied

```bash
# Error: open /dev/tpmrm0: permission denied
# Solution: Use sudo, or set FDO_TPM_OWNER_HIERARCHY=1 if Platform is locked
sudo -E go test -v -tags=spec_compliance_test ./tpm -run TestSpecCompliance
```

### No TPM Device

```bash
# Error: No hardware TPM available
# Solution: Check TPM device availability, or use simulator
ls -la /dev/tpm*
FDO_TPM=sim go test -v -tags=spec_compliance_test -run TestSpecCompliance -count=1
```

### Platform Hierarchy Locked

```bash
# Error: NVDefineSpace ... Platform hierarchy is not accessible
# Solution: Use Owner hierarchy fallback (not fully spec-compliant)
FDO_TPM_OWNER_HIERARCHY=1 go test -v -tags=spec_compliance_test -run TestSpecCompliance -count=1
```

## CI/CD Integration

All opt-in TPM tests are excluded from standard pipelines (`go test ./...`, `make test`, `test_examples.sh`). This ensures CI/CD works without TPM hardware. Build tags (`spec_compliance_test`, `hardware_tpm`) must be explicitly provided.
