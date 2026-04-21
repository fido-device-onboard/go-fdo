# TPM Compliance Testing

Tests in this package verify compliance with **"Securing FDO Credentials
in the TPM"**, the authoritative specification for how FDO credentials
are stored and managed in a TPM.

## Overview

| Category | File(s) | Build Tag | Runs by Default |
|----------|---------|-----------|-----------------|
| Simulator unit tests | `tpm_test.go` | none | Yes (`go test ./tpm/...`) |
| Spec compliance suite (Phases 1-7) | `spec_compliance_test.go` | `spec_compliance_test` | No |
| Phase 9 integration tests | `phase9_integration_test.go` | `spec_compliance_test` | No |
| Hardware integration | `hardware_test.go` | `hardware_tpm` | No |
| End-to-end TPM integration | `../test_tpm_examples.sh` | build tag `tpm` | Via `make test-tpm` or `make test-tpm-sim` |

## Spec Compliance Tests (Phases 1-7)

`TestSpecCompliance` in `spec_compliance_test.go` validates every normative
requirement in the spec:

| Phase | What it validates |
|-------|-------------------|
| Phase 1: Constants | NV index ranges (0x01D10000-0x01D10005), persistent handle ranges, DeviceKeyType enum |
| Phase 2: Data Structures | DCTPM CBOR field sizes and types |
| Phase 3: Storage | NV define/write/read roundtrip, persistent key creation (child-of-SRK), key derivation, TPM2_Clear resilience |
| Phase 4: Crypto | Signing with empty auth (determinism, multiple digests), HMAC with empty auth, persistent handle operations |
| Phase 5: Compliance | NV attribute bits (Table 9), object attributes (Table 11: userWithAuth=1, adminWithPolicy=1), empty-auth Sign/HMAC succeeds, Owner R/W on all NV profiles |
| Phase 6: E2E | Full DI → provision → onboard cycle using raw TPM commands |
| Phase 7: Library API | `ReadNVCredentials`, `ReadDAKPublicKey`, `ProveDAKPossession` |

### Running

```bash
cd tpm

# Software simulator (no hardware needed)
FDO_TPM=sim go test -v -tags=spec_compliance_test -run TestSpecCompliance -count=1

# Hardware TPM (Linux — Platform hierarchy locked)
FDO_TPM_OWNER_HIERARCHY=1 go test -v -tags=spec_compliance_test -run TestSpecCompliance -count=1

# Run a specific phase
FDO_TPM=sim go test -v -tags=spec_compliance_test -run TestSpecCompliance/Phase5 -count=1
```

## Phase 9 Integration Tests

`TestPhase9_*` tests in `phase9_integration_test.go` prove the production
library API can perform a complete DI → NV Store → NV Load → Sign → HMAC
cycle using **only the TPM** — zero files, zero shared Go state between
provision and verify phases.

| Test | What it proves |
|------|----------------|
| `ProductionAPI_NVOnly` | Full lifecycle: CreateSRK → CreateChildECKey → CreateChildHMACKey → PersistKey → write DCTPM (with magic) → ReadNVCredentials → LoadPersistentKey → Sign → HMAC verify |
| `HMACDeterminism` | Same persistent key + same data = same HMAC across multiple calls |
| `SignMultipleDigests` | 10 different digests signed and verified with persistent DAK |
| `EmptyAuthWorks` | Empty password auth succeeds on userWithAuth=1 keys |
| `CleanupFDOState` | `CleanupFDOState` removes all NV indices + persistent handles |

### Running

```bash
cd tpm

# Software simulator
FDO_TPM=sim go test -v -tags=spec_compliance_test -run TestPhase9 -count=1

# Hardware TPM
FDO_TPM_OWNER_HIERARCHY=1 go test -v -tags=spec_compliance_test -run TestPhase9 -count=1

# Both suites at once
FDO_TPM=sim go test -v -tags=spec_compliance_test -count=1
```

## End-to-End TPM Integration Tests

`test_tpm_examples.sh` runs full FDO DI → TO1/TO2 flows with a real server
and a TPM-enabled client. The server runs in standard (non-TPM) mode; only
the client stores credentials in the TPM.

| Test | What it demonstrates |
|------|----------------------|
| `basic` | DI provisions keys + DCTPM into TPM, TO1/TO2 onboards using only TPM state |
| `basic-reuse` | DI + onboard + second onboard (credential reuse) |
| `fdo200` | Same as basic but with FDO 2.0 protocol |

### Running

```bash
# Software simulator (no hardware needed)
make test-tpm-sim
# or: TPM_MODE=sim ./test_tpm_examples.sh all

# Hardware TPM
make test-tpm
# or: ./test_tpm_examples.sh all

# Specific test
TPM_MODE=sim ./test_tpm_examples.sh basic
```

## CLI Walkthrough Tools

The TPM-enabled client binary includes inspection commands:

```bash
cd examples && go build -tags=tpm -o fdo-client ./cmd

# Show all FDO state in TPM (decodes DCTPM CBOR structure)
./fdo-client client -tpm-show

# Clear all FDO state from TPM
./fdo-client client -tpm-clear

# Export DAK public key as PEM
./fdo-client client -tpm-export-dak

# Prove DAK possession (sign a challenge)
./fdo-client client -tpm-prove
./fdo-client client -tpm-prove -tpm-challenge "my test nonce"
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FDO_TPM` | (hardware) | Set to `sim` for software simulator. Default requires real hardware TPM. |
| `FDO_TPM_P384` | `1` (enabled) | Set to `0` to skip P-384/SHA-384 test variants |
| `FDO_TPM_OWNER_HIERARCHY` | (off) | Set to `1` to use Owner hierarchy instead of Platform. Required on Linux userspace where Platform hierarchy is locked after boot. |
| `FDO_TPM_KEY_METHOD` | `child` | Set to `primary` to use CreatePrimary with unique strings instead of child-of-SRK key creation |
| `TPM_MODE` | `hw` | For `test_tpm_examples.sh`: `hw` for hardware, `sim` for swtpm |

**Design principle:** Tests never silently skip or auto-fallback. A passing
result means the tests actually exercised a real TPM (or the simulator was
explicitly requested). If hardware is unavailable or Platform hierarchy is
locked, the test **fails** with a clear error message.

## Troubleshooting

### Permission Denied

```bash
# Error: open /dev/tpmrm0: permission denied
sudo -E go test -v -tags=spec_compliance_test ./tpm -run TestSpecCompliance
```

### No TPM Device

```bash
# Use the software simulator instead
FDO_TPM=sim go test -v -tags=spec_compliance_test -run TestSpecCompliance -count=1
```

### Platform Hierarchy Locked

```bash
# Use Owner hierarchy (required on Linux userspace)
FDO_TPM_OWNER_HIERARCHY=1 go test -v -tags=spec_compliance_test -run TestSpecCompliance -count=1
```

## CI/CD Integration

All opt-in TPM tests are excluded from standard pipelines (`go test ./...`,
`make test`, `test_examples.sh`). Build tags (`spec_compliance_test`,
`hardware_tpm`, `tpm`) must be explicitly provided.

For CI with a software TPM: `make test-tpm-sim` runs the full end-to-end
integration suite using swtpm.
