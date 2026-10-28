# TPM Compliance Testing

Tests in this package verify compliance with **"Securing FDO Credentials
in the TPM"**, the authoritative specification for how FDO credentials
are stored and managed in a TPM.

## Overview

| Category | File(s) | Build Tag | Runs by Default |
|----------|---------|-----------|-----------------|
| Simulator unit tests | `tpm_test.go` | none | Yes (`go test ./tpm/...`) |
| Spec compliance suite | `spec_compliance_test.go` | `spec_compliance_test` | No |
| DCTPM / Device key policy unit tests | `dctpm_test.go`, `nv_dctpm_test.go`, `device_key_policy_test.go` | none (simulator) | Yes |
| Phase 9 integration tests | `phase9_integration_test.go` | `spec_compliance_test` | No |
| Hardware integration | `hardware_test.go` | `hardware_tpm` | No |
| End-to-end TPM integration | `../test_tpm_examples.sh` | build tag `tpm` | Via `make test-tpm` or `make test-tpm-sim` |

## Spec Compliance Tests

`TestSpecCompliance` in `spec_compliance_test.go` drives the library
functions the credential store (`cred/tpm_store.go`) uses for DI, load and
TO2 updates, and checks the results against the spec tables. It runs on a
hardware TPM by default (`FDO_TPM=sim` for the simulator) and **removes any
existing FDO state** (DCTPM index, FDO persistent handles) first.

| Subtest | What it validates |
|---------|-------------------|
| `Constants` | DCTPM index 0x01D10001, magic "FDO1", default handles 0x81020002/0x81020003 (Tables 5, 6) |
| `DCTPM_Index` | Table 9 attributes incl. `WRITE_STCLEAR`; Owner hierarchy by default; 512-byte index; structure is the first CBOR item at offset 0 and trailing bytes are ignored; in-place update keeps the index; `TPM2_NV_WriteLock` blocks updates |
| `Keys` | For child-of-SRK and primary-with-unique-string keys, P-256 and P-384 (if the TPM lists it): Table 11 attributes (incl. `noDA`); Device key authPolicy = `PolicyCommandCode(TPM_CC_Certify)` (Table 12), HMAC key empty; Sign and HMAC with empty auth; `TPM2_Certify` only via the policy; `TPM2_ObjectChangeAuth` refused for both keys |
| `Lifecycle` | DI (keys + DCTPM recording the handles) → load → sign/HMAC → TO2 update (new GUID, longer RVInfo, same keys) → load → `CleanupFDOState` |

The store-level counterpart is `TestTPMStore_SaveInPlace` in
`cred/tpm_store_test.go` (`-tags tpmsim`): a TO2 save does not redefine the
index, a failed save leaves the previous credentials loadable, a wrong magic
is not loaded.

### Running

```bash
cd tpm

# Software simulator (no hardware needed)
FDO_TPM=sim go test -v -tags=spec_compliance_test -run TestSpecCompliance -count=1

# Hardware TPM (DCTPM under the Owner hierarchy, the default)
go test -v -tags=spec_compliance_test -run TestSpecCompliance -count=1

# DCTPM under the Platform hierarchy (only where Platform auth is available)
FDO_TPM_PLATFORM_HIERARCHY=1 go test -v -tags=spec_compliance_test -run TestSpecCompliance -count=1

# One subtest
FDO_TPM=sim go test -v -tags=spec_compliance_test -run TestSpecCompliance/Keys -count=1
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
| `FDO_TPM_PLATFORM_HIERARCHY` | (off) | Set to `1` to create DCTPM under the Platform hierarchy (`PLATFORMCREATE`). Default is Owner. Used by the credential store and `TestSpecCompliance`. |
| `FDO_TPM_OWNER_HIERARCHY` | (off) | Phase 9 tests only: set to `1` to use the Owner hierarchy (required on Linux userspace where Platform is locked). |
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
# TestSpecCompliance uses the Owner hierarchy by default; don't set
# FDO_TPM_PLATFORM_HIERARCHY. For the Phase 9 tests:
FDO_TPM_OWNER_HIERARCHY=1 go test -v -tags=spec_compliance_test -run TestPhase9 -count=1
```

## CI/CD Integration

All opt-in TPM tests are excluded from standard pipelines (`go test ./...`,
`make test`, `test_examples.sh`). Build tags (`spec_compliance_test`,
`hardware_tpm`, `tpm`) must be explicitly provided.

For CI with a software TPM: `make test-tpm-sim` runs the full end-to-end
integration suite using swtpm.
