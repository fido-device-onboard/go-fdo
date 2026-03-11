# TPM Specification Compliance Testing TODO

## Objective

Develop comprehensive test code to exercise TPM specification compliance for FDO credentials, ensuring all data structures, NV indices, and object handles work correctly without modifying the main library code initially.

Authoritative reference: **"Securing FDO Credentials in the TPM v1.0"**, available at <https://fidoalliance.org/specifications/download-iot-specifications/>

Agents should run simulated TPM tests, but Agents do not have sudo or TPM access. Will require user to execute tests against actual TPM hardware.

## Running Spec Compliance Tests

All tests are consolidated in a single file (`tpm/spec_compliance_test.go`) with one entry point: `TestSpecCompliance`.

```bash
cd tpm

# ── Hardware TPM on Linux (the standard way) ──
# Platform hierarchy is locked after boot on Linux, even for root.
# FDO_TPM_OWNER_HIERARCHY=1 is REQUIRED — without it NVDefineSpace
# will fail with TPM_RC_BAD_AUTH.

# Run ALL tests (spec compliance + Phase 9) against hardware TPM
FDO_TPM_OWNER_HIERARCHY=1 go test -v -tags=spec_compliance_test -count=1

# Spec compliance phases only
FDO_TPM_OWNER_HIERARCHY=1 go test -v -tags=spec_compliance_test -run TestSpecCompliance -count=1

# Phase 9 library integration tests only
FDO_TPM_OWNER_HIERARCHY=1 go test -v -tags=spec_compliance_test -run TestPhase9 -count=1

# ── Software simulator (no hardware needed) ──
FDO_TPM=sim go test -v -tags=spec_compliance_test -count=1

# ── Run a specific phase (simulator example) ──
FDO_TPM=sim go test -v -tags=spec_compliance_test -run TestSpecCompliance/Phase1 -count=1
FDO_TPM=sim go test -v -tags=spec_compliance_test -run TestSpecCompliance/Phase3_Storage -count=1
FDO_TPM=sim go test -v -tags=spec_compliance_test -run TestSpecCompliance/Phase5_Compliance -count=1

# Disable P-384 tests (they are enabled by default)
FDO_TPM=sim FDO_TPM_P384=0 go test -v -tags=spec_compliance_test -count=1
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FDO_TPM` | (hardware) | **Default is real hardware TPM.** Tests FAIL if no hardware TPM is accessible. Set to `sim` to explicitly opt in to the software simulator. |
| `FDO_TPM_P384` | `1` (enabled) | Set to `0` to skip P-384/SHA-384 test variants |
| `FDO_TPM_OWNER_HIERARCHY` | (off) | Set to `1` to use Owner hierarchy instead of Platform for Profile A/B. **Required on Linux userspace where Platform hierarchy is locked after boot.** PlatformCreate will be false — not fully spec-compliant. |

**Important:** Tests never do anything hidden. A passing result always means the tests actually exercised a real TPM with the expected configuration. If hardware is unavailable, platform hierarchy is locked, or any other requirement isn't met — the test **fails** with a clear error message telling the user exactly what to do.

### P-384 Note

P-384/SHA-384 variants share the same NV index handles as their P-256/SHA-256 counterparts (per spec). Each subtest opens its own TPM session with cleanup to avoid index collisions.

### Test Structure

```text
TestSpecCompliance/
  Phase1_Constants/
    NVIndexRange
    PersistentHandles
    DeviceKeyTypes
  Phase2_DataStructures/
    DCTPMStructure/
      FDO_DeviceKey, IDevID, LDevID
  Phase3_Storage/
    NVDefinition/
      DCActive, DCTPM, DCOV, HMAC_US_SHA256, HMAC_US_SHA384,
      DeviceKey_US_P256, DeviceKey_US_P384, FDO_Certificate
    DataRoundTrip/
      DCActive, DCTPM, DCOV, HMAC_US, DeviceKey_US, FDO_Certificate
    PersistentObjects/
      DeviceKey_ECC_P256, HMACSecret_SHA256
    KeyDerivation/
      HMAC_SHA256, HMAC_SHA384, DeviceKey_P256, DeviceKey_P384
    ClearResilience
  Phase4_Crypto/
    Signing/
      BasicSign, Determinism, DifferentDigests/...
    HMAC/
      Basic, LargeData
    PersistentHandleOps/
      ReadPublic_DeviceKey, ReadPublic_HMACSecret, Sign, HMAC
  Phase5_Compliance/
    NVAttributes/
      ProfileA, ProfileB/..., ProfileC/..., ProfileDifferentiation
    ObjectAttributes/
      DeviceKey, HMACSecret
    AuthPolicyDigest/
      DeviceKey, HMACSecret
    NegativeAuth/
      PasswordOnSigningKey, PasswordOnHMACKey,
      OwnerWriteOnProfileB, OwnerReadOnProfileB, WrongPolicyNVIndex
  Phase6_E2E/
    DI_Provision          — Manufacturer: create DAK, HMAC key, NV credentials, extract evidence
    Onboard_Attest        — Device: discover TPM objects, sign nonce, compute HMAC; owner verifies
    Onboard_Attest_Again  — Fresh nonce, proves persistence + repeatability
  Phase7_LibraryAPI/
    ReadNVCredentials     — Read all FDO credentials from TPM NV indices
    ReadDAKPublicKey      — Extract DAK public key from persistent handle
    ProveDAK_SpecificChallenge  — Sign a specific challenge with DAK via policy session
    ProveDAK_RandomChallenge    — Sign a random challenge with DAK via policy session
```

### Build Tag

All tests require: `//go:build spec_compliance_test`

Build with: `-tags=spec_compliance_test`

## Spec Compliance Details

### NV Attribute Profiles (Table 9)

Three distinct NV attribute profiles are defined per the FDO specification:

| Profile | Indices | OwnerWrite | AuthWrite | OwnerRead | AuthRead | NoDA | PlatformCreate | Auth Handle |
|---------|---------|------------|-----------|-----------|----------|------|----------------|-------------|
| **A** | DCActive | 1 | 1 | 1 | 1 | 1 | 1 | TPMRHPlatform |
| **B** | DCTPM, HMAC_US, DeviceKey_US | 0 | 1 | 0 | 1 | 1 | 1 | TPMRHPlatform |
| **C** | DCOV, FDO_Cert | 1 | 1 | 1 | 1 | 1 | 0 | TPMRHOwner |

- **Profile A** (DCActive): Full Owner + NV auth access, platform-created
- **Profile B** (DCTPM, US indices): NV index auth only (no Owner read/write), platform-created
- **Profile C** (DCOV, FDO_Cert): Full Owner + NV auth access, Owner-created (no PlatformCreate)

### Object Attributes (Table 11)

Key templates MUST use:

- `fixedTPM = 1`
- `stClear = 0`
- `fixedParent = 1`
- `sensitiveDataOrigin = 1`
- **`userWithAuth = 0`** (NOT 1 -- keys use authPolicy, not password auth)
- `sign = 1`
- `AuthPolicy` set to policy digest from Table 12

### Auth Policy (Table 12)

Keys are authorized via a compound policy tied to their Unique String NV index:

```text
PolicyNV(US_NV_Index, offset=0, size=1, operand=0x00, operation=UnsignedGE)
  || PolicySecret(US_NV_Index)
```

This is computed via trial session (`tpm2.PolicySession` with `tpm2.Trial()`) and set as the key's `AuthPolicy` field. At runtime, `tpm2.Policy()` JIT callback executes these policy commands in a real policy session.

## Phase Status

### Phase 1: Constants — DONE

- NV Index handles (0x01D10000-0x01D10005)
- Persistent object handles (0x81020002, 0x81020003)
- NV attribute profiles (A, B, C)
- DeviceKeyType constants (0, 1, 2)

### Phase 2: Data Structures — DONE

- DCTPM structure generation for all DeviceKeyType values

### Phase 3: TPM Storage Operations — DONE

- [x] NV index definition with correct attributes per profile (A/B/C)
- [x] Data round-trip for all 6 NV indices
- [x] Persistent object creation with UserWithAuth=0 + AuthPolicy
- [x] Key derivation from Unique Strings (P-256, SHA-256)
- [x] P-384/SHA-384 key derivation (when enabled)
- [x] TPM2_Clear resilience (deterministic re-derivation)

### Phase 4: Cryptographic Operations — DONE

- [x] ECDSA signing with policy session auth
- [x] Signing determinism verification
- [x] Signing with different digest values
- [x] HMAC with policy session auth
- [x] HMAC with large data (SequenceUpdate chunking)
- [x] Persistent handle operations (ReadPublic, Sign, HMAC)

### Phase 5: Compliance Verification — DONE

- [x] NV attribute bit-pattern verification (all 3 profiles)
- [x] Profile differentiation cross-check
- [x] Object attribute verification (Table 11)
- [x] Auth policy digest verification (Table 12)
- [x] Negative auth tests (password rejected, wrong policy, owner access on Profile B)

### Phase 6: End-to-End DI → Onboard Flow — DONE

- [x] DI_Provision: manufacturer creates DAK, HMAC key, credential NV indices
- [x] DI_Provision: extracts public key, GUID, HMAC baseline (Ownership Voucher evidence)
- [x] Onboard_Attest: discovers TPM objects fresh via NVReadPublic/ReadPublic
- [x] Onboard_Attest: signs owner's nonce with DAK, owner verifies against DI public key
- [x] Onboard_Attest: computes HMAC over GUID, owner verifies against manufacturer baseline
- [x] Onboard_Attest_Again: fresh nonce, proves persistence + repeatability
- This phase is the basis for integrating TPM attestation into the actual DI and TO2 code

### Phase 7: Library API — DONE

Tests that exercise the production `tpm/nv.go` exported functions (`ReadNVCredentials`,
`ReadDAKPublicKey`, `ProveDAKPossession`) from the spec compliance test harness:

- [x] ReadNVCredentials: reads all FDO credential NV indices + verifies persistent key presence
- [x] ReadDAKPublicKey: extracts public key from persistent DAK handle
- [x] ProveDAK_SpecificChallenge: signs a known challenge with DAK via policy session, verifies signature
- [x] ProveDAK_RandomChallenge: signs a random challenge, verifies signature

### Phase 11: Edge Cases — NOT STARTED

- [ ] NV space exhaustion scenarios
- [ ] Oversized data rejection
- [ ] Concurrent access scenarios

### Phase 12: Performance — NOT STARTED

- [ ] NV storage/retrieval benchmarks
- [ ] Persistent vs derived key performance
- [ ] TPM resource usage under load

### Phase 9: Library Integration — DONE

- [x] NV write/provisioning functions in `tpm/nv.go` (DefineNVSpace, WriteNV, ComputeFDOAuthPolicy, PersistKey, EvictPersistentHandle, UndefineNVSpace, CleanupFDOState)
- [x] NV read/inspection functions in `tpm/nv.go` (ReadNVCredentials, ReadDAKPublicKey, ProveDAKPossession)
- [x] Spec-compliant ECC key creation in `tpm/key.go` (GenerateSpecECKey: UserWithAuth=false, AuthPolicy, UniqueString)
- [x] Spec-compliant HMAC key creation in `tpm/key.go` (GenerateSpecHMACKey: UserWithAuth=false, AuthPolicy, UniqueString)
- [x] Persistent key loader in `tpm/key.go` (LoadPersistentKey: policy session auth via fdoKeyPolicy)
- [x] Spec-compliant HMAC in `tpm/hmac.go` (NewSpecHmac: persistent key with policy session auth)
- [x] NV-based credential storage in `cred/tpm_store.go` (NewDI provisions NV + persistent keys, Save writes DCTPM/DCOV/DCActive to NV, Load reads exclusively from NV — no disk file written or read)
- [x] ~~Backward compatibility: Load() falls back to file-based credentials when NV not provisioned~~ (removed — Load() is NV-only now)
- [x] Save() handles re-save correctly (UndefineNVSpace before DefineNVSpace for DCTPM/DCOV)

#### Phase 9 Integration Tests

**TPM-layer tests** (`tpm/phase9_integration_test.go`, build tag `spec_compliance_test`):

```bash
cd tpm

# Hardware TPM on Linux (standard)
FDO_TPM_OWNER_HIERARCHY=1 go test -v -tags=spec_compliance_test -run TestPhase9 -count=1

# Software simulator
FDO_TPM=sim go test -v -tags=spec_compliance_test -run TestPhase9 -count=1
```

| Test | What it proves |
|------|---------------|
| `TestPhase9_ProductionAPI_NVOnly` | Full DI→NV→Load→Sign→HMAC cycle using ONLY production exported API, zero disk storage, zero shared Go state between provision and verify phases |
| `TestPhase9_HMACDeterminism` | Persistent HMAC key produces identical output across 3 separate `NewSpecHmac()` calls |
| `TestPhase9_SignMultipleDigests` | Persistent DAK signs 10 different digests, all verifiable with same public key |
| `TestPhase9_PasswordAuthRejected` | `UserWithAuth=false` enforced: password auth → `TPM_RC_AUTH_UNAVAILABLE`; policy session → success |
| `TestPhase9_CleanupFDOState` | Full provision → cleanup → verify all NV indices + persistent handles removed |

**cred.Store interface tests** (`cred/tpm_store_test.go`, build tag `tpmsim`):

```bash
cd cred && go test -v -tags=tpmsim -count=1
```

| Test | What it proves |
|------|---------------|
| `TestTPMStore_NVOnlyRoundTrip` | Production `cred.Store` interface: Open→NewDI→Save→(delete file)→Load from NV only→verify credential+sign+HMAC |
| `TestTPMStore_FileFallback` | Load() succeeds via NV-first path when file also exists |
| `TestTPMStore_SaveOverwrite` | Save() called twice (re-onboard), Load() from NV returns latest credential |

### Phase 10: Hardware TPM Integration Testing — NOT STARTED

**Prerequisite:** Access to `/dev/tpmrm0` (user must be in `tss` group or have appropriate permissions).

- [ ] Run `cred.Store` integration tests against real hardware TPM with Owner hierarchy
- [ ] Run Phase 9 integration tests against real hardware TPM
- [ ] Verify NV state persists across TPM connections (hardware-only — simulator resets)
- [ ] Test Platform hierarchy on systems where it is available (UEFI environment)
- [ ] End-to-end FDO protocol (DI → TO1 → TO2) with TPM-backed credentials

### ~~TODO:~~ DONE: TPM Simulator State Persistence

**Status: IMPLEMENTED** — The simulator now uses a singleton pattern
(`open_sim.go`) that keeps the go-tpm-tools simulator alive across
`DefaultOpen()`/`Close()` cycles within a process. NV indices and
persistent handles survive across connections, enabling integration
tests that do DI → Close → Reopen → Load.

**Implementation:**

- `open_sim.go`: Singleton `*simtools.Simulator` via `GetWithFixedSeedInsecure(8086)`
  with a `simConn` wrapper whose `Close()` is a no-op (doesn't destroy the simulator).
- `ResetSimulator()`: Exported function to truly destroy the singleton (for test cleanup
  or the `--tpm-clear` CLI command).
- New tests in `cred/tpm_store_test.go`:
  - `TestTPMStore_CrossConnectionPersistence`: DI on conn1 → Close → Load on conn2
  - `TestTPMStore_ClearAndReprovision`: DI → Clear → verify Load fails → fresh DI

**CLI command:** `fdo client --tpm-clear` removes all FDO NV indices and persistent
keys, working equally on hardware TPM and simulator.

**Limitation:** Persistence is within a single process lifetime. Cross-process
persistence (separate CLI invocations) would require an external simulator
(e.g., swtpm with TCP transport) or modifications to the MS TPM reference
implementation's NV memory layer to use file-backed storage.

## Key Helper Functions (all in spec_compliance_test.go)

- `openTPM(t)` — Env-var-controlled TPM backend selection (hardware or simulator)
- `cleanupFDOState(t, thetpm)` — Removes pre-existing NV indices and persistent handles
- `defineNVSpec()` — Creates NV index with profile-specific attributes
- `writeNVOwner()` / `readNVOwner()` — Owner auth (Profile A, C)
- `writeNVAuth()` / `readNVAuth()` — NV index auth (Profile B)
- `computeFDOAuthPolicy()` — Trial policy session for auth digest
- `fdoKeyPolicy()` — JIT policy session for runtime key authorization
- `createPersistentECCKey()` — Full ECC key creation flow
- `createPersistentHMACKey()` — Full HMAC key creation flow
- `onboardFromTPMOnly()` — Simulates device-side TO2: discovers TPM objects, signs nonce, verifies HMAC

## Implementation Notes

### NV Index Constants

```go
const (
    DCActive_Index      = 0x01D10000
    DCTPM_Index         = 0x01D10001
    DCOV_Index          = 0x01D10002
    HMAC_US_Index       = 0x01D10003
    DeviceKey_US_Index  = 0x01D10004
    FDO_Cert_Index      = 0x01D10005  // See note below
)
```

**Note on `FDO_Cert_Index` (`0x01D10005`):** The spec defines this as an
optional "FDO Device Certificate" (X.509), but this is a **spec gap**. The FDO
credential (Ownership Voucher) is not an X.509 certificate — it is a
CBOR-encoded, variable-length data structure with no normalized format. It
routinely exceeds the ~700-byte practical limit of older TPMs. The information
it provides (proof of ownership) is recoverable at any time by re-running TO2
and can be cached on non-TPM media without compromising the security model.
The constant is defined and exercised in Profile C tests for completeness, but
production code does not provision this index. See `tpm-spec-gap-analysis.md`
§13 for full discussion.

### Persistent Object Handles

```go
const (
    FDO_Device_Key_Handle  = 0x81020002
    FDO_HMAC_Secret_Handle = 0x81020003
)
```

### Success Criteria

1. All NV indices can be created with correct attributes per profile (A/B/C)
2. All data can be stored and retrieved correctly using profile-appropriate auth
3. Keys created with UserWithAuth=0 and AuthPolicy (not password auth)
4. Key operations (Sign, HMAC) use policy sessions for authorization
5. Key derivation works for all DeviceKeyType options
6. Spec compliance verified through automated tests
7. Performance acceptable for production use
