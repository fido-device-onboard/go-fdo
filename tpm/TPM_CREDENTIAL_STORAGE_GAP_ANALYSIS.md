# TPM Credential Storage — Comprehensive Gap Analysis

## Objective

Identify all work required to support **full TPM-based credential storage** per
"Securing FDO Credentials in the TPM v1.0" so that when TPM mode is chosen,
**no `credentials.blob` (cred.bin) file exists on disk** — all secrets and
credential metadata live inside the TPM's NV indices and persistent object
handles.

### Design Constraints

- **Opt-in**: TPM mode is activated by a flag (e.g. `-tpm`). Default behavior
  (blob-based credentials) must remain unchanged.
- **Simulator + Hardware**: Must work on both `go-tpm` simulator and real
  hardware TPMs.
- **P-384 optional**: P-384/SHA-384 support is optional; P-256/SHA-256 is
  required.
- **Owner hierarchy optional**: Platform hierarchy is preferred per spec, but
  Owner hierarchy must be supported for Linux userspace where Platform is locked.
- **No disk secrets**: When TPM mode is active, the HMAC key, device signing
  key, and all credential metadata must reside in the TPM. No `cred.bin`.

Authoritative reference: **"Securing FDO Credentials in the TPM v1.0"**,
available at <https://fidoalliance.org/specifications/download-iot-specifications/>

---

## Current State Summary

### What Already Works

| Feature | Status | Location |
|---------|--------|----------|
| `hash.Hash` HMAC interface | Working | `tpm/hmac.go` — `tpm.Hmac` satisfies `hash.Hash` + `fallibleHash` |
| `crypto.Signer` key interface | Working | `tpm/key.go` — `tpm.Key` satisfies `crypto.Signer` + `io.Closer` |
| TPM key generation (EC P-256, P-384, RSA 2048/3072) | Working | `tpm/key.go:29-131` |
| TPM HMAC (SHA-256, SHA-384) | Working | `tpm/hmac.go:26-37` |
| Integration with DI/TO2 protocol | Working | `examples/cmd/tpm.go` — passes TPM-backed `hash.Hash` and `crypto.Signer` into `DIConfig`/`TO2Config` |
| `tpm.DeviceCredential` type | Partial | `tpm/credential.go` — stores `DeviceKeyType` + `DeviceKeyHandle` but still written to `cred.bin` |
| Spec compliance tests (Phases 1-6) | Working | `tpm/spec_compliance_test.go` — exercises NV indices, persistent handles, auth policies, E2E flow |

### What Does NOT Work (The Gaps)

| Gap | Severity | Description |
|-----|----------|-------------|
| **G1: Credentials still on disk** | Critical | `tpm.DeviceCredential` is CBOR-serialized to `cred.bin` — public metadata (GUID, RvInfo, PublicKeyHash) is on disk, not in TPM NV |
| **G2: No NV storage in production code** | Critical | NV index operations (`0x01D10000`-`0x01D10005`) exist only in `spec_compliance_test.go`, not in the `tpm/` library |
| **G3: Transient keys only** | Critical | Production code uses `CreatePrimary` + `FlushContext` (ephemeral). Spec requires persistent handles at `0x81020002` / `0x81020003` |
| **G4: No Unique Strings** | Critical | Production key templates do not set the `Unique` field. Spec requires Unique Strings stored at NV `0x01D10003`/`0x01D10004` for deterministic key derivation resilient to `TPM2_Clear` |
| **G5: Wrong auth model** | Critical | Production keys use `UserWithAuth=true` (password auth). Spec requires `UserWithAuth=false` + `AuthPolicy` = `PolicyNV(US) \|\| PolicySecret(US)` |
| **G6: No DCActive flag** | High | No NV index for the 1-byte DCActive flag (`0x01D10000`) that indicates whether credentials are provisioned |
| **G7: No DCTPM in NV** | High | The DCTPM structure (credential metadata) is not stored in NV index `0x01D10001` |
| **G8: No DCOV in NV** | Medium | Ownership Voucher data is not stored in NV index `0x01D10002` |
| **G9: No FDO Certificate in NV** | Low | Optional X.509 cert not stored in NV index `0x01D10005` |
| **G10: No NV credential reader** | Critical | No function to read `fdo.DeviceCredential` fields back from TPM NV during TO1/TO2 |
| **G11: No DI provisioner** | Critical | No function to write credential data into TPM NV during DI |
| **G12: CLI still writes cred.bin** | Critical | `examples/cmd/credential.go` always writes a file, even in TPM mode |

---

## Architecture: What Needs to Change

### Layer 1: `tpm/` Package — New Production Functions

The `tpm/` package needs new exported functions that mirror what
`spec_compliance_test.go` already exercises. These can be extracted/adapted
from the test helpers.

#### 1a. NV Index Management

```
tpm/nv.go (NEW file)
```

Functions needed:

| Function | Purpose | Based on test helper |
|----------|---------|---------------------|
| `DefineNVIndex(t TPM, index, size, profile, hierarchy)` | Create NV index with correct attributes per profile A/B/C | `defineNVSpec()` |
| `WriteNV(t TPM, index, data, profile)` | Write data using profile-appropriate auth | `writeNVOwner()` / `writeNVAuth()` |
| `ReadNV(t TPM, index, size, profile)` | Read data using profile-appropriate auth | `readNVOwner()` / `readNVAuth()` |
| `UndefineNV(t TPM, index, hierarchy)` | Remove NV index | cleanup helpers |
| `NVExists(t TPM, index) bool` | Check if NV index is defined | `tpm2.NVReadPublic` |

Constants (move from test to production):

```go
const (
    DCActiveIndex     = 0x01D10000
    DCTPMIndex        = 0x01D10001
    DCOVIndex         = 0x01D10002
    HMACUSIndex       = 0x01D10003
    DeviceKeyUSIndex  = 0x01D10004
    FDOCertIndex      = 0x01D10005

    FDODeviceKeyHandle  = 0x81020002
    FDOHMACSecretHandle = 0x81020003
)
```

NV profile types (move from test to production):

```go
type NVProfile int
const (
    ProfileA NVProfile = iota // DCActive: OwnerWrite+AuthWrite+OwnerRead+AuthRead+NoDA+PlatformCreate
    ProfileB                  // DCTPM, US indices: AuthWrite+AuthRead+NoDA+PlatformCreate
    ProfileC                  // DCOV, FDO_Cert: OwnerWrite+AuthWrite+OwnerRead+AuthRead+NoDA (Owner-created)
)
```

#### 1b. Persistent Key Management

```
tpm/persistent.go (NEW file)
```

Functions needed:

| Function | Purpose | Based on test helper |
|----------|---------|---------------------|
| `CreatePersistentECCKey(t TPM, curve, uniqueString, handle, policyDigest)` | Create ECC key with auth policy, persist to handle | `createPersistentECCKey()` |
| `CreatePersistentHMACKey(t TPM, hashAlg, uniqueString, handle, policyDigest)` | Create HMAC key with auth policy, persist to handle | `createPersistentHMACKey()` |
| `ComputeAuthPolicy(t TPM, nvIndex) ([]byte, error)` | Compute Table 12 auth policy digest | `computeFDOAuthPolicy()` |
| `KeyPolicy(t TPM, nvIndex) tpm2.PolicyCallback` | Runtime policy session for key authorization | `fdoKeyPolicy()` |
| `LoadPersistentKey(t TPM, handle) (Key, error)` | Load existing persistent key for signing | NEW |
| `LoadPersistentHMAC(t TPM, handle, hashAlg) (Hmac, error)` | Load existing persistent HMAC key | NEW |

#### 1c. Credential Lifecycle

```
tpm/credential.go (EXTEND existing file)
```

Functions needed:

| Function | Purpose |
|----------|---------|
| `Provision(t TPM, cred *fdo.DeviceCredential, opts ProvisionOpts) error` | Write all credential data to TPM NV during DI. Creates Unique Strings, derives keys, writes DCTPM/DCOV/DCActive, persists keys to handles. |
| `LoadCredential(t TPM) (*fdo.DeviceCredential, error)` | Read credential data from TPM NV indices. Returns populated `fdo.DeviceCredential` from NV-stored DCTPM data. |
| `IsProvisioned(t TPM) (bool, error)` | Check DCActive flag at `0x01D10000` |
| `SignerFromTPM(t TPM) (Key, error)` | Get `crypto.Signer` backed by the persistent device key at `0x81020002` |
| `HMACsFromTPM(t TPM) (sha256Hmac, sha384Hmac Hmac, error)` | Get `hash.Hash` instances backed by the persistent HMAC key at `0x81020003` |
| `UpdateCredential(t TPM, newCred *fdo.DeviceCredential) error` | Update DCTPM/DCOV in NV after TO2 credential replacement |
| `Deprovision(t TPM) error` | Remove all FDO NV indices and persistent handles (factory reset) |

Options type:

```go
type ProvisionOpts struct {
    Curve        elliptic.Curve // P-256 (default) or P-384
    UseOwnerHierarchy bool     // Use Owner instead of Platform hierarchy
    // FDO Certificate is optional
    Certificate  *x509.Certificate
}
```

### Layer 2: Adapt Existing `tpm.Key` and `tpm.Hmac`

The current `tpm.Key` and `tpm.Hmac` implementations create **transient**
primary keys each time. For persistent-handle-backed operations, we need
alternate constructors.

#### Current constructors (keep for backward compat)

```go
// Creates a transient primary key — existing behavior, unchanged
func GenerateECKey(t TPM, curve elliptic.Curve) (Key, error)
func NewHmac(t TPM, h crypto.Hash) (Hmac, error)
```

#### New constructors needed

```go
// Load a persistent key at the given handle.
// Uses policy session authorization (not password auth).
// The nvIndex is the Unique String NV index for the policy.
func OpenKey(t TPM, handle tpm2.TPMHandle, nvIndex tpm2.TPMHandle) (Key, error)

// Load a persistent HMAC key at the given handle.
// Uses policy session authorization.
func OpenHMAC(t TPM, handle tpm2.TPMHandle, nvIndex tpm2.TPMHandle, hashAlg crypto.Hash) (Hmac, error)
```

Key differences from current implementation:

| Aspect | Current (transient) | New (persistent) |
|--------|-------------------|-----------------|
| Key creation | `CreatePrimary` each time | `CreatePrimary` + `EvictControl` once during DI |
| Key loading | N/A (derived on demand) | `ReadPublic` on persistent handle |
| Authorization | `UserWithAuth=true`, HMAC session | `UserWithAuth=false`, policy session via `PolicyNV + PolicySecret` |
| `Close()` behavior | `FlushContext` (destroys key) | No-op or release session (key persists) |
| Unique field | Not set | Set from Unique String stored in NV |

#### Internal changes to `key` struct

The private `key` struct (`tpm/key.go:146-150`) needs a `persistent bool`
field. When `persistent=true`, `Close()` should NOT flush the handle.

The private `hmac` struct (`tpm/hmac.go:55-70`) needs similar changes:

- New `policyCallback` field for policy-based auth instead of HMAC session auth
- `init()` should use `ReadPublic` instead of `CreatePrimary` when backed by a
  persistent handle

### Layer 3: CLI Changes (`examples/cmd/`)

#### `examples/cmd/credential.go` — Eliminate `cred.bin` in TPM mode

Current `readCred()` reads from a file even in TPM mode. Must change to:

```go
func readCred() (...) {
    if tpmPath != "" {
        tpmc, _ := tpmOpen(tpmPath)
        // Check if TPM is provisioned
        if !tpm.IsProvisioned(tpmc) {
            return ..., fmt.Errorf("TPM not provisioned; run DI first")
        }
        // Read credential metadata from TPM NV
        cred, _ := tpm.LoadCredential(tpmc)
        // Get HMAC and signing key from persistent handles
        h256, h384, _ := tpm.HMACsFromTPM(tpmc)
        key, _ := tpm.SignerFromTPM(tpmc)
        return cred, h256, h384, key, cleanup, nil
    }
    // ... existing blob path unchanged
}
```

Current `saveCred()` writes to a file. In TPM mode, it should be a no-op
(credential data was already written to NV during DI provisioning).

Current `updateCred()` updates the file. In TPM mode, must update NV:

```go
func updateCred(newDC fdo.DeviceCredential) error {
    if tpmPath != "" {
        tpmc, _ := tpmOpen(tpmPath)
        return tpm.UpdateCredential(tpmc, &newDC)
    }
    // ... existing blob path unchanged
}
```

#### `examples/cmd/tpm.go` — Use persistent handles

Current `tpmCred()` creates transient keys. Must change to:

```go
func tpmCred() (hash.Hash, hash.Hash, crypto.Signer, func() error, error) {
    tpmc, _ := tpmOpen(tpmPath)
    h256, h384, _ := tpm.HMACsFromTPM(tpmc)
    key, _ := tpm.SignerFromTPM(tpmc)
    return h256, h384, key, func() error {
        _ = h256.Close()
        _ = h384.Close()
        _ = key.Close()
        return tpmc.Close()
    }, nil
}
```

#### `examples/cmd/client.go` — DI provisioning flow

Current `di()` generates keys in software then optionally swaps for TPM.
In full TPM mode, DI must also write credential data to NV:

```go
func di(ctx context.Context) error {
    // ... existing key/HMAC generation (transient, for the DI protocol) ...

    // Run DI protocol (unchanged)
    cred, err := fdo.DI(ctx, transport, mfgInfo, fdo.DIConfig{
        HmacSha256: hmacSha256, HmacSha384: hmacSha384, Key: key,
    })

    if tpmPath != "" {
        tpmc, _ := tpmOpen(tpmPath)
        // Provision: write credentials to TPM NV + persist keys
        return tpm.Provision(tpmc, cred, tpm.ProvisionOpts{
            Curve: selectedCurve,
            UseOwnerHierarchy: ownerHierarchyFlag,
        })
        // NO cred.bin written!
    }
    return saveCred(blob.DeviceCredential{...}) // blob path unchanged
}
```

### Layer 4: Protocol Library Considerations

The core protocol library (`di.go`, `to2.go`, `to1.go`, `hash.go`,
`voucher.go`) does NOT need changes. The interfaces are already correct:

| Interface | Used by | TPM-compatible? |
|-----------|---------|----------------|
| `hash.Hash` | `DIConfig.HmacSha256/384`, `TO2Config.HmacSha256/384`, `VerifyOptions.HmacSha256/384` | Yes — `tpm.Hmac` satisfies it |
| `crypto.Signer` | `DIConfig.Key`, `TO2Config.Key`, TO1's `key` param | Yes — `tpm.Key` satisfies it |
| `fallibleHash` | `hmacHash()` and `hmacVerify()` in `hash.go` | Yes — `tpm.Hmac.Err()` satisfies it |

**One notable limitation**: The `ASYMKEX2048`/`ASYMKEX3072` key exchange suites
(`kex/oaep.go:117-119`) require `*rsa.PrivateKey` for decryption and explicitly
reject TPM keys. This is a server-side concern (the device doesn't use OAEP
decryption), but worth noting. ECDH suites work fine with TPM.

---

## Detailed Work Items

### WI-1: Extract NV Operations from Tests to Library

**Effort**: Medium
**Files**: New `tpm/nv.go`
**Depends on**: Nothing

Move and generalize the NV operations from `spec_compliance_test.go` into
production code:

1. Export the NV index constants (currently test-only `const` block)
2. Create `NVProfile` type and profile attribute constructors
3. Implement `DefineNVIndex()`, `WriteNV()`, `ReadNV()`, `UndefineNV()`, `NVExists()`
4. Handle Platform vs Owner hierarchy based on configuration
5. Unit tests for each function

### WI-2: Extract Persistent Key Operations from Tests to Library

**Effort**: Medium
**Files**: New `tpm/persistent.go`
**Depends on**: WI-1

Move and generalize the persistent key operations:

1. Export `ComputeAuthPolicy()` (from `computeFDOAuthPolicy()`)
2. Export `KeyPolicy()` (from `fdoKeyPolicy()`)
3. Implement `CreatePersistentECCKey()` and `CreatePersistentHMACKey()`
4. Support P-256 and P-384 curves
5. Unit tests for each function

### WI-3: New Constructors for Persistent-Handle Key/HMAC

**Effort**: Medium
**Files**: `tpm/key.go`, `tpm/hmac.go`
**Depends on**: WI-2

Add `OpenKey()` and `OpenHMAC()` constructors:

1. `OpenKey(t, handle, nvIndex)` — loads persistent key, uses policy auth
2. `OpenHMAC(t, handle, nvIndex, hashAlg)` — loads persistent HMAC key, uses policy auth
3. Both return existing interface types (`Key`, `Hmac`)
4. `Close()` on persistent keys must NOT flush the handle
5. Policy session management for authorization
6. Unit tests

### WI-4: Credential Lifecycle Functions

**Effort**: Large
**Files**: `tpm/credential.go` (extend)
**Depends on**: WI-1, WI-2, WI-3

Implement the full credential lifecycle:

1. `Provision()` — called during DI:
   - Generate Unique Strings (random bytes for HMAC and DeviceKey NV indices)
   - Define all 6 NV indices with correct profiles
   - Write Unique Strings to NV indices `0x01D10003`, `0x01D10004`
   - Compute auth policy digest
   - Create + persist ECC key at `0x81020002` using DeviceKey Unique String
   - Create + persist HMAC key at `0x81020003` using HMAC Unique String
   - Serialize DCTPM structure (version, device info, GUID, RV info, pubkey hash,
     device key type, device key handle) and write to NV `0x01D10001`
   - Write DCOV data to NV `0x01D10002`
   - Set DCActive to `0x01` at NV `0x01D10000`
   - Optionally write FDO certificate to NV `0x01D10005`

2. `LoadCredential()` — called during TO1/TO2:
   - Check DCActive at `0x01D10000`
   - Read DCTPM from NV `0x01D10001`
   - Deserialize into `fdo.DeviceCredential`
   - Return populated credential

3. `SignerFromTPM()` — wrapper for `OpenKey(t, 0x81020002, 0x01D10004)`

4. `HMACsFromTPM()` — wrapper for `OpenHMAC(t, 0x81020003, 0x01D10003, ...)`

5. `UpdateCredential()` — called after TO2 credential replacement:
   - Read existing DCTPM
   - Update GUID, RvInfo, PublicKeyHash
   - Re-write DCTPM to NV `0x01D10001`
   - Update DCOV at `0x01D10002`

6. `IsProvisioned()` — read DCActive flag

7. `Deprovision()` — remove all NV indices and persistent handles

### WI-5: CLI Integration

**Effort**: Medium
**Files**: `examples/cmd/credential.go`, `examples/cmd/tpm.go`, `examples/cmd/client.go`
**Depends on**: WI-4

Update the example CLI to use NV-based credentials when `-tpm` is set:

1. `readCred()` — branch: TPM mode reads from NV, blob mode reads from file
2. `saveCred()` — branch: TPM mode is no-op (data already in NV), blob mode writes file
3. `updateCred()` — branch: TPM mode calls `tpm.UpdateCredential()`, blob mode updates file
4. `tpmCred()` — use `OpenKey`/`OpenHMAC` instead of `GenerateECKey`/`NewHmac`
5. `di()` — after DI protocol, call `tpm.Provision()` instead of `saveCred()`
6. Integration test: verify no `cred.bin` is created in TPM mode

### WI-6: Update `tpm.DeviceCredential` Struct

**Effort**: Small
**Files**: `tpm/credential.go`
**Depends on**: WI-4

The `tpm.DeviceCredential` struct may need to be updated or deprecated:

- Currently stores `DeviceKeyType` and `DeviceKeyHandle`
- In full TPM mode, these are always `FdoDeviceKey` and `0x81020002`
- The struct might become unnecessary (credential data lives in NV, not in a Go struct)
- Consider keeping it as a transient in-memory representation returned by `LoadCredential()`

### WI-7: Integration Tests

**Effort**: Medium
**Files**: New `tpm/integration_test.go` or extend `tpm/tpm_test.go`
**Depends on**: WI-5

End-to-end tests using the actual DI/TO2 protocol with TPM NV storage:

1. DI with TPM → verify NV indices populated, no file on disk
2. TO1+TO2 with TPM → verify credential read from NV, attestation succeeds
3. TO2 credential replacement → verify NV updated
4. Credential reuse → verify NV unchanged
5. Deprovision → verify all NV indices removed
6. Re-provision after deprovision → verify keys re-derived correctly

### WI-8: Update Integration Test Script

**Effort**: Small
**Files**: `test_examples.sh`
**Depends on**: WI-5

Add test scenarios for TPM credential storage:

```bash
# New test case
tpm-nv)   # TPM NV-based credential storage (no cred.bin)
```

---

## Interface Compatibility Analysis

The key insight from this analysis is that the **protocol-level interfaces are
already TPM-friendly**. The work is entirely in the `tpm/` package and the CLI:

### Interfaces that DON'T need to change

| Interface | File | Why it's fine |
|-----------|------|---------------|
| `hash.Hash` | stdlib | `tpm.Hmac` already satisfies it |
| `crypto.Signer` | stdlib | `tpm.Key` already satisfies it |
| `fallibleHash` | `hash.go:17-19` | `tpm.Hmac.Err()` satisfies it |
| `fdo.DIConfig` | `di.go:19-52` | Accepts `hash.Hash` + `crypto.Signer` |
| `fdo.TO2Config` | `to2.go:89-178` | Accepts `hash.Hash` + `crypto.Signer` |
| `fdo.VerifyOptions` | `voucher.go:275-290` | Accepts `hash.Hash` |
| `fdo.DeviceCredential` | `credential.go:24-30` | Contains only public metadata |

### Interfaces that need NEW implementations (not changes)

| Interface | Current impl | New impl needed |
|-----------|-------------|----------------|
| `tpm.Key` (`crypto.Signer`) | Transient primary key | Persistent handle + policy auth |
| `tpm.Hmac` (`hash.Hash`) | Transient primary key | Persistent handle + policy auth |

### Code paths that need branching (TPM NV vs file)

| Code path | File | Change |
|-----------|------|--------|
| `readCred()` | `examples/cmd/credential.go:22` | TPM: read from NV; blob: read from file |
| `saveCred()` | `examples/cmd/credential.go:83` | TPM: no-op; blob: write file |
| `updateCred()` | `examples/cmd/credential.go:65` | TPM: update NV; blob: update file |
| `tpmCred()` | `examples/cmd/tpm.go:24` | Use persistent handles instead of transient |
| `di()` | `examples/cmd/client.go:257` | TPM: call `tpm.Provision()`; blob: call `saveCred()` |

---

## Risk Assessment

### Low Risk

- **NV operations**: Well-understood TPM2 commands, fully exercised in
  `spec_compliance_test.go` Phases 3-6
- **Persistent handles**: Standard TPM2 pattern, tested in Phase 4
- **Protocol compatibility**: No changes to core protocol code

### Medium Risk

- **Policy session management**: Policy sessions are more complex than HMAC
  sessions. The compound `PolicyNV || PolicySecret` policy requires correct
  NV index state. Tested in Phase 5 but production error handling needs care.
- **TPM2_Clear resilience**: Keys are re-derived from Unique Strings after
  `TPM2_Clear`. The NV indices storing Unique Strings are in Profile B
  (platform-created) — they survive `TPM2_Clear`. Tested in Phase 3
  (`ClearResilience`) but the full credential lifecycle after clear needs
  end-to-end testing.

### Higher Risk

- **NV space constraints**: Real TPMs have limited NV space. The DCTPM
  structure and DCOV data could be large. Need to measure actual sizes and
  ensure they fit within typical TPM NV limits (usually 768 bytes per index
  on older TPMs, larger on newer ones).
- **Platform hierarchy availability**: On many Linux systems, Platform
  hierarchy is locked after boot. Profile A and B indices require
  PlatformCreate. The Owner hierarchy fallback changes the security
  properties (no PlatformCreate attribute). This is documented in the spec
  but may confuse users.
- **Concurrent TPM access**: Multiple processes accessing the same TPM
  simultaneously can cause resource contention. The resource manager
  (`/dev/tpmrm0`) helps but doesn't eliminate all issues.

---

## Sequencing Recommendation

```
Phase A: Foundation (WI-1, WI-2)
  Extract NV and persistent key operations from tests to library.
  These are well-tested patterns being promoted to production code.

Phase B: Key Access (WI-3, WI-6)
  New constructors for persistent-handle-backed Key/Hmac.
  Update DeviceCredential struct.

Phase C: Credential Lifecycle (WI-4)
  The core work: Provision, LoadCredential, UpdateCredential, etc.
  This is the largest work item.

Phase D: CLI Integration (WI-5)
  Wire everything into the example CLI.
  Eliminate cred.bin in TPM mode.

Phase E: Testing (WI-7, WI-8)
  Integration tests and test script updates.
  Verify on both simulator and hardware.
```

Estimated total effort: **Medium-Large** (the individual pieces are
straightforward since the spec compliance tests already exercise all the
TPM operations — the work is primarily structuring them as a production
library with proper error handling, documentation, and testing).

---

## Appendix: File Impact Summary

### New files

| File | Purpose |
|------|---------|
| `tpm/nv.go` | NV index management (define, read, write, undefine) |
| `tpm/persistent.go` | Persistent key management (create, auth policy, load) |
| `tpm/integration_test.go` | End-to-end integration tests |

### Modified files

| File | Changes |
|------|---------|
| `tpm/credential.go` | Add `Provision()`, `LoadCredential()`, `UpdateCredential()`, `IsProvisioned()`, `SignerFromTPM()`, `HMACsFromTPM()`, `Deprovision()` |
| `tpm/key.go` | Add `OpenKey()` constructor, `persistent` flag on `key` struct, policy-based `Close()` |
| `tpm/hmac.go` | Add `OpenHMAC()` constructor, policy-based auth path, persistent handle support |
| `examples/cmd/credential.go` | Branch `readCred()`/`saveCred()`/`updateCred()` for TPM NV mode |
| `examples/cmd/tpm.go` | Use persistent handles in `tpmCred()` |
| `examples/cmd/client.go` | Call `tpm.Provision()` after DI in TPM mode |
| `test_examples.sh` | Add TPM NV credential storage test scenario |

### Unchanged files

| File | Why unchanged |
|------|--------------|
| `di.go` | Accepts `hash.Hash` + `crypto.Signer` — already TPM-compatible |
| `to2.go` | Same |
| `to1.go` | Same |
| `hash.go` | `hmacHash()` / `hmacVerify()` use `hash.Hash` interface — already works with TPM |
| `voucher.go` | Uses `hash.Hash` for HMAC verification — already works with TPM |
| `credential.go` | `fdo.DeviceCredential` is public metadata only — no secrets |
| `blob/credential.go` | Software credential path — unchanged, remains default |
