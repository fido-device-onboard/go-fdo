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
| Integration with DI/TO2 protocol | Working | `cred/tpm_store.go` — `cred.Store` interface provides `NewDI`/`Save`/`Load` with full NV lifecycle |
| `tpm.DeviceKeyType` constants | Working | `tpm/credential.go` — `FdoDeviceKey`, `IDevIDDeviceKey`, `LDevIDDeviceKey` (struct removed, constants retained) |
| Spec compliance tests (Phases 1-7) | Working | `tpm/spec_compliance_test.go` — exercises NV indices, persistent handles, auth policies, E2E flow, library API |
| NV index management | Working | `tpm/nv.go` — `DefineNVSpace`, `WriteNV`, `ReadNVCredentials`, `UndefineNVSpace`, `CleanupFDOState` |
| Spec-compliant key creation | Working | `tpm/key.go` — `GenerateSpecECKey` (UserWithAuth=false, AuthPolicy, UniqueString) |
| Spec-compliant HMAC key creation | Working | `tpm/key.go` — `GenerateSpecHMACKey` (UserWithAuth=false, AuthPolicy, UniqueString) |
| Persistent key loading + policy auth | Working | `tpm/key.go` — `LoadPersistentKey`; `tpm/hmac.go` — `NewSpecHmac` |
| NV-based credential store | Working | `cred/tpm_store.go` — `NewDI` provisions NV+keys, `Save` writes DCTPM/DCOV/DCActive to NV, `Load` reads from NV with file fallback |
| TPM inspection CLI | Working | `examples/cmd/tpm.go` — `tpmShowCredentials`, `tpmExportDAK`, `tpmProveDAK` |
| DAK possession proof | Working | `tpm/nv.go` — `ReadDAKPublicKey`, `ProveDAKPossession` |

### What Does NOT Work (The Gaps)

| Gap | Severity | Description | Status |
|-----|----------|-------------|--------|
| **G1: Credentials still on disk** | ~~Critical~~ | ~~`cred/tpm_store.go:Save()` writes NV indices correctly but also writes a minimal `cred.bin` file for backward compatibility~~ | **CLOSED** — `Save()` no longer writes any file; all credential data lives exclusively in TPM NV. `Load()` reads from NV only (no file fallback). |
| **G2: No NV storage in production code** | ~~Critical~~ | ~~NV index operations exist only in tests~~ | **CLOSED** — `tpm/nv.go` has `DefineNVSpace`, `WriteNV`, `ReadNVCredentials`, `UndefineNVSpace`, `CleanupFDOState`, etc. |
| **G3: Transient keys only** | ~~Critical~~ | ~~Production code uses `CreatePrimary` + `FlushContext` (ephemeral)~~ | **CLOSED** — `tpm/key.go:GenerateSpecECKey()` + `tpm/nv.go:PersistKey()` create persistent keys at `0x81020002`/`0x81020003`; `LoadPersistentKey()` loads them |
| **G4: No Unique Strings** | ~~Critical~~ | ~~Production key templates do not set the `Unique` field~~ | **CLOSED** — `GenerateSpecECKey()` and `GenerateSpecHMACKey()` accept Unique Strings; `cred/tpm_store.go:NewDI()` generates and stores them in NV |
| **G5: Wrong auth model** | ~~Critical~~ | ~~Production keys use `UserWithAuth=true`~~ | **CLOSED** — Spec-compliant functions (`GenerateSpecECKey`, `GenerateSpecHMACKey`, `LoadPersistentKey`, `NewSpecHmac`) use `UserWithAuth=false` + policy session auth. Legacy functions (`GenerateECKey`, `NewHmac`) retain `UserWithAuth=true` for backward compat. |
| **G6: No DCActive flag** | ~~High~~ | ~~No NV index for DCActive~~ | **CLOSED** — `cred/tpm_store.go:NewDI()` creates DCActive at `0x01D10000` (Profile A); `Save()` sets it to `0x01`; `loadFromNV()` checks it |
| **G7: No DCTPM in NV** | ~~High~~ | ~~DCTPM not stored in NV~~ | **CLOSED** — `cred/tpm_store.go:Save()` writes DCTPM to NV `0x01D10001` (Profile B) |
| **G8: No DCOV in NV** | ~~Medium~~ | ~~DCOV not stored in NV~~ | **CLOSED** — `cred/tpm_store.go:Save()` writes DCOV to NV `0x01D10002` (Profile C) |
| **G9: "FDO Certificate" in NV** | ~~Low~~ | ~~Optional X.509 cert not stored in NV index `0x01D10005`~~ | **Spec gap** — The spec defines NV index `0x01D10005` for an "FDO Device Certificate" described as an X.509 certificate, but what the spec actually envisions storing here is the Ownership Voucher, which is not an X.509 certificate. The OV is a CBOR-encoded, variable-length data structure with no normalized format suitable for TPM NV storage. It is also large — easily exceeding the ~700-byte practical limit of older TPMs. Furthermore, the information it provides (proof of ownership) can be obtained at any time by re-running TO2, and if local persistence is desired for self-re-attestation purposes, it can be stored on whatever media is available (filesystem, flash, etc.) without compromising the TPM security model. See discussion in `tpm-spec-gap-analysis.md` §13. |
| **G10: No NV credential reader** | ~~Critical~~ | ~~No function to read credentials from NV~~ | **CLOSED** — `tpm/nv.go:ReadNVCredentials()` reads all NV indices; `cred/tpm_store.go:loadFromNV()` uses it |
| **G11: No DI provisioner** | ~~Critical~~ | ~~No function to provision NV during DI~~ | **CLOSED** — `cred/tpm_store.go:NewDI()` does full provisioning (Unique Strings → NV, auth policies, persistent keys, DCActive) |
| **G12: CLI still writes cred.bin** | ~~Critical~~ | ~~`cred/tpm_store.go:Save()` still writes a file via `writeCredFile()` alongside NV~~ | **CLOSED** — `Save()` no longer writes any file. `Load()` reads exclusively from NV (file fallback removed). |

---

## Architecture: What Changed (vs Original Plan)

> **Note:** This section was originally titled "What Needs to Change." Most of the
> proposed work has been completed, though the final architecture differs from the
> original plan in some ways. This section is preserved with annotations for reference.

### Layer 1: `tpm/` Package — Production Functions — DONE

The `tpm/` package now has production functions that mirror and extend what
`spec_compliance_test.go` exercises.

#### 1a. NV Index Management — DONE

```
tpm/nv.go (EXISTS)
```

All proposed functions were implemented (some with slightly different names):

| Proposed Function | Actual Implementation | Status |
|-------------------|----------------------|--------|
| `DefineNVIndex(t, index, size, profile, hierarchy)` | `DefineNVSpace(t, index, size, profile, usePlatform)` | **DONE** |
| `WriteNV(t, index, data, profile)` | `WriteNV(t, index, nvName, data, profile)` | **DONE** |
| `ReadNV(t, index, size, profile)` | `ReadNVCredentials(t)` (reads all indices) + internal `nvReadOwner`/`nvReadAuth` | **DONE** |
| `UndefineNV(t, index, hierarchy)` | `UndefineNVSpace(t, index)` | **DONE** |
| `NVExists(t, index)` | Implicit in `ReadNVCredentials()` error handling | **DONE** (differently) |

Additional functions not in original plan:

- `ComputeFDOAuthPolicy(t, usIndex, usName)` — trial session policy digest
- `PersistKey(t, transient, persistentHandle)` — EvictControl wrapper
- `EvictPersistentHandle(t, handle)` — remove persistent handle
- `CleanupFDOState(t)` — remove all FDO NV indices and persistent handles
- `ReadDAKPublicKey(t)` — read public key from persistent DAK handle
- `ProveDAKPossession(t, challenge)` — sign challenge with DAK via policy session

Constants (now in production `tpm/nv.go`):

```go
const (
    DCActiveIndex     = 0x01D10000
    DCTPMIndex        = 0x01D10001
    DCOVIndex         = 0x01D10002
    HMACUSIndex       = 0x01D10003
    DeviceKeyUSIndex  = 0x01D10004
    FDOCertIndex      = 0x01D10005

    DAKHandle         = 0x81020002
    HMACKeyHandle     = 0x81020003
)
```

NV profile types (now in production `tpm/nv.go`):

```go
type NVProfile int
const (
    NVProfileA NVProfile = iota // DCActive: OwnerWrite+AuthWrite+OwnerRead+AuthRead+NoDA+PlatformCreate
    NVProfileB                  // DCTPM, US indices: AuthWrite+AuthRead+NoDA+PlatformCreate
    NVProfileC                  // DCOV, FDO_Cert: OwnerWrite+AuthWrite+OwnerRead+AuthRead+NoDA (Owner-created)
)
```

#### 1b. Persistent Key Management — DONE

```
tpm/key.go + tpm/nv.go (functions split across both files)
```

> **Note:** The original plan proposed a new `tpm/persistent.go` file. Instead,
> persistent key functions were distributed across `tpm/key.go` and `tpm/nv.go`.

| Proposed Function | Actual Implementation | Location | Status |
|-------------------|----------------------|----------|--------|
| `CreatePersistentECCKey(...)` | `GenerateSpecECKey()` + `PersistKey()` | `key.go` + `nv.go` | **DONE** (two-step) |
| `CreatePersistentHMACKey(...)` | `GenerateSpecHMACKey()` + `PersistKey()` | `key.go` + `nv.go` | **DONE** (two-step) |
| `ComputeAuthPolicy(...)` | `ComputeFDOAuthPolicy()` | `nv.go` | **DONE** |
| `KeyPolicy(...)` | `fdoKeyPolicy()` (unexported) | `nv.go` | **DONE** (internal) |
| `LoadPersistentKey(...)` | `LoadPersistentKey()` | `key.go` | **DONE** |
| `LoadPersistentHMAC(...)` | `NewSpecHmac()` | `hmac.go` | **DONE** |

#### 1c. Credential Lifecycle — DONE (at `cred/` layer)

> **Note:** The original plan proposed adding lifecycle functions to
> `tpm/credential.go`. Instead, the functionality was implemented in
> `cred/tpm_store.go` via the `cred.Store` interface.

| Proposed Function | Actual Implementation | Location | Status |
|-------------------|----------------------|----------|--------|
| `Provision()` | `tpmStore.NewDI()` | `cred/tpm_store.go` | **DONE** |
| `LoadCredential()` | `tpmStore.loadFromNV()` | `cred/tpm_store.go` | **DONE** |
| `IsProvisioned()` | Implicit in `loadFromNV()` (checks DCActive) | `cred/tpm_store.go` | **DONE** (implicit) |
| `SignerFromTPM()` | `LoadPersistentKey()` called inline | `cred/tpm_store.go` | **DONE** (inline) |
| `HMACsFromTPM()` | `NewSpecHmac()` called inline | `cred/tpm_store.go` | **DONE** (inline) |
| `UpdateCredential()` | `tpmStore.Save()` (re-writes NV) | `cred/tpm_store.go` | **DONE** |
| `Deprovision()` | `CleanupFDOState()` | `tpm/nv.go` | **DONE** |

### Layer 2: Adapt Existing `tpm.Key` and `tpm.Hmac` — DONE

The original `tpm.Key` and `tpm.Hmac` implementations create **transient**
primary keys each time. New constructors for persistent-handle-backed operations
were added alongside the originals (backward compatible).

#### Original constructors (kept for backward compat)

```go
// Creates a transient primary key — existing behavior, unchanged
func GenerateECKey(t TPM, curve elliptic.Curve) (Key, error)
func NewHmac(t TPM, h crypto.Hash) (Hmac, error)
```

#### New constructors (implemented)

```go
// Spec-compliant ECC key: UserWithAuth=false, AuthPolicy, UniqueString
func GenerateSpecECKey(t TPM, curveID, hashAlg, uniqueString, policy) (*tpm2.NamedHandle, crypto.PublicKey, error)

// Spec-compliant HMAC key: UserWithAuth=false, AuthPolicy, UniqueString
func GenerateSpecHMACKey(t TPM, uniqueString, policy) (*tpm2.NamedHandle, error)

// Load a persistent key at the given handle.
// Uses policy session authorization (not password auth).
func LoadPersistentKey(t TPM, persistentHandle uint32, usIndex uint32) (Key, error)

// Load a persistent HMAC key at the given handle.
// Uses policy session authorization.
func NewSpecHmac(t TPM, h crypto.Hash) (Hmac, error)
```

Key differences between legacy and spec-compliant implementations:

| Aspect | Legacy (transient) | Spec-compliant (persistent) |
|--------|-------------------|-----------------|
| Key creation | `CreatePrimary` each time | `CreatePrimary` + `EvictControl` once during DI |
| Key loading | N/A (derived on demand) | `ReadPublic` on persistent handle |
| Authorization | `UserWithAuth=true`, HMAC session | `UserWithAuth=false`, policy session via `PolicyNV + PolicySecret` |
| `Close()` behavior | `FlushContext` (destroys key) | No-op (key persists) |
| Unique field | Not set | Set from Unique String stored in NV |

Implementation details:

- `persistentKey` type in `tpm/key.go` wraps persistent handle with no-op `Close()`
- `specHmac` type in `tpm/hmac.go` wraps persistent HMAC with policy session auth
- `fdoKeyPolicy()` in `tpm/nv.go` provides JIT policy session for both key types

### Layer 3: CLI Changes (`examples/cmd/`) — DONE (via cred.Store interface)

> **Note:** The original plan proposed explicit TPM-vs-blob branching in
> `credential.go`, `tpm.go`, and `client.go`. Instead, the CLI was refactored
> to use a `cred.Store` interface abstraction. Build tags select the backend
> (`tpm`, `tpmsim`, or default blob). No explicit `if tpmPath != ""` branching.

#### `examples/cmd/credential.go` — Refactored

The file now delegates all storage to `credStore` (a `cred.Store`):

- `openCredStore()` → `cred.Open(blobPath)` (build tags select backend)
- `newDICred(keyType)` → `credStore.NewDI(keyType)`
- `saveCred(dc)` → `credStore.Save(dc)`
- `readCred()` → `credStore.Load()`
- `closeCredStore()` → `credStore.Close()`

**Remaining gap:** `cred/tpm_store.go:Save()` still writes a file alongside NV
for backward compatibility. The original goal of "no `cred.bin`" is not fully
achieved.

#### `examples/cmd/tpm.go` — Replaced

The original `tpmCred()` function no longer exists. The file now provides
TPM diagnostic/inspection utilities:

- `tpmShowCredentials()` — reads and displays all FDO credentials from NV
- `tpmExportDAK()` — exports DAK public key as PEM
- `tpmProveDAK()` — proves DAK possession by signing a challenge

#### `examples/cmd/client.go` — Uses cred.Store

`di()` calls `newDICred(keyType)` which delegates to `tpmStore.NewDI()`.
The provisioning happens inside the `cred.Store` implementation, not in
the CLI code itself.

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

## Detailed Work Items — Status

### WI-1: Extract NV Operations from Tests to Library — DONE

**Files**: `tpm/nv.go` (created)

All NV operations moved to production code:

1. Exported NV index constants (`DCActiveIndex`, `DCTPMIndex`, etc.)
2. Created `NVProfile` type with `NVProfileA`, `NVProfileB`, `NVProfileC`
3. Implemented `DefineNVSpace()`, `WriteNV()`, `UndefineNVSpace()`
4. Platform vs Owner hierarchy handled via `usePlatform` parameter
5. Tested in Phase 9 integration tests + `cred/tpm_store_test.go`

### WI-2: Extract Persistent Key Operations from Tests to Library — DONE

**Files**: `tpm/key.go`, `tpm/nv.go`

> **Note:** Implemented across two files instead of a new `tpm/persistent.go`.

1. `ComputeFDOAuthPolicy()` exported in `tpm/nv.go`
2. `fdoKeyPolicy()` unexported in `tpm/nv.go` (used internally by `LoadPersistentKey` and `NewSpecHmac`)
3. `GenerateSpecECKey()` and `GenerateSpecHMACKey()` in `tpm/key.go`
4. P-256 and P-384 curves supported
5. Tested in Phase 9 integration tests

### WI-3: New Constructors for Persistent-Handle Key/HMAC — DONE

**Files**: `tpm/key.go`, `tpm/hmac.go`

> **Note:** Named `LoadPersistentKey` and `NewSpecHmac` instead of `OpenKey`/`OpenHMAC`.

1. `LoadPersistentKey(t, handle, nvIndex)` — loads persistent key, uses policy auth
2. `NewSpecHmac(t, h)` — loads persistent HMAC key, uses policy auth
3. Both return existing interface types (`Key`, `Hmac`)
4. `Close()` on persistent keys is a no-op (key persists)
5. Policy session management via `fdoKeyPolicy()`
6. Tested in Phase 9 integration tests

### WI-4: Credential Lifecycle Functions — DONE (at cred/ layer)

**Files**: `cred/tpm_store.go` (created)

> **Note:** Functions were implemented on the `cred.Store` interface rather
> than directly in `tpm/credential.go` as originally planned.

1. `tpmStore.NewDI()` serves as `Provision()` — full NV + key provisioning
2. `tpmStore.loadFromNV()` serves as `LoadCredential()` — reads from NV indices
3. `tpmStore.Save()` serves as `UpdateCredential()` — re-writes DCTPM/DCOV/DCActive
4. `tpm.CleanupFDOState()` serves as `Deprovision()`
5. Backward compatibility: `Load()` falls back to file-based credentials
6. Tested in `cred/tpm_store_test.go` and Phase 9 integration tests

### WI-5: CLI Integration — DONE (via cred.Store interface)

**Files**: `examples/cmd/credential.go`, `examples/cmd/tpm.go`, `examples/cmd/client.go`

> **Note:** Implemented via `cred.Store` interface + build tags, not explicit branching.

1. `readCred()` → `credStore.Load()` — **DONE** (polymorphic)
2. `saveCred()` → `credStore.Save()` — **DONE** (writes NV + file)
3. `updateCred()` → not needed (Save handles both cases) — **DONE** (removed)
4. `tpmCred()` → removed; `cred/tpm_store.go` handles key creation — **DONE**
5. `di()` → `newDICred()` delegates to `tpmStore.NewDI()` — **DONE**
6. **Remaining gap:** `cred.bin` is still created alongside NV for backward compat

### WI-6: Remove `tpm.DeviceCredential` Struct — DONE

**Files**: `tpm/credential.go` (struct + String() removed), `tpm/tpm_test.go`
(switched to `blob.DeviceCredential` for logging), `tpm/hardware_test.go`
(removed `tpm.DeviceCredential` usage), `doc.go` (updated reference)

The `tpm.DeviceCredential` struct (which embedded `fdo.DeviceCredential` +
`DeviceKeyType` + `DeviceKeyHandle`) has been removed. It was dead code — the
NV flow in `cred/tpm_store.go` works with `fdo.DeviceCredential` directly and
stores TPM-specific fields in separate NV indices. The `DeviceKeyType`
constants (`FdoDeviceKey`, `IDevIDDeviceKey`, `LDevIDDeviceKey`) are retained
in `tpm/credential.go` as they are used by spec compliance tests and the
DCTPM CBOR structure.

### WI-7: Integration Tests — DONE

**Files**: `tpm/phase9_integration_test.go`, `cred/tpm_store_test.go`

TPM-layer tests (`phase9_integration_test.go`):

1. `TestPhase9_ProductionAPI_NVOnly` — full DI→NV→Load→Sign→HMAC cycle
2. `TestPhase9_HMACDeterminism` — persistent HMAC key determinism
3. `TestPhase9_SignMultipleDigests` — persistent DAK signs 10 digests
4. `TestPhase9_PasswordAuthRejected` — UserWithAuth=false enforced
5. `TestPhase9_CleanupFDOState` — provision → cleanup → verify

cred.Store tests (`cred/tpm_store_test.go`):

1. `TestTPMStore_NVOnlyRoundTrip` — Open→NewDI→Save→Load from NV only
2. `TestTPMStore_FileFallback` — Load succeeds via NV-first with file present
3. `TestTPMStore_SaveOverwrite` — Save twice, Load returns latest credential

### WI-8: Update Integration Test Script — PARTIALLY DONE

**Files**: `test_examples.sh`

TPM test scenarios may have been added; requires verification against current
`test_examples.sh` content.

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

### Interfaces that need NEW implementations (not changes) — DONE

| Interface | Original impl | New impl | Status |
|-----------|-------------|----------------|--------|
| `tpm.Key` (`crypto.Signer`) | Transient primary key | `persistentKey` — persistent handle + policy auth | **DONE** |
| `tpm.Hmac` (`hash.Hash`) | Transient primary key | `specHmac` — persistent handle + policy auth | **DONE** |

### Code paths that were branched (TPM NV vs file) — DONE via cred.Store

> **Note:** These were implemented via the `cred.Store` interface + build tags,
> not explicit if/else branching.

| Code path | File | Status |
|-----------|------|--------|
| `readCred()` | `examples/cmd/credential.go` | **DONE** — delegates to `credStore.Load()` |
| `saveCred()` | `examples/cmd/credential.go` | **DONE** — delegates to `credStore.Save()` |
| `updateCred()` | `examples/cmd/credential.go` | **Removed** — `Save()` handles both DI and TO2 |
| `tpmCred()` | `examples/cmd/tpm.go` | **Removed** — `cred/tpm_store.go` handles key creation |
| `di()` | `examples/cmd/client.go` | **DONE** — `newDICred()` delegates to `tpmStore.NewDI()` |

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

## Sequencing — Completed

All phases have been completed:

```
Phase A: Foundation (WI-1, WI-2) — DONE
  NV and persistent key operations extracted to tpm/nv.go and tpm/key.go.

Phase B: Key Access (WI-3, WI-6) — DONE
  LoadPersistentKey and NewSpecHmac implemented.
  tpm.DeviceCredential struct removed (dead code for NV flow).

Phase C: Credential Lifecycle (WI-4) — DONE
  Implemented in cred/tpm_store.go via cred.Store interface.

Phase D: CLI Integration (WI-5) — DONE
  CLI refactored to use cred.Store. Build tags select backend.

Phase E: Testing (WI-7, WI-8) — MOSTLY DONE
  Phase 9 integration tests + cred.Store tests complete.
  test_examples.sh updates partially done.
```

### Remaining Work

1. ~~**Eliminate `cred.bin` in TPM mode** (G1/G12)~~ — **DONE.** `Save()` no
   longer writes any file; `Load()` reads exclusively from NV.
2. ~~**FDO Certificate in NV** (G9)~~ — **Reclassified as spec gap.** The spec
   defines `0x01D10005` for an "FDO Device Certificate" but the data in
   question (Ownership Voucher) is not an X.509 certificate and has no
   normalized format suitable for TPM NV storage. Not implementing.
3. ~~**Clean up `tpm.DeviceCredential`** (WI-6)~~ — **DONE.** Struct and
   `String()` method removed. `DeviceKeyType` constants retained.

---

## Appendix: File Impact Summary — Actuals

### Files created

| File | Purpose | Status |
|------|---------|--------|
| `tpm/nv.go` | NV index management + persistent key helpers + DAK proof | **Created** |
| `cred/tpm_store.go` | `cred.Store` implementation with NV-based lifecycle | **Created** |
| `cred/tpm_store_test.go` | cred.Store interface tests (tpmsim build tag) | **Created** |
| `tpm/phase9_integration_test.go` | Library integration tests (spec_compliance_test build tag) | **Created** |

> **Note:** `tpm/persistent.go` and `tpm/integration_test.go` (proposed in original plan) were not created.
> Their functionality was absorbed into `tpm/nv.go`, `tpm/key.go`, and `tpm/phase9_integration_test.go`.

### Files modified

| File | Changes |
|------|---------|
| `tpm/key.go` | Added `GenerateSpecECKey()`, `GenerateSpecHMACKey()`, `LoadPersistentKey()`, `persistentKey` type |
| `tpm/hmac.go` | Added `NewSpecHmac()`, `specHmac` type |
| `examples/cmd/credential.go` | Refactored to use `cred.Store` interface (no explicit TPM branching) |
| `examples/cmd/tpm.go` | Replaced `tpmCred()` with inspection utilities (`tpmShowCredentials`, `tpmExportDAK`, `tpmProveDAK`) |
| `examples/cmd/client.go` | Uses `cred.Store` for DI/TO2 credential handling |

### Unchanged files (as predicted)

| File | Why unchanged |
|------|--------------|
| `di.go` | Accepts `hash.Hash` + `crypto.Signer` — already TPM-compatible |
| `to2.go` | Same |
| `to1.go` | Same |
| `hash.go` | `hmacHash()` / `hmacVerify()` use `hash.Hash` interface — already works with TPM |
| `voucher.go` | Uses `hash.Hash` for HMAC verification — already works with TPM |
| `credential.go` | `fdo.DeviceCredential` is public metadata only — no secrets |
| `blob/credential.go` | Software credential path — unchanged, remains default |
| `tpm/credential.go` | `DeviceKeyType` constants retained; `DeviceCredential` struct + `String()` removed (dead code) |
