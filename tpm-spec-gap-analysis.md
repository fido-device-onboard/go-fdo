# Gap Analysis: go-fdo TPM Implementation vs Spec

**Spec:** securing-fdo-in-tpm-v1.0-rd-20231010  
**Implementation:** go-fdo repository, `tpm/` package  
**Date:** 2026-03-10  

## Purpose

This document maps every deviation between the go-fdo TPM implementation and
the "Securing FDO Credentials in the TPM" specification as written. Where a
deviation exists, we note whether the gap is in the implementation, in the
spec, or both. This analysis directly informs the proposed spec amendment
(`proposed-amendment-securing-fdo-in-tpm.md`).

The implementation has two layers:

- **Production code** (`tpm/key.go`, `tpm/hmac.go`, `tpm/nv.go`, `cred/tpm_store.go`): the
  library used by the FDO client/server
- **Spec compliance tests** (`tpm/spec_compliance_test.go`, `tpm/phase9_integration_test.go`): test
  code that exercises the spec's NV index layout, key templates, and policy
  sessions

---

## 1. Hierarchy Selection

### Spec Says

- Device Key and HMAC Secret **SHALL** be created as primary objects in the
  **Endorsement hierarchy** (sections 4.6, 4.7)
- NV indices for credentials **SHOULD** be created under the **Platform
  hierarchy** (`TPMA_NV_PLATFORMCREATE=1`) (Table 9)
- Key persistence via `EvictControl` uses **Owner hierarchy** (Table 6)

### Implementation Does

| Operation | Production Code | Spec Compliance Tests |
|-----------|----------------|----------------------|
| Key creation (`CreatePrimary`) | Endorsement | Endorsement |
| NV index creation (`NV_DefineSpace`) | Platform (Profile A/B), Owner (Profile C) via `tpm/nv.go` | Platform (Profile A/B), Owner (Profile C) |
| Key persistence (`EvictControl`) | Owner via `tpm/nv.go:PersistKey()` | Owner |
| NV read (Profile A/C) | Owner via `tpm/nv.go:nvReadOwner()` | Owner |
| NV read (Profile B) | NV self-auth via `tpm/nv.go:nvReadAuth()` | NV self-auth (empty authValue) |

### Gap

**Production code now matches the spec for key creation hierarchy** (Endorsement)
**and NV operations** (Platform for Profile A/B, Owner for Profile C). The
`tpm/nv.go` module provides full NV index management in production code,
and `cred/tpm_store.go` uses it for credential lifecycle.

**Spec gap:** As argued in the proposed amendment, the Endorsement hierarchy
mandate creates an ownership mismatch for OEM provisioning. The OEM does not
own the Endorsement hierarchy. In practice, an OEM on a manufacturing line
would more naturally place keys under the Platform hierarchy. The spec's
mandate is a friction point for the most common deployment scenario.

---

## 2. Key Creation: Templates and Attributes

### Spec Says (Table 11)

Device Key and HMAC key templates SHALL have:

- `fixedTPM = 1`
- `fixedParent = 1`
- `sensitiveDataOrigin = 1`
- `userWithAuth = 0` (access via policy only)
- `adminWithPolicy = 0`
- `sign = 1`
- `decrypt = 0`
- `restricted = 0`
- `noDA = 0`

- AuthPolicy: `PolicyNV(Unique String, offset=0, size=1, op=GEQ, operand=0) || PolicySecret(Unique String NV Index)` (Table 12)
- Unique field: populated from Unique String NV index (section 4.6)

### Implementation Does

**Production code** (`tpm/key.go`, `tpm/hmac.go`):

The production code now has **two code paths**: legacy (backward-compatible) and
spec-compliant. The spec-compliant functions (`GenerateSpecECKey`,
`GenerateSpecHMACKey`, `LoadPersistentKey`, `NewSpecHmac`) match the spec. The
legacy functions (`GenerateECKey`, `NewHmac`) retain the old behavior.

| Attribute | Spec | Legacy Production | Spec-Compliant Production | Match? |
|-----------|------|-------------------|--------------------------|--------|
| `fixedTPM` | true | true | true | Yes |
| `fixedParent` | true | true | true | Yes |
| `sensitiveDataOrigin` | true | true | true | Yes |
| `userWithAuth` | **false** | **true** | **false** | Legacy: NO / Spec: Yes |
| `sign` / `signEncrypt` | true | true | true | Yes |
| `decrypt` | false | false (not set) | false (not set) | Yes |
| `restricted` | false | false (not set) | false (not set) | Yes |
| AuthPolicy | PolicyNV + PolicySecret digest | **empty** | Computed via `ComputeFDOAuthPolicy()` | Legacy: NO / Spec: Yes |
| Unique field | From NV Unique String | **empty** | From NV index content | Legacy: NO / Spec: Yes |

**Spec compliance tests** (`tpm/spec_compliance_test.go`):

| Attribute | Spec | Test Code | Match? |
|-----------|------|-----------|--------|
| `userWithAuth` | false | false | Yes |
| AuthPolicy | PolicyNV + PolicySecret | Computed via trial session | Yes |
| Unique field | From NV Unique String | From NV index content | Yes |

### Gap

The spec-compliant production functions now match the spec for all three
attributes (`userWithAuth`, AuthPolicy, Unique field). The legacy functions
retain the old behavior for backward compatibility. When `cred/tpm_store.go`
is used (TPM build tag), all key creation goes through the spec-compliant path.

The three deviations that **previously** existed in production code have been
resolved:

1. ~~**`userWithAuth = true`**~~: Spec-compliant functions use `false`.
   `cred/tpm_store.go:NewDI()` calls `GenerateSpecECKey()` and
   `GenerateSpecHMACKey()` which set `UserWithAuth=false`.

2. ~~**No AuthPolicy**~~: `ComputeFDOAuthPolicy()` in `tpm/nv.go` computes the
   spec's compound policy digest. Used by `cred/tpm_store.go:NewDI()`.

3. ~~**No Unique String**~~: `cred/tpm_store.go:NewDI()` generates random
   Unique Strings, writes them to NV indices `0x01D10003`/`0x01D10004`, and
   passes them to `GenerateSpecECKey()`/`GenerateSpecHMACKey()`.

**Spec gap:** The policy mechanism (PolicyNV + PolicySecret) is designed to
restrict key usage to the ROE. As discussed in the proposed amendment, this
restriction becomes counterproductive post-onboarding when the Owner needs
runtime FDO client access to the keys. The spec should define the policy as a
recommended security profile, not a mandatory attribute.

---

## 3. Key Persistence and Rotation

### Spec Says

- Device Key **SHOULD** be persisted to handle `0x81020002` via
  `TPM2_EvictControl` (section 4.6)
- HMAC Secret **MAY** be persisted to handle `0x81020003` (section 4.7)
- If persisted, HMAC Secret **SHALL** be evicted during TO2 (section 4.7)
- Key **rotation** is achieved via **Unique Strings**: a random value stored in
  an NV index is fed into the `CreatePrimary` template's `Unique` field. The
  derivation is: `EPS + Template + Unique String = Key`. Writing a new random
  Unique String and calling `CreatePrimary` produces a different key.
- Persistence is recommended as a convenience and safety net: if Endorsement
  auth is changed by a downstream entity, a persisted key can still be used
  without needing to call `CreatePrimary` (which requires Endorsement auth).

### Implementation Does

**Production code:** Keys are now created via **two paths**:

1. **Legacy path** (`GenerateECKey`/`NewHmac`): Creates **transient** primary
   objects via `CreatePrimary` on every use, with **no Unique String**. Keys are
   flushed after each operation. Used when blob-based credentials are active.

2. **Spec-compliant path** (`cred/tpm_store.go:NewDI()`): Generates random
   Unique Strings, writes them to NV, creates keys with `GenerateSpecECKey()`/
   `GenerateSpecHMACKey()`, and persists to `0x81020002` (DAK) and `0x81020003`
   (HMAC) via `PersistKey()`. Subsequent `Load()` uses `LoadPersistentKey()` and
   `NewSpecHmac()` to access the persistent handles.

**Spec compliance tests:** Keys are created with Unique Strings from NV indices
and persisted to `0x81020002` (DAK) and `0x81020003` (HMAC) via `EvictControl`.

### Gap

**The Unique String and persistence gaps have been closed** in the spec-compliant
code path. When using the TPM build tag and `cred/tpm_store.go`:

1. ~~**Key rotation is impossible**~~: Unique Strings are stored in NV indices.
   Writing a new Unique String and calling `CreatePrimary` derives a new key.
2. ~~**No distinguishable provisioning events**~~: Unique Strings make each
   provisioning event unique.
3. ~~**Key persistence missing**~~: Keys are persisted to spec-defined handles.

**Remaining gap (credential reuse/rotation):** While the mechanisms for key
rotation exist (Unique String NV write → re-derive), the production code does
not implement HMAC key rotation during TO2 credential reuse. `Save()` re-writes
DCTPM/DCOV but does not rotate the HMAC Unique String.

**Spec gap (Unique String NV access for rotation):** The Unique String NV
indices are Profile B (`OWNERWRITE=0`, `PLATFORMCREATE=1`). Writing a new
Unique String to rotate a key requires either Platform auth or the NV
authValue -- neither of which is available to post-onboarding Owner-hierarchy
software. This is not a separate issue from the credential reuse problem
(gaps #7 and #10); it is the same underlying access restriction blocking the
rotation mechanism that the spec itself defines. The spec provides the rotation
concept but the NV protection model prevents its use post-onboarding.

---

## 4. NV Index Storage vs Disk File

### Spec Says

All FDO credentials SHALL be stored in TPM NV indices at standardized handles:

| Handle | Content | Profile |
|--------|---------|---------|
| `0x01D10000` | DCActive (1-byte flag) | A |
| `0x01D10001` | DCTPM (CBOR: ProtVer, DeviceInfo, GUID, RVInfo, PubKeyHash, DeviceKeyType, DeviceKeyHandle) | B |
| `0x01D10002` | DCOV (Ownership Voucher, optional) | C |
| `0x01D10003` | HMAC Unique String | B |
| `0x01D10004` | Device Key Unique String | B |
| `0x01D10005` | FDO Device Certificate (optional) | C |

### Implementation Does

**Production code** (`cred/tpm_store.go`): When the TPM build tag is active,
credential metadata is stored exclusively in TPM NV indices via `tpmStore.Save()`
and read back via `tpmStore.loadFromNV()`. No disk file is written. `Load()`
reads from NV only (file fallback has been removed). The `tpm/nv.go` module
provides all NV index management functions.

**Spec compliance tests and `tpm/nv.go`**: Define all NV index constants and
implement `ReadNVCredentials()`, `ReadDAKPublicKey()`, and
`ProveDAKPossession()`. These functions can read from NV indices and use
persisted keys. NV write/provisioning operations are in `tpm/nv.go` (production)
and exercised by both spec compliance tests and `cred/tpm_store.go`.

### Gap

**CLOSED.** The production code now uses the TPM as both a crypto engine and an
exclusive credential store when the TPM build tag is active. No disk file is
written — all credential data lives in TPM NV indices.

---

## 5. NV Index Attributes

### Spec Says (Table 9)

| Attribute | Profile A (DCActive) | Profile B (DCTPM, key U/S) | Profile C (DCOV, cert) |
|-----------|---------------------|---------------------------|----------------------|
| `OWNERWRITE` | 1 | **0** | 1 |
| `AUTHWRITE` | 1 | 1 | 1 |
| `OWNERREAD` | 1 | **0** | 1 |
| `AUTHREAD` | 1 | 1 | 1 |
| `PLATFORMCREATE` | 1 | 1 | 0 |
| `NO_DA` | 1 | 1 | 1 |

Key point: Profile B indices (the core credentials and key Unique Strings) have
`OWNERWRITE=0` and `OWNERREAD=0`, meaning the Owner hierarchy cannot
read or write them. Only authValue access is permitted.

### Implementation Does

**Production code** (`tpm/nv.go`): Implements all three NV attribute profiles
via `nvProfileAttrs()`:

```
Profile A: OWNERWRITE|AUTHWRITE|OWNERREAD|AUTHREAD|NO_DA|PLATFORMCREATE
Profile B: AUTHWRITE|AUTHREAD|NO_DA|PLATFORMCREATE
Profile C: OWNERWRITE|AUTHWRITE|OWNERREAD|AUTHREAD|NO_DA
```

`cred/tpm_store.go:NewDI()` uses these profiles when creating NV indices.

**Spec compliance tests** implement exactly the same attributes (verified in
Phase 5).

### Gap

The spec compliance tests faithfully implement the spec's attribute profiles.
The profiles themselves are the issue, as discussed in the proposed amendment:

- **Profile B's `OWNERWRITE=0` and `OWNERREAD=0`** prevent the Owner
  hierarchy from accessing core credentials. This blocks credential reuse by
  any post-onboarding software that operates under Owner hierarchy.

- **Profile B's `PLATFORMCREATE=1`** means these indices can only be deleted by
  Platform auth. This is correct for pre-onboarding protection but means a
  subsequent owner (who typically has Owner hierarchy, not Platform) cannot
  clean up FDO credentials.

**Spec gap:** The attribute profiles assume a rigid ROE model where only the
ROE (with authValue knowledge) accesses Profile B indices. Post-onboarding, the
Owner needs access. The proposed amendment recommends extending DCActive's
pattern (`OWNERWRITE=1`, `OWNERREAD=1`) to all credential indices, or making
profiles a policy choice.

---

## 6. Authorization Model

### Spec Says

- Keys: `userWithAuth=false`, access via policy session only
  - Policy: `PolicyNV(US index >= 0) AND PolicySecret(US index auth)`
- NV Profile A (DCActive): empty authValue, Owner hierarchy read/write
- NV Profile B (credentials): authValue-only access (empty or 32-byte ROE
  secret)
- NV Profile C (DCOV, cert): Owner hierarchy read/write

### Implementation Does

**Production code:**

- Keys (spec-compliant path): `userWithAuth=false`, accessed via
  `fdoKeyPolicy()` in `tpm/nv.go` which implements PolicyNV + PolicySecret
- Keys (legacy path): `userWithAuth=true`, accessed via HMAC session with empty password
- NV Profile A/C: read via Owner hierarchy (`nvReadOwner()`)
- NV Profile B: read via NV self-auth (`nvReadAuth()`)
- All auth values: empty (`tpm2.PasswordAuth(nil)`)

**Spec compliance tests and `tpm/nv.go`:**

- Keys: `userWithAuth=false`, accessed via `fdoKeyPolicy()` which implements
  the compound PolicyNV + PolicySecret session
- NV Profile A/C: read via Owner hierarchy (`nvReadOwner()`)
- NV Profile B: read via NV self-auth with empty password (`nvReadAuth()`)
- All auth values: empty (`tpm2.PasswordAuth(nil)`)

### Gap

The production code now implements the full policy-based auth model in the
spec-compliant path. When `cred/tpm_store.go` is used, all key operations go
through `LoadPersistentKey()` and `NewSpecHmac()`, which use `fdoKeyPolicy()`.

The `fdoKeyPolicy()` function in `tpm/nv.go` is production code that
correctly implements the spec's compound policy:

```go
func fdoKeyPolicy(usIndex uint32, usName tpm2.TPM2BName) tpm2.Session {
    return tpm2.Policy(tpm2.TPMAlgSHA256, 16, func(tpm transport.TPM, handle tpm2.TPMISHPolicy, _ tpm2.TPM2BNonce) error {
        // PolicyNV: US index value >= 0x00 (index must be populated)
        // PolicySecret: prove knowledge of US index authValue
    })
}
```

**Spec gap:** The policy model is functional but assumes the ROE can always
satisfy it. Post-onboarding, if the ROE is replaced by normal OS software, the
software needs the authValue to satisfy PolicySecret. If the authValue is empty
(locking ROE model) and the NV index is locked, the policy can still be
satisfied (PolicySecret checks auth knowledge, not data access). But the
software still cannot READ the credential NV data. This is the fundamental
conflict the proposed amendment addresses.

---

## 7. Device Initialization (DI) Flow

### Spec Says (section 6.1)

DI provisions all FDO credentials into TPM NV indices:

1. Set DCActive = True at `0x01D10000`
2. Write DCTPM structure to `0x01D10001`
3. Generate and write Device Key Unique String to `0x01D10004`
4. Create Device Key from template + Unique String, persist to `0x81020002`
5. Generate and write HMAC Unique String to `0x01D10003`
6. Create HMAC key from template + Unique String, persist to `0x81020003`
7. Compute HMAC over credentials for Ownership Voucher

### Implementation Does

**Production DI flow** (`cred/tpm_store.go:NewDI()`):

1. Clean up existing FDO state (`CleanupFDOState()`)
2. Generate random Unique Strings for DeviceKey and HMAC
3. Define + write DeviceKey_US NV (`0x01D10004`, Profile B)
4. Define + write HMAC_US NV (`0x01D10003`, Profile B)
5. Compute AuthPolicy via trial session (`ComputeFDOAuthPolicy()`)
6. Create ECC primary under Endorsement with Unique String + AuthPolicy (`GenerateSpecECKey()`)
7. Persist DAK to `0x81020002` via `PersistKey()`
8. Create HMAC primary under Endorsement with Unique String + AuthPolicy (`GenerateSpecHMACKey()`)
9. Persist HMAC key to `0x81020003` via `PersistKey()`
10. Define DCActive NV (`0x01D10000`, Profile A), set to `0x00`
11. Load persistent DAK via `LoadPersistentKey()` + spec HMACs via `NewSpecHmac()`
12. Return `hash.Hash` and `crypto.Signer` to the DI protocol
13. After DI, `Save()` writes DCTPM + DCOV + DCActive to NV (and file)

**Spec compliance test DI flow** (`spec_compliance_test.go`, Phase 6):

Same flow as production, exercised independently against the spec.

### Gap

The production DI flow now implements full spec-compliant provisioning with
NV indices, persistent keys, Unique Strings, and policy-based auth. The gap
between production and tests has been **closed**.

---

## 8. TO2 / Onboarding Credential Access

### Spec Says

During TO2, the ROE:

1. Reads DCActive from NV to determine if onboarding should proceed
2. Reads DCTPM from NV to get GUID, RVInfo, PubKeyHash
3. Uses Device Key (from persistent handle) to sign protocol messages via
   policy session
4. Uses HMAC key (from persistent handle) to compute HMAC via policy session
5. After successful TO2, updates DCTPM (new GUID, RVInfo, PubKeyHash), rotates
   HMAC Unique String

### Implementation Does

**Production TO2 flow** (`cred/tpm_store.go:Load()`):

1. Calls `loadFromNV()` first:
   a. Reads all NV indices via `ReadNVCredentials()`
   b. Verifies DCActive = `0x01`
   c. Verifies DAK and HMAC key persistent handles exist
   d. Decodes DCOV from NV to reconstruct `fdo.DeviceCredential`
2. Falls back to `loadFromFile()` if NV not provisioned (backward compat)
3. Loads persistent DAK via `LoadPersistentKey()` (policy session auth)
4. Loads spec-compliant HMAC via `NewSpecHmac()` (policy session auth)
5. Returns `crypto.Signer` and `hash.Hash` to the TO2 protocol
6. After TO2: `Save()` re-writes DCTPM/DCOV/DCActive to NV (and file)

**`tpm/nv.go` provides full NV-based TO2 support:**

- `ReadNVCredentials()`: reads all NV indices, checks persistent key presence
- `ReadDAKPublicKey()`: reads public key from persistent DAK handle
- `ProveDAKPossession()`: signs a nonce with the DAK using `fdoKeyPolicy()`
  policy session

### Gap

The production TO2 flow now reads from NV and uses persistent keys with
policy session auth. The read-side and write-side are both implemented.

**Remaining gap:** The `Save()` method handles credential updates after TO2
but does not rotate the HMAC Unique String (HMAC key rotation). This means
the same HMAC key is reused across onboarding cycles. The spec envisions
HMAC rotation on each successful TO2.

---

## 9. Credential Reuse

### Spec Says

After successful TO2, credentials are updated:

- New GUID, RVInfo, PubKeyHash written to DCTPM NV index
- New HMAC Unique String written (rotates HMAC key)
- New HMAC computed over new credentials
- Active may be set to False
- Device Key may optionally be rotated (new Unique String)

### Implementation Does

**Production code** (`examples/cmd/client.go`): If `AllowCredentialReuse: true`
and TO2 returns `nil` new credentials, the existing NV-stored credentials are
unchanged. On next boot, the same persistent keys are loaded from the TPM and
the same NV-based metadata is used. This is a "soft" credential reuse — the
credentials aren't actually updated in the TPM, they're just not overwritten.

**Spec compliance tests:** No TO2 credential update flow is tested. The tests
cover DI provisioning and credential reading but not the post-TO2 update cycle.

### Gap

There is no production or test implementation of credential reuse as the spec
defines it (NV index updates, HMAC rotation, key rotation). The production
approach of "don't change the NV indices" works for the simple case but does not
provide the cryptographic credential rotation the spec envisions.

**Spec gap (critical):** As detailed in the proposed amendment, the spec's own
protection model (Profile B: `OWNERWRITE=0`, `PLATFORMCREATE=1`) makes
credential reuse impractical. An entity performing credential reuse needs to
write to Profile B NV indices, which requires either Platform auth (typically
not available post-manufacturing) or the NV index authValue (which may not be
available to post-onboarding software). The spec creates the requirement for
credential reuse but blocks the mechanism to achieve it.

---

## 10. IDevID / LDevID Support

### Spec Says

- `DeviceKeyType` enum: 0 = FDO key, 1 = IDevID, 2 = LDevID
- IDevID or LDevID MAY be used instead of the FDO-specific Device Key
- IDevID management follows TCG DevID spec, outside this spec's scope
- If IDevID/LDevID is used, `DeviceKeyHandle` in DCTPM points to that key

### Implementation Does

**Constants defined** (`tpm/credential.go`):

```go
const (
    FdoDeviceKey    DeviceKeyType = 0  // FDO key derived from Unique String
    IDevIDDeviceKey DeviceKeyType = 1  // IDevID in the TPM
    LDevIDDeviceKey DeviceKeyType = 2  // LDevID in the TPM
)
```

**No code path uses IDevID or LDevID.** The enum values exist and are validated
in spec compliance tests (Phase 1/2), but there is no function to discover,
load, or use an existing IDevID or LDevID key for FDO operations.

### Gap

The implementation has the data model for IDevID/LDevID but no operational
support. There is no key preference order (DAK > LDevID > IDevID) as proposed
in the amendment. All production FDO operations create a new FDO-specific key
(`DeviceKeyType = 0`).

---

## 11. DCTPM CBOR Structure

### Spec Says (section 4.5)

```cddl
DCTPM = [
    DCProtVer:      protver,
    DCDeviceInfo:   tstr,
    DCGuid:         Guid,
    DCRVInfo:       RendezvousInfo,
    DCPubKeyHash:   Hash,
    DeviceKeyType:  uint,
    DeviceKeyHandle: uint
]
```

Minimum size: 384 bytes. Recommended: 512 bytes.

### Implementation Does

**`tpm/credential.go`** defines `DeviceKeyType` constants (0=FDO, 1=IDevID,
2=LDevID) used by the DCTPM structure. The `tpm.DeviceCredential` struct that
previously represented the full DCTPM layout has been removed — it was dead
code superseded by the NV flow.

**`cred/tpm_store.go`** stores DCTPM fields across two NV indices:

- `DCTPM` (0x01D10001): GUID + DeviceInfo (compact binary)
- `DCOV` (0x01D10002): Version, RVInfo, PublicKeyHash, KeyType (CBOR via `dcovNVData`)

```go
type dcovNVData struct {
    Version       uint16
    RvInfo        [][]protocol.RvInstruction
    PublicKeyHash protocol.Hash
    KeyType       protocol.KeyType
}
```

**Spec compliance tests** (Phase 2-4) validate CBOR encode/decode round-trip
and verify the structure matches what the spec prescribes.

### Gap

The data structure is spec-compliant. The gap is that it is only
populated/used in tests, not in production DI/TO2 flows.

---

## 12. Handle Values

### Spec Says

All handle values are **placeholders for testing only:**

> *"The values presented are appropriate for testing, but not for released
> products."*

Expected allocation: TCG delegates `0x01D10000`-`0x01D100FF` to FIDO. FIDO
has not yet developed governance for this range.

### Implementation Does

Uses the same placeholder values:

- NV: `0x01D10000` - `0x01D10005`
- Persistent objects: `0x81020002` - `0x81020003`

### Gap

Both the spec and implementation use unassigned test values. This is a known
blocker for production deployment, tracked in the proposed amendment's open
questions.

---

## 13. "FDO Device Certificate" NV Index (`0x01D10005`)

### Spec Says

NV index `0x01D10005` (Profile C) is reserved for the "FDO Device Certificate,"
described as an optional X.509 certificate associated with the FDO Device Key.

### The Problem

The spec's characterization of this index as an "X.509 certificate" is
misleading and impractical for several reasons:

1. **The Ownership Voucher is not an X.509 certificate.** The FDO credential
   that proves device-to-owner binding is the Ownership Voucher (OV). The OV
   is a CBOR-encoded, FDO-specific data structure — not an X.509 certificate.
   There is no standardized DER/PEM encoding, no ASN.1 schema, and no
   interoperability with existing X.509 tooling. Calling it a "certificate"
   implies a normalized format that does not exist.

2. **Size exceeds practical TPM NV limits.** An Ownership Voucher includes the
   device certificate chain, manufacturer info, rendezvous directives, and the
   owner's public key — routinely exceeding 1 KB. Many TPMs (especially older
   or resource-constrained models) have NV storage budgets of ~700 bytes per
   index or limited total NV capacity. Storing the OV in TPM NV is impractical
   on a significant portion of the installed TPM base.

3. **The data is not a secret.** The Ownership Voucher does not contain any
   secret material. It is a signed assertion of ownership that can be freely
   distributed. Storing it in the TPM provides integrity protection, but the
   same integrity guarantee is already achieved by the OV's cryptographic
   signature chain. TPM NV storage adds cost (space, complexity, provisioning
   time) without a corresponding security benefit.

4. **The information is recoverable.** If a device needs to know who its owner
   is (for internal self-re-attestation), it can re-run TO2 at any time to
   re-obtain the Ownership Voucher. The owner service always has the
   authoritative copy. For cases where local caching is desired, the OV can be
   stored on whatever media is available (filesystem, flash partition, etc.)
   without compromising the TPM's security guarantees for actual secrets
   (device key, HMAC key, unique strings).

### Implementation Decision

**Not implemented.** This is classified as a **spec gap**, not an
implementation gap. The NV index constant (`FDOCertIndex = 0x01D10005`) is
defined for completeness and is exercised in spec compliance tests (Profile C
attribute validation, define/write/read round-trip), but the production code
does not provision or use this index.

### Recommendation for Spec Amendment

The spec should either:

- **Remove** the `0x01D10005` index entirely, acknowledging that the OV is not
  suitable for TPM NV storage and is not security-sensitive.
- **Redefine** it as truly optional with clear guidance that it is for the
  device's X.509 certificate (if one exists via IDevID/LDevID), not the
  Ownership Voucher — and note the size constraints that make this impractical
  on many TPMs.
- **Clarify** that implementations MAY store ownership proof on non-TPM media
  without violating the spec's security model, since the OV is not secret
  material.

---

## Summary: Deviation Map

| # | Area | Spec Requirement | Production Code | Spec Tests | Gap Location | Status |
|---|------|-----------------|-----------------|------------|--------------|--------|
| 1 | Key hierarchy | Endorsement (SHALL) | Endorsement | Endorsement | Spec (ownership mismatch) | Unchanged |
| 2 | `userWithAuth` | false | **false** (spec path) / true (legacy) | false | ~~Implementation~~ Spec (policy model impractical post-onboarding) | **CLOSED** (spec path) |
| 3 | AuthPolicy | PolicyNV+PolicySecret | **Implemented** via `ComputeFDOAuthPolicy()` | Implemented | ~~Implementation~~ Spec (same as #2) | **CLOSED** |
| 4 | Unique Strings | From NV index | **Implemented** — `NewDI()` provisions NV + passes to key creation | Implemented | ~~Implementation~~ | **CLOSED** |
| 5 | Key persistence | SHOULD persist | **Persisted** to `0x81020002`/`0x81020003` | Persisted | ~~Implementation~~ | **CLOSED** |
| 5a | Key rotation via U/S NV write | Profile B (`OWNERWRITE=0`) | Mechanism exists, not exercised post-TO2 | Tested | Spec (same access issue as #7/#10) | Partially closed |
| 6 | Credential storage | TPM NV indices | **NV indices only** (no disk file) | NV indices | ~~Implementation~~ | **CLOSED** |
| 7 | NV Profile B access | authValue only (`OWNERWRITE=0`) | Matches spec | Matches spec | Spec (blocks credential reuse) | Unchanged |
| 8 | DI flow | Full NV provisioning | **Full NV provisioning** via `tpmStore.NewDI()` | Full NV provisioning | ~~Implementation~~ | **CLOSED** |
| 9 | TO2 credential update | NV writes + HMAC rotation | NV writes via `Save()`, **no HMAC rotation** | Not tested | Implementation + Spec | Partially closed |
| 10 | Credential reuse | NV updates | NV updates via `Save()`, no key rotation | Not implemented | Both (spec blocks its own mechanism) | Partially closed |
| 11 | IDevID/LDevID | Enum + discovery | Enum only, no discovery | Enum validation | Implementation | Unchanged |
| 12 | Key preference order | Not defined | Not implemented | Not tested | Spec (proposed in amendment) | Unchanged |
| 13 | Handle values | Placeholder (testing only) | Same placeholders | Same placeholders | Spec (TCG/FIDO allocation needed) | Unchanged |
| 14 | DCTPM structure | CBOR, 512 bytes recommended | **Used in production** by `tpmStore.Save()`/`loadFromNV()` | Full encode/decode | ~~Implementation~~ | **CLOSED** |
| 15 | "FDO Certificate" NV | X.509 cert at `0x01D10005` (optional) | Not implemented | Profile C tests only | **Spec** (OV is not X.509; size impractical; not secret) | **Spec gap** |

### Deviations That Highlight Spec Issues

Gaps 1, 2, 3, 7, 9, 10, 12, and 15 are cases where the implementation's
deviation from the spec is either: (a) a pragmatic response to the spec's
impractical requirements, or (b) an area where the spec does not provide
sufficient guidance.

These gaps directly inform the proposed amendment:

- **Hierarchy mandate** (#1): spec should allow Platform hierarchy for OEM
  provisioning
- **Policy/auth model** (#2, #3, #7): spec should make the strict ROE policy a
  recommended profile, not mandatory, and allow Owner hierarchy access
  post-onboarding
- **Credential reuse** (#9, #10): spec creates the requirement but blocks the
  mechanism
- **Key preference order** (#12): spec should define DAK > LDevID > IDevID
  discovery priority
- **"FDO Certificate" NV index** (#15): spec defines an NV index for a
  "certificate" that is actually an Ownership Voucher — not X.509, not
  normalized, too large for many TPMs, not secret, and recoverable via TO2
