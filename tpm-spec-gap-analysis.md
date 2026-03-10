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
- **Production code** (`tpm/key.go`, `tpm/hmac.go`, `cred/tpm_store.go`): the
  library used by the FDO client/server
- **Spec compliance tests** (`tpm/spec_compliance_test.go`, `tpm/nv.go`): test
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
| NV index creation (`NV_DefineSpace`) | Not implemented | Platform (Profile A/B), Owner (Profile C) |
| Key persistence (`EvictControl`) | Not implemented | Owner |
| NV read (Profile A/C) | Not implemented | Owner |
| NV read (Profile B) | Not implemented | NV self-auth (empty authValue) |

### Gap

**Production code matches the spec for key creation hierarchy** (Endorsement).
However, there is no production code for NV index creation at all -- NV
operations exist only in the spec compliance tests.

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

| Attribute | Spec | Production | Match? |
|-----------|------|------------|--------|
| `fixedTPM` | true | true | Yes |
| `fixedParent` | true | true | Yes |
| `sensitiveDataOrigin` | true | true | Yes |
| `userWithAuth` | **false** | **true** | **NO** |
| `sign` / `signEncrypt` | true | true | Yes |
| `decrypt` | false | false (not set) | Yes |
| `restricted` | false | false (not set) | Yes |
| AuthPolicy | PolicyNV + PolicySecret digest | **empty** | **NO** |
| Unique field | From NV Unique String | **empty** | **NO** |

**Spec compliance tests** (`tpm/spec_compliance_test.go`):

| Attribute | Spec | Test Code | Match? |
|-----------|------|-----------|--------|
| `userWithAuth` | false | false | Yes |
| AuthPolicy | PolicyNV + PolicySecret | Computed via trial session | Yes |
| Unique field | From NV Unique String | From NV index content | Yes |

### Gap

Three related deviations in production code:

1. **`userWithAuth = true`**: Production keys can be used with simple password
   auth. The spec requires `userWithAuth = false` so that keys can only be used
   via the compound policy session (PolicyNV + PolicySecret). This is the most
   significant security difference -- it means any process with TPM access can
   use the keys without satisfying a policy.

2. **No AuthPolicy**: Without a policy digest in the key template, there is no
   mechanism to restrict key usage to entities that can prove knowledge of the
   Unique String NV index auth.

3. **No Unique String**: Without a Unique String in the template, the key is
   derived solely from the hierarchy seed + template. This means: (a) the key
   cannot be rotated without changing the template, and (b) the key does not
   survive `TPM2_Clear` in a distinguishable way (any entity with Endorsement
   access and the same template gets the same key).

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

**Production code:** Keys are created as **transient** primary objects via
`CreatePrimary` on every use, with **no Unique String**. The derivation is just
`EPS + Template`, which is deterministic -- same key every time. Keys are never
persisted to handles; they are flushed after each operation.

**Spec compliance tests:** Keys are created with Unique Strings from NV indices
and persisted to `0x81020002` (DAK) and `0x81020003` (HMAC) via `EvictControl`.

### Gap

**IMPLEMENTATION MISS -- MUST FIX: Unique Strings.** The production code does
not use Unique Strings at all. This is a critical gap that must be addressed.
Without Unique Strings:

- **Key rotation is impossible.** You always derive the same key from
  `EPS + Template`. There is no mechanism to produce a different key without
  changing the template itself.
- **Credential reuse cannot update the HMAC key.** The FDO TO2 protocol
  expects the HMAC secret to be rotated on each successful onboarding. Without
  a Unique String in an NV index, there is nothing to update.
- **No distinguishable provisioning events.** Without a Unique String, any
  entity with Endorsement access and the same template derives the identical
  key. There is no way to prove that a specific key was provisioned at a
  specific time by a specific entity.

The spec's Unique String mechanism is sound and must be adopted in production.
The Unique Strings are stored in specific NV indices: `0x01D10003` (HMAC
Unique String) and `0x01D10004` (Device Key Unique String). These are read from
NV and fed into the `CreatePrimary` template's `Unique` field (Table 10 in the
spec). The production key creation code (`tpm/key.go:newPrimaryKey()` and
`tpm/hmac.go:init()`) must be updated to accept and use Unique Strings, and
the DI flow must provision these NV indices.

**IMPLEMENTATION MISS -- SHOULD FIX: Key Persistence.** The production code
does not persist keys to handles. This works because `CreatePrimary` is
deterministic, but it means every FDO operation requires Endorsement hierarchy
access. If Endorsement auth is set by a downstream entity, the production code
cannot recreate keys. The spec's recommendation to persist is a reasonable
safety net and should be implemented.

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

**Production code** (`cred/tpm_store.go`): Credential metadata (key type,
algorithm selection) is written to a **disk file** (`cred.bin`). No NV indices
are written during DI or read during TO2 in production. The TPM is used only
for cryptographic operations (signing, HMAC), not for credential storage.

**Spec compliance tests and `tpm/nv.go`**: Define all NV index constants and
implement `ReadNVCredentials()`, `ReadDAKPublicKey()`, and
`ProveDAKPossession()`. These functions can read from NV indices and use
persisted keys. NV write/provisioning operations exist only in the test code.

### Gap

This is the largest structural deviation. The production implementation treats
the TPM as a **crypto accelerator** (sign and HMAC operations) while storing
credential metadata on disk. The spec treats the TPM as both a crypto engine
and a **credential store**.

**Spec relevance:** The standardized NV index locations are valuable regardless
of the protection policy debate. They allow any FDO software on any OS to
discover whether FDO credentials exist and what state they're in. The
implementation should move toward NV-based credential storage. The NV index
constants and read functions in `tpm/nv.go` are a partial bridge toward this.

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

**Spec compliance tests** implement exactly the spec's attributes:
```
Profile A: OWNERWRITE|AUTHWRITE|OWNERREAD|AUTHREAD|NO_DA|PLATFORMCREATE
Profile B: AUTHWRITE|AUTHREAD|NO_DA|PLATFORMCREATE
Profile C: OWNERWRITE|AUTHWRITE|OWNERREAD|AUTHREAD|NO_DA
```

**Production code:** No NV index creation exists in production, so no
attributes are set.

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
- Keys: `userWithAuth=true`, accessed via HMAC session with empty password
- No NV auth model (no NV indices in production)

**Spec compliance tests and `tpm/nv.go`:**
- Keys: `userWithAuth=false`, accessed via `fdoKeyPolicy()` which implements
  the compound PolicyNV + PolicySecret session
- NV Profile A/C: read via Owner hierarchy (`nvReadOwner()`)
- NV Profile B: read via NV self-auth with empty password (`nvReadAuth()`)
- All auth values: empty (`tpm2.PasswordAuth(nil)`)

### Gap

The spec compliance tests implement the full policy-based auth model. Production
code uses the simplest possible auth (password with `userWithAuth=true`).

The `fdoKeyPolicy()` function in `tpm/nv.go` is production-ready code that
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
1. Create transient HMAC keys (SHA-256 and SHA-384) via `tpm.NewHmac()`
2. Generate transient device key via `tpm.GenerateECKey()` (or RSA variant)
3. Return `hash.Hash` and `crypto.Signer` to the DI protocol
4. After DI completes, `Save()` writes key type metadata to disk file

**Spec compliance test DI flow** (`spec_compliance_test.go`, Phase 6):
1. Generate GUID
2. Write DCActive to NV `0x01D10000` (Profile A, Platform hierarchy)
3. Write DCTPM to NV `0x01D10001` (Profile B, Platform hierarchy)
4. Generate Device Key Unique String, write to NV `0x01D10004`
5. Compute AuthPolicy via trial session
6. Create ECC primary under Endorsement with Unique String + AuthPolicy
7. Persist DAK to `0x81020002` via `EvictControl` (Owner hierarchy)
8. Generate HMAC Unique String, write to NV `0x01D10003`
9. Create HMAC key under Endorsement with Unique String + AuthPolicy
10. Persist HMAC key to `0x81020003`
11. Compute HMAC baseline, write DCOV to NV `0x01D10002`

### Gap

The production DI flow is a minimal "TPM as crypto accelerator" approach. It
creates the cryptographic keys in the TPM (correct algorithms, correct
hierarchy) but does not provision NV indices, persist keys, use Unique Strings,
or set policy-based auth. Credential metadata goes to disk.

The spec compliance tests implement the full spec-compliant DI flow. The gap
between production and tests represents the work needed to move credential
storage into the TPM.

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
1. Reads credential metadata from **disk file**
2. Recreates transient HMAC keys via `tpm.NewHmac()`
3. Recreates transient device key via `tpm.GenerateECKey()`
4. Returns `crypto.Signer` and `hash.Hash` to the TO2 protocol
5. Protocol uses key for signing and HMAC for credential verification
6. After TO2: if credential reuse, disk file unchanged; if new credentials,
   disk file rewritten

**`tpm/nv.go` provides partial NV-based TO2 support:**
- `ReadNVCredentials()`: reads all NV indices, checks persistent key presence
- `ReadDAKPublicKey()`: reads public key from persistent DAK handle
- `ProveDAKPossession()`: signs a nonce with the DAK using `fdoKeyPolicy()`
  policy session

### Gap

The production TO2 flow bypasses NV storage entirely. The `tpm/nv.go` functions
provide a read-side bridge but there is no production write path for updating
credentials after TO2 (no `UpdateCredential()` or equivalent).

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
and TO2 returns `nil` new credentials, the existing disk file is unchanged. On
next boot, the same transient keys are recreated from the TPM seed and the same
disk-based metadata is used. This is a "soft" credential reuse -- the
credentials aren't actually updated in the TPM, they're just not changed on
disk.

**Spec compliance tests:** No TO2 credential update flow is tested. The tests
cover DI provisioning and credential reading but not the post-TO2 update cycle.

### Gap

There is no production or test implementation of credential reuse as the spec
defines it (NV index updates, HMAC rotation, key rotation). The production
approach of "don't change the disk file" works for the simple case but does not
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

**`tpm/credential.go`** defines:
```go
type Credential struct {
    Version       uint16
    DeviceInfo    string
    GUID          fdo.GUID
    RVInfo        [][]fdo.RvInstruction
    PubKeyHash    fdo.Hash
    DeviceKeyType DeviceKeyType
    KeyHandle     uint32
}
```

This structure matches the spec's DCTPM fields. CBOR marshaling is implemented
via `fdo.cbor` tags.

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

## Summary: Deviation Map

| # | Area | Spec Requirement | Production Code | Spec Tests | Gap Location |
|---|------|-----------------|-----------------|------------|--------------|
| 1 | Key hierarchy | Endorsement (SHALL) | Endorsement | Endorsement | Spec (ownership mismatch) |
| 2 | `userWithAuth` | false | **true** | false | Implementation + Spec (policy model impractical post-onboarding) |
| 3 | AuthPolicy | PolicyNV+PolicySecret | **none** | Implemented | Implementation + Spec (same as #2) |
| 4 | Unique Strings | From NV index | **none** | Implemented | **MUST FIX in implementation** (spec's approach is correct; without this, no key rotation, no HMAC rotation, no credential reuse) |
| 5 | Key persistence | SHOULD persist | **transient** | Persisted | SHOULD FIX in implementation (safety net against Endorsement auth changes) |
| 5a | Key rotation via U/S NV write | Profile B (`OWNERWRITE=0`) | N/A | Tested | Spec (same access issue as #7/#10) |
| 6 | Credential storage | TPM NV indices | **disk file** | NV indices | Implementation |
| 7 | NV Profile B access | authValue only (`OWNERWRITE=0`) | N/A | Matches spec | Spec (blocks credential reuse) |
| 8 | DI flow | Full NV provisioning | Crypto-only, disk metadata | Full NV provisioning | Implementation |
| 9 | TO2 credential update | NV writes + HMAC rotation | Disk file unchanged | Not tested | Implementation + Spec |
| 10 | Credential reuse | NV updates | Disk no-op | Not implemented | Both (spec blocks its own mechanism) |
| 11 | IDevID/LDevID | Enum + discovery | Enum only, no discovery | Enum validation | Implementation |
| 12 | Key preference order | Not defined | Not implemented | Not tested | Spec (proposed in amendment) |
| 13 | Handle values | Placeholder (testing only) | Same placeholders | Same placeholders | Spec (TCG/FIDO allocation needed) |
| 14 | DCTPM structure | CBOR, 512 bytes recommended | Struct defined, not used in prod | Full encode/decode | Implementation |

### Deviations That Highlight Spec Issues

Gaps 1, 2, 3, 7, 9, 10, and 12 are cases where the implementation's deviation
from the spec is either: (a) a pragmatic response to the spec's impractical
requirements, or (b) an area where the spec does not provide sufficient
guidance.

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
