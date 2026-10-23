# COSE_Sign1 Domain Separation via external_aad

**Status:** Draft / Proposed for FDO 2.0
**Date:** 2026-03-18
**Related:** `di-factory-authentication-and-tpm.md`, `fdo-appnote-voucher-transfer.bs`,
RFC 9052 (COSE Structures), RFC 9528 (EDHOC)

## 1. The Problem: HSMs, COSE, and "Know What You Sign"

> **A COSE_Sign1 payload is opaque bytes. There is no definitive way for a
> signer to know what it is signing, or to distinguish it from anything else
> that signature could be misconstrued to mean.** A permanent transfer of
> device ownership is indistinguishable from an ephemeral session nonce. A
> factory attestation is indistinguishable from a voucher chain entry. Without
> `external_aad`, the signer has no mechanism -- at the COSE layer -- to
> declare what it intended, and the verifier has no mechanism to confirm it.

### 1.1 Why HSMs Only Want to Sign X.509

Hardware Security Modules are designed around a central tenet: **know exactly
what you are signing before you sign it.** An HSM is not a dumb signing
oracle. It is a policy-enforced signer that understands the structure of what
it signs and can be configured to restrict what it is *willing* to sign.

X.509 certificates are the canonical example of this philosophy done right.
The X.509 structure is rigidly defined -- every field has a specified meaning,
a specified encoding, and a specified interpretation. An HSM that signs an
X.509 certificate can inspect every field, understand what the resulting
certificate will authorize, and enforce policy: "sign only certificates with
subjects matching these patterns, containing only these extensions, with these
specific OID values." The HSM *understands* what the signature means.

The X.509 `CRITICAL` flag is the purest expression of this principle. An
extension marked CRITICAL means: **do not sign this certificate unless you
understand this extension and are explicitly granting what it requests.** If
the HSM encounters a CRITICAL extension it doesn't recognize, it refuses to
sign. This is deliberate -- it prevents the HSM from blindly vouching for
semantics it cannot evaluate.

Many high-security HSMs take this further: they *only* sign X.509
certificates. Full stop. Not arbitrary hashes, not opaque blobs, not
"whatever the application hands them." This is a feature, not a limitation --
it ensures the HSM can never be used as a signing oracle by an application
that has been compromised or misconfigured.

### 1.2 Why COSE Breaks This Model

COSE_Sign1 asks the HSM to sign an opaque CBOR payload. From the HSM's
perspective, the payload is just bytes. The HSM cannot inspect it, cannot
understand what the signature will authorize, and cannot enforce policy about
what it is willing to sign.

FDO makes this worse. The same key is used to produce COSE_Sign1 signatures
in many different protocol contexts -- voucher extension, TO2 ownership
proofs, rendezvous registration, challenge-response authentication, firmware
metadata, and (proposed) DI factory attestation. Each of these has radically
different security implications:

- **OVEntry (voucher extension):** Transfers device ownership to a new party.
  This signature is permanent, stored in the voucher, and verified repeatedly
  over the device's lifetime.
- **TO2.ProveOVHdr:** Proves to a device that you possess the owner private
  key. Ephemeral, session-bound.
- **FDOKeyAuth.Prove:** Proves key ownership to a voucher transfer API.
  Ephemeral, session-bound.
- **DI.MfgAttest (proposed):** Attests that the factory possesses the
  manufacturer private key. Permanent.

An HSM configured to "sign COSE_Sign1 payloads with this key" has no way to
distinguish these. It cannot say "allow this key to sign OVEntries but not
TO2 proofs" or "allow challenge-response signatures but not voucher
extensions." Every COSE_Sign1 looks the same at the signing layer: opaque
payload bytes, protected headers, empty external data.

To make an HSM enforce per-operation policy today, you would need to embed
FDO-specific CBOR parsing logic into the HSM itself -- decode the payload,
determine whether it's an OVEntry or a TO2.ProveOVHdr or an FDOKeyAuth.Prove
based on CBOR array structure (4 elements vs. 8 elements vs. 5 elements
starting with a text string), and apply policy accordingly. This is fragile,
protocol-version-dependent, and far beyond what any general-purpose HSM
supports.

### 1.3 What We Need

A fundamental, high-level mechanism that allows any signer -- HSM or
otherwise -- to:

1. **Tell one operation from another.** Before signing, the signer must know
   unambiguously which protocol operation this signature is for.
2. **Scope what it is willing to sign.** An administrator must be able to
   configure: "this key may produce OVEntry signatures and DI attestation
   signatures, but not TO2 proofs or FDOKeyAuth signatures."

This mechanism must be:

- **Simple:** A fixed tag, not a CBOR structure that requires protocol-
  specific parsing.
- **External to the payload:** The signer should not need to decode the
  payload to determine what it is. The context must be provided alongside
  the payload, not buried inside it.
- **Cryptographically bound:** The tag must be included in the signing input,
  not just checked by application logic. A signature produced without the
  correct tag must be invalid.

COSE_Sign1 already provides exactly this mechanism: **`external_aad`**.

## 2. Background: What external_aad Is

RFC 9052 Section 4.3 defines "Externally Supplied Data" for COSE structures.
The `external_aad` field is included in the Sig_structure that gets hashed
before signing, but is **not carried** in the COSE_Sign1 output:

```
Sig_structure = [
    context:        "Signature1",
    body_protected:  empty_or_serialized_map,
    external_aad:    bstr,              ;; <-- THIS FIELD
    payload:         bstr
]
```

Both signer and verifier must agree on `external_aad` out-of-band -- that is,
it is implied by the protocol context. If the verifier supplies a different
tag than the signer used, verification fails. This makes it ideal for domain
separation: the verifier knows which context it expects, supplies the matching
tag, and any signature produced in a different context is rejected.

RFC 9052 Section 4.3 explicitly states that applications using this feature
"need to define how the externally supplied authenticated data is to be
constructed."

### 2.1 How Other Protocols Use external_aad

**EDHOC (RFC 9528)** is the gold standard for COSE domain separation. Every
COSE_Sign1 and COSE_Encrypt0 operation uses context-specific external_aad:

| EDHOC Operation | external_aad |
|-----------------|-------------|
| Message 2 signature (Responder) | `<< TH_2, CRED_R, ? EAD_2 >>` |
| Message 3 signature (Initiator) | `<< TH_3, CRED_I, ? EAD_3 >>` |
| Message 3 encryption | `TH_3` |
| Message 4 encryption | `TH_4` |

EDHOC's approach binds each signature to the full transcript hash (`TH_n`)
and the signer's credential (`CRED_x`). This makes it cryptographically
impossible for a Message 2 signature to verify as a Message 3 signature, even
if the same key were used in both. The RFC explicitly constructs these as
CBOR-encoded arrays to avoid ambiguity.

**WebAuthn/FIDO2** doesn't use COSE_Sign1 for assertions directly, but its
signing format is instructive -- both for what it gets right and for where
it falls short. This matters because WebAuthn and FDO are both FIDO Alliance
specifications. The same organization that designed WebAuthn's domain
separation chose not to apply the same rigor to FDO's use of COSE_Sign1.

Every WebAuthn assertion signature covers `authenticatorData || clientDataHash`.
Two mechanisms provide domain separation:

1. **`rpIdHash`** -- the first 32 bytes of `authenticatorData` are the
   SHA-256 of the Relying Party identifier. A signature produced for
   `example.com` will never verify for `evil.com`, because the verifier
   independently computes the rpIdHash and the hash won't match. This
   disambiguates one relying party from another.

2. **`clientDataJSON.type`** -- the `type` field in the client data is a
   string, either `"webauthn.create"` (registration) or `"webauthn.get"`
   (authentication). This string is included in `clientDataHash`, which is
   part of the signed data. A registration signature can never be replayed
   as an authentication signature, because the `type` value differs and the
   hash changes. **This is directly analogous to our proposal** -- a fixed
   string tag that distinguishes ceremony types, included in the signing
   input, independently reconstructed by the verifier.

Both mechanisms illustrate the right instinct but share a fundamental flaw:
**they only work if the other protocol knows to look for them.**

`clientDataJSON.type` disambiguates `"webauthn.create"` from `"webauthn.get"`
-- but only because both sides of a WebAuthn ceremony know the payload is
JSON, know to parse it, and know to check the `type` field. A completely
different protocol that receives the same signed bytes has no idea the payload
is JSON at all. It sees opaque bytes, and if those bytes happen to decode as
a valid message in its own format, the signature verifies. The `type` field
is a semantic defense inside the payload, not a structural defense in the
signing input. It prevents confusion within WebAuthn, but provides zero
protection against a different protocol that doesn't understand WebAuthn's
payload format.

`rpIdHash` has the same problem at a different level. It disambiguates one
relying party from another -- but it does **not** disambiguate across
protocols. The signed data is `authenticatorData || clientDataHash`, which
is just bytes. If some other protocol also expects a signature over a byte
string whose first 32 bytes happen to be a SHA-256 hash, an authenticator
signature could theoretically verify in that other context. The rpIdHash is
not a protocol-level domain tag; it is a relying-party-level domain tag. A
signature over `[32-byte-hash || other-data]` looks the same whether it came
from WebAuthn or from a hypothetical protocol that also signs
`[32-byte-hash || payload]`.

This is the fundamental danger of signing oracles: **the attacker's protocol
doesn't need to understand your protocol's formatting.** It just needs
overlapping byte patterns. A signing oracle attack doesn't replay a "WebAuthn
assertion" or an "FDO voucher entry" -- it replays *bytes that happen to be
valid in both contexts*. Payload-level type tags, JSON fields, and
application-specific structures all fail against this because the attacking
protocol doesn't parse them -- it just sees bytes that verify.

Without a deterministic, protocol-level mechanism that is always present in
the signing input regardless of payload content, there is no security proof
against cross-protocol confusion. Frankly, WebAuthn has this gap too -- it
is mitigated in practice only because authenticator keys are tightly scoped
(bound to a specific credential and relying party, generated on the
authenticator, never exported or shared with other protocols). FDO does not
have this luxury -- FDO keys are used across multiple protocol phases (TO0,
TO1, TO2, voucher extension, FDOKeyAuth) and may be used by HSMs that also
sign in other COSE-based contexts.

**OSCORE (RFC 8613)** uses COSE_Encrypt0 with external_aad containing the
CoAP request/response context (OSCORE option, partial IV, etc.), binding each
encrypted message to its specific CoAP context.

**CWT (RFC 8392)** and **SUIT (RFC 9019/9124)** rely on implicit domain
separation via distinct payload structures rather than explicit external_aad.
This is the same strategy FDO currently uses -- and as we show below, it has
gaps.

### 2.2 The Spectrum of Domain Separation

Protocols protect against signing oracle attacks at different layers:

| Layer | Mechanism | Strength | FDO Status |
|-------|-----------|----------|------------|
| **COSE Sig_structure** | `external_aad` tag | Cryptographic -- different signing inputs | **Missing everywhere** |
| **Payload structure** | Different CBOR shapes, TypeTags | Structural -- CBOR decoder rejects mismatches | Partial (FDOKeyAuth only) |
| **Nonce binding** | Fresh per-session nonce in payload | Temporal -- signature tied to specific session | Most ephemeral operations |
| **Verification context** | Application logic checks | Procedural -- code checks expected fields | Present but fragile |

Best practice (per EDHOC) is defense at all layers. FDO currently relies only
on the bottom three, missing the strongest one.

### 2.3 external_aad as the HSM Policy Hook

Returning to the HSM problem from Section 1: `external_aad` is precisely
what an HSM needs to enforce per-operation signing policy without understanding
CBOR or FDO protocol internals. The signing request to the HSM becomes:

> "Sign this payload with key K, in the context `FDO-OVEntry-v1`."

The HSM doesn't need to decode the payload. It just needs to check: "Is key K
authorized to sign in context `FDO-OVEntry-v1`?" This is a simple string
comparison against a policy table -- the same kind of policy check HSMs
already do for X.509 (key usage, subject constraints, extension OIDs).

An HSM configured with:

```
Key K1: allowed contexts = ["FDO-OVEntry-v1", "FDO-DI-MfgAttest-v1"]
Key K2: allowed contexts = ["FDO-TO2-ProveOVHdr-v1", "FDO-TO2-SetupDevice-v1"]
```

...can enforce that a voucher extension key is never used for TO2 session
proofs, and a session key is never used for permanent voucher signatures --
without any knowledge of CBOR, COSE payload structures, or FDO protocol
semantics. The `external_aad` tag is the operation's identity, visible to
the signer before it signs, and cryptographically bound to the output.

This is not hypothetical. HSM vendors are increasingly adding COSE support,
and the first question they ask is: "How do we know what we're signing?" The
answer, today, is: "You don't." With external_aad, the answer becomes: "The
tag tells you."

## 3. Current State: Comprehensive Audit

An audit of every COSE_Sign1 call site in the go-fdo codebase confirms that
**all signing and verification operations pass `nil` / empty `external_aad`**.
The COSE implementation (`cose/sign.go`) correctly supports external_aad in
its Sig_structure -- the infrastructure is present, but no caller uses it.

The following table catalogs every operation, including what is signed, who
signs and verifies, and whether the signature is ephemeral (session-bound) or
long-lived (stored in an artifact).

### 3.1 Owner Key Operations

The owner key is used in four different protocol contexts. This is the highest
risk area because the same key signs payloads with fundamentally different
purposes and lifetimes.

| Operation | Msg Type | Payload (CBOR) | Purpose | Lifetime | Nonce? | external_aad |
|-----------|----------|----------------|---------|----------|--------|-------------|
| **TO0.OwnerSign** | 22 | `To1d = [RvAddrs, To0dHash]` (2-element array) | Owner registers RV blob with rendezvous server | Medium (hours/days -- stored at RV) | Indirect (To0dHash covers NonceTO0Sign) | nil |
| **TO2.ProveOVHdr** | 60/61 | `ovhProof = [OVH, NumEntries, HMAC, Nonce, SigInfo, KexA, HelloHash, MaxMsgSize]` (8-element array) | Owner proves to device it possesses the voucher private key | Ephemeral (session only) | Yes (NonceTO2ProveOV) | nil |
| **TO2.SetupDevice** | 65 | `deviceSetup = [RvInfo, GUID, Nonce, Owner2Key]` (4-element array) | Owner tells device its new identity | Ephemeral (session only) | Yes (NonceTO2SetupDv) | nil |
| **OVEntry** | -- | `VoucherEntryPayload = [PrevHash, HeaderHash, Extra, PublicKey]` (4-element array) | Voucher chain entry binding ownership transfer | **Permanent** (stored in voucher, verified repeatedly) | **No** | nil |

Also signed by owner key (or delegate):
| **FDOKeyAuth.Prove** | -- | `[TypeTag="FDOKeyAuth.Prove", NonceS, NonceC, HashChallenge, CallerKey]` (5-element array) | Prove key ownership for voucher transfer API | Ephemeral (session only) | Yes (two nonces) | nil |
| **FDOKeyAuth.Challenge** | -- | `[TypeTag="FDOKeyAuth.Challenge", NonceC, NonceS, HashHello, CallerKey]` (5-element array) | Server challenges caller in voucher transfer | Ephemeral (session only) | Yes (two nonces) | nil |

### 3.2 Device Key Operations

The device key signs in two distinct protocol phases.

| Operation | Msg Type | Payload (CBOR) | Purpose | Lifetime | Nonce? | external_aad |
|-----------|----------|----------------|---------|----------|--------|-------------|
| **TO1.ProveToRV** | 32/33 | `EAT = {10: Nonce, 256: UEID, -257: null}` (CBOR map) | Device proves identity to rendezvous server | Ephemeral | Yes | nil |
| **TO2.ProveDevice** | 62/63 | `EAT = {10: Nonce, 256: UEID, -257: {KexB}}` (CBOR map) | Device proves identity to owner during TO2 | Ephemeral | Yes | nil |

FDO 2.0 adds:
| **TO2.ProveDevice20** | 82 | `EAT` wrapping `ProveDevice20Payload = [KexSuite, CipherSuite, XA, Nonce, HashPrev]` (5-element array) | Anti-DoS: device proves first in FDO 2.0 | Ephemeral | Yes | nil |

### 3.3 Manufacturer Key Operations

| Operation | Msg Type | Payload (CBOR) | Purpose | Lifetime | Nonce? | external_aad |
|-----------|----------|----------------|---------|----------|--------|-------------|
| **OVEntry** (first) | -- | `VoucherEntryPayload = [PrevHash, HeaderHash, Extra, PublicKey]` | First voucher chain entry -- manufacturer signs over to first owner | **Permanent** | **No** | nil |
| **DI.MfgAttest** (proposed) | 11 | `OVHeader` (bstr) | Prove manufacturer possesses private key during DI | **Permanent** (or at least long-lived -- proves DI was authentic) | **No** | nil |

### 3.4 Other Keys

| Operation | Msg Type | Payload (CBOR) | Purpose | Lifetime | Nonce? | external_aad |
|-----------|----------|----------------|---------|----------|--------|-------------|
| **TO2.ProveOVHdr20** | 83 | `ProveOVHdr20Payload = [OVH, NumEntries, HMAC, Nonce, XB, MaxMsgSize]` (6-element array) | Owner proves to device (FDO 2.0 flow) | Ephemeral | Yes | nil |
| **FSIM.MetaPayload** | -- | MetaPayload CBOR (image URL + hash + metadata) | Signed boot image metadata for BMO | **Permanent** (stored, verified at boot) | **No** | nil |

## 4. Concrete Confusion Scenarios

For a signing oracle attack to succeed, three conditions must hold:

1. **Same key** signs in both contexts
2. **Payload bytes** from context A can be accepted in context B
3. **No domain separation** distinguishes the signing inputs

Condition 3 is universally true today (all external_aad is empty). Condition 1
is true for several pairs. The question is condition 2 -- whether CBOR
structural differences are enough.

### 4.1 TO2.SetupDevice vs OVEntry -- Same Key, Same Array Length

**Risk: Medium-High.** Both are 4-element CBOR arrays signed by the owner key,
with `PublicKey` as the last element.

```
deviceSetup          = [RvInfo[][], GUID(bstr/16), Nonce(bstr/16), PublicKey]
VoucherEntryPayload  = [Hash([int,bstr]), Hash([int,bstr]), null/bstr, PublicKey]
```

**Why it doesn't trivially work:** Element 0 is a nested array (RvInfo) vs. a
2-element `[int, bstr]` array (Hash). Element 1 is a raw 16-byte bstr (GUID)
vs. a 2-element array (Hash). A strict CBOR decoder will reject the type
mismatch.

**Why it's still concerning:** Both element 2 and element 3 could plausibly
overlap -- Nonce is a 16-byte bstr, and Extra can be null or bstr; PublicKey
matches PublicKey. If an implementation uses lenient CBOR decoding (e.g., raw
`cbor.RawBytes` matching), the structural defense weakens. More importantly,
the defense is fragile -- it depends on CBOR type checking in the decoder, not
on a cryptographic property.

**With external_aad:** Even with identical payload bytes, different tags
produce different signing inputs. The structural defense becomes irrelevant.

### 4.2 TO1.ProveToRV vs TO2.ProveDevice -- Same Key, Same Structure

**Risk: Medium.** Both are EAT tokens (CBOR maps) signed by the device key.

```
TO1: EAT = {10: Nonce, 256: UEID, -257: null}
TO2: EAT = {10: Nonce, 256: UEID, -257: {KeyExchangeB: bstr}}
```

**Structural difference:** TO2 includes `eatFdoClaim` (-257) with
KeyExchangeB data; TO1 has null or absent -257. However, CBOR maps don't
enforce field ordering, and the EAT structure is an open map -- additional
claims can be present or absent.

**Attack scenario:** A malicious owner server (or MITM) initiates a TO2
session with a device, receives the TO2.ProveDevice EAT token, then replays
it to a rendezvous server as TO1.ProveToRV. The nonces are different (TO1 uses
an RV-provided nonce, TO2 uses an owner-provided nonce), so the RV server
would need to have issued the same nonce value -- which is a 128-bit random
collision, making this practically infeasible. But the defense is probabilistic
(nonce uniqueness), not structural.

**With external_aad:** Different tags make this cryptographically impossible
regardless of nonce values.

### 4.3 DI.MfgAttest vs OVEntry -- Same Key, No Nonces

**Risk: High.** This is the scenario from `di-factory-authentication-and-tpm.md`
that motivated this entire analysis. The manufacturer key signs both the
proposed DI attestation and the first OVEntry, and **neither contains a nonce**.

```
DI.MfgAttest payload = OVHeader (bstr, CBOR-encoded VoucherHeader)
OVEntry payload      = [PrevHash, HeaderHash, Extra, PublicKey] (4-element array)
```

**Structural difference:** The DI attestation payload is a single CBOR bstr
(encoded VoucherHeader); the OVEntry payload is a 4-element CBOR array. These
are structurally different at the CBOR level.

**Why external_aad is still essential:** Without it, both signatures have
identical Sig_structures apart from the payload bytes. A future protocol change
that adjusts either payload format could collapse the structural defense. And
since neither payload has a nonce, there is no temporal binding -- a signature
is valid forever.

**The DI proposal already specifies `external_aad = "FDO-DI-MfgAttest-v1"`.**
This document proposes extending the same approach to all operations.

### 4.4 FDOKeyAuth.Prove vs OVEntry -- Same Key

**Risk: Low-Medium.** FDOKeyAuth wisely includes a TypeTag string
(`"FDOKeyAuth.Prove"`) as the first array element, making the CBOR structure
distinguishable. But:

- The TypeTag is inside the payload, not in external_aad
- If an attacker could somehow get a signer to produce a COSE_Sign1 over
  arbitrary bytes (not going through the FDOKeyAuth message construction), the
  TypeTag wouldn't help
- The defense depends on the signing code always constructing the payload
  correctly, not on a cryptographic invariant

**With external_aad:** TypeTags remain as defense-in-depth (belt), and
external_aad provides cryptographic enforcement (suspenders).

### 4.5 Cross-Protocol: FDO Signatures vs Non-FDO Protocols

If an FDO key is also used in another COSE-based protocol (CWT, SUIT, etc.),
signatures from that protocol could potentially verify in FDO contexts, and
vice versa. This is especially relevant for:

- **CWT tokens:** If an owner key is also used to sign CWTs (e.g., for API
  authentication), the CWT signature has the same Sig_structure shape as any
  FDO signature. CWT doesn't mandate external_aad either (RFC 8392).

- **SUIT manifests:** If a manufacturer key is used for both firmware signing
  (SUIT) and FDO voucher extension, signatures could theoretically cross.

This is speculative -- FDO keys are unlikely to be shared with other protocols
in practice. But the point of domain separation is to make the defense
structural rather than relying on operational discipline.

### 4.6 Confusion Scenario Summary

| Pair | Key | Array Lengths | Structural Distinction | Nonce Binding | Risk Without AAD |
|------|-----|---------------|----------------------|---------------|-----------------|
| TO2.SetupDevice vs OVEntry | Owner | 4 vs 4 | Element types differ | SetupDevice yes, OVEntry no | **Medium-High** |
| TO1.ProveToRV vs TO2.ProveDevice | Device | Map vs Map | FDO claim presence | Both yes (different nonces) | Medium |
| DI.MfgAttest vs OVEntry | Manufacturer | bstr vs 4-array | Fundamentally different | **Neither** | **High** |
| FDOKeyAuth.Prove vs OVEntry | Owner | 5 vs 4 | TypeTag + length | FDOKeyAuth yes | Low-Medium |
| TO2.ProveOVHdr vs OVEntry | Owner | 8 vs 4 | Length + nonce | ProveOVHdr yes | Low |
| TO0.OwnerSign vs OVEntry | Owner | 2 vs 4 | Length | Indirect (hash over nonce) | Low |
| FSIM.MetaPayload vs OVEntry | Any | Varies | Structure differs | Neither | Medium |
| FDO vs non-FDO COSE | Any | Varies | Protocol-dependent | Protocol-dependent | **Unknown** |

## 5. Proposed external_aad Tags

Every FDO COSE_Sign1 operation gets a unique ASCII string tag. The tag is
used as `external_aad` in the COSE Sig_structure and must be agreed upon by
both signer and verifier (implied by the protocol message context).

```cddl
;; FDO 2.0 external_aad tags
;; Each tag is a fixed ASCII string, CBOR-encoded as a bstr for
;; inclusion in the Sig_structure external_aad field.

FDO_AAD_TO0_OwnerSign      = "FDO-TO0-OwnerSign-v1"
FDO_AAD_TO1_ProveToRV      = "FDO-TO1-ProveToRV-v1"
FDO_AAD_TO2_ProveOVHdr     = "FDO-TO2-ProveOVHdr-v1"
FDO_AAD_TO2_ProveDevice    = "FDO-TO2-ProveDevice-v1"
FDO_AAD_TO2_SetupDevice    = "FDO-TO2-SetupDevice-v1"
FDO_AAD_TO2_ProveDevice20  = "FDO-TO2-ProveDevice20-v1"
FDO_AAD_TO2_ProveOVHdr20   = "FDO-TO2-ProveOVHdr20-v1"
FDO_AAD_OVEntry            = "FDO-OVEntry-v1"
FDO_AAD_DI_MfgAttest       = "FDO-DI-MfgAttest-v1"
FDO_AAD_KeyAuth_Challenge  = "FDO-KeyAuth-Challenge-v1"
FDO_AAD_KeyAuth_Prove      = "FDO-KeyAuth-Prove-v1"
FDO_AAD_FSIM_MetaPayload   = "FDO-FSIM-MetaPayload-v1"
```

### 5.1 Tag Design Rationale

- **`FDO-` prefix:** Prevents collision with other COSE-based protocols (CWT,
  SUIT, EDHOC, etc.) that may use the same keys.
- **Operation name:** Unambiguously identifies the protocol context.
- **`-v1` suffix:** Enables versioning if the signing semantics change in
  future protocol revisions.
- **ASCII string:** Simple, human-readable, and deterministic serialization.
  No CBOR encoding ambiguity.

### 5.2 How It Changes the Signing Input

Today, every FDO COSE_Sign1 produces:

```
Sig_structure = ["Signature1", protected_headers, h'', payload]
                                                  ^^^^
                                                  empty external_aad
```

With this proposal:

```
;; TO2.ProveOVHdr
Sig_structure = ["Signature1", protected, "FDO-TO2-ProveOVHdr-v1", payload]
                                          ^^^^^^^^^^^^^^^^^^^^^^^^

;; OVEntry
Sig_structure = ["Signature1", protected, "FDO-OVEntry-v1", payload]
                                          ^^^^^^^^^^^^^^^^
```

Even if `protected` and `payload` were somehow identical, the different
`external_aad` values produce different hash inputs, and therefore different
valid signatures.

## 6. Implementation

### 6.1 Code Changes Required

The go-fdo COSE implementation already supports external_aad. Every
`.Sign()` call currently passes `nil`:

```go
// Current (to2.go:849)
if err := s1.Sign(ownerKey, nil, nil, opts); err != nil { ... }

// Proposed
if err := s1.Sign(ownerKey, nil, []byte("FDO-TO2-ProveOVHdr-v1"), opts); err != nil { ... }
```

Similarly, every `.Verify()` call must pass the matching tag:

```go
// Current
if ok, err := s1.Verify(pub, nil, nil); ...

// Proposed
if ok, err := s1.Verify(pub, nil, []byte("FDO-TO2-ProveOVHdr-v1")); ...
```

### 6.2 Files Affected

| File | Operations | Current external_aad |
|------|-----------|---------------------|
| `to0.go` (lines 212, 233) | TO0.OwnerSign (owner + delegate signing) | `nil` |
| `to1.go` (line 156) | TO1.ProveToRV | `nil` |
| `to2.go` (lines 849, 1012, 1212) | TO2.ProveOVHdr, ProveDevice, SetupDevice | `nil` |
| `to2_client_v200.go` (line 310) | TO2.ProveDevice20 | `nil` |
| `to2_server_v200.go` (line 250) | TO2.ProveOVHdr20 | `nil` |
| `voucher.go` (line 706) | OVEntry (ExtendVoucher) | `nil` |
| `transfer/fdokeyauth_messages.go` (line 259) | FDOKeyAuth.Challenge, Prove | `nil` |
| `fsim/meta_helpers.go` (line 93) | FSIM.MetaPayload | `nil` |

Plus all corresponding `.Verify()` call sites.

### 6.3 Backward Compatibility

**This is a breaking change.** A signature produced with external_aad will
not verify without the same external_aad, and vice versa. Existing FDO 1.1
signatures (with empty external_aad) will fail verification if the verifier
expects a tag.

**Mitigation options:**

1. **Protocol version gating:** FDO 2.0 mandates external_aad; FDO 1.1
   continues with empty. The protocol version is negotiated before any
   signatures are exchanged.

2. **OVEntry special case:** Existing vouchers contain OVEntry signatures
   made with empty external_aad. Verifiers must accept both old (empty) and
   new (tagged) OVEntries based on the voucher's protocol version field, or
   a flag in the OVEntry itself.

3. **FDOKeyAuth:** Since the voucher transfer protocol is new (defined in our
   appnote, not the base FDO spec), we can mandate external_aad from v1 with
   no backward compatibility concern.

4. **DI.MfgAttest:** This is a new operation. external_aad is mandatory from
   the start.

## 7. Relationship to Existing Defenses

### 7.1 FDOKeyAuth TypeTags (Belt)

FDOKeyAuth already includes `"FDOKeyAuth.Prove"` and
`"FDOKeyAuth.Challenge"` as the first CBOR array element in signed payloads.
This is good practice and should be retained. It provides:

- **Structural defense:** A CBOR decoder expecting an OVEntry (which starts
  with a Hash) will reject a payload starting with a text string.
- **Human readability:** The TypeTag makes payloads self-describing.

But it does NOT provide:

- **Cryptographic domain separation:** The COSE Sig_structure is identical
  whether the payload starts with a TypeTag or not. The tag is just payload
  bytes.
- **Defense against arbitrary-payload signing:** If an attacker can get a
  signer to produce a COSE_Sign1 over chosen bytes (bypassing the message
  construction code), TypeTags don't help.

**Recommendation:** Keep TypeTags as defense-in-depth. Add external_aad for
cryptographic enforcement. Belt and suspenders.

### 7.2 Nonce Binding

Most ephemeral operations (TO1, TO2, FDOKeyAuth) include fresh nonces, which
bind signatures to specific sessions. This prevents replay of captured
signatures. But:

- **OVEntry has no nonce.** Voucher signatures are permanent.
- **FSIM.MetaPayload has no nonce.** Signed metadata is permanent.
- **DI.MfgAttest (proposed) has no nonce.**
- Nonces prevent replay but not type confusion. A signature with a fresh
  nonce can still be misinterpreted in the wrong context if the payload
  happens to decode successfully.

### 7.3 CBOR Structure Differences

Different FDO messages use different CBOR array lengths and element types.
This provides implicit structural defense. But:

- **TO2.SetupDevice and OVEntry are both 4-element arrays** with PublicKey
  as the last element (see Section 4.1).
- **TO1 and TO2 EAT tokens are both CBOR maps** with the same key structure.
- Structural defense is fragile -- it depends on strict decoder behavior and
  breaks silently if payload formats evolve to become more similar.

## 8. Prior Art: Why EDHOC Got This Right

EDHOC (RFC 9528) is instructive because it faced exactly the same problem:
multiple COSE_Sign1 operations using potentially the same key across different
protocol messages. The EDHOC designers solved it by including the transcript
hash and credential identifier in external_aad for every signature:

```
;; EDHOC Message 2 (Responder signs)
external_aad = << TH_2, CRED_R, ? EAD_2 >>

;; EDHOC Message 3 (Initiator signs)
external_aad = << TH_3, CRED_I, ? EAD_3 >>
```

This is more sophisticated than our proposal (EDHOC binds to the full
transcript; we use fixed string tags), but the principle is identical:
**every COSE_Sign1 must include context in external_aad that makes the
signing input unambiguous.**

EDHOC's security analysis explicitly considers signing oracle attacks and
relies on external_aad to prevent them. FDO's security analysis does not
mention external_aad at all (`FIDO-IoT-spec.bs` contains zero references to
the term).

## 9. Recommended Rollout

### Phase 1: New Operations (No Backward Compatibility Concern)

- **DI.MfgAttest:** `"FDO-DI-MfgAttest-v1"` -- mandatory from introduction
- **FDOKeyAuth.Challenge:** `"FDO-KeyAuth-Challenge-v1"` -- mandatory from
  next voucher transfer protocol revision
- **FDOKeyAuth.Prove:** `"FDO-KeyAuth-Prove-v1"` -- same

### Phase 2: FDO 2.0 Protocol Messages

Gated on FDO 2.0 version negotiation:

- **TO2.ProveDevice20:** `"FDO-TO2-ProveDevice20-v1"`
- **TO2.ProveOVHdr20:** `"FDO-TO2-ProveOVHdr20-v1"`

### Phase 3: Existing Operations (Breaking Change)

Requires protocol versioning coordination:

- **TO0.OwnerSign:** `"FDO-TO0-OwnerSign-v1"`
- **TO1.ProveToRV:** `"FDO-TO1-ProveToRV-v1"`
- **TO2.ProveOVHdr:** `"FDO-TO2-ProveOVHdr-v1"`
- **TO2.ProveDevice:** `"FDO-TO2-ProveDevice-v1"`
- **TO2.SetupDevice:** `"FDO-TO2-SetupDevice-v1"`

### Phase 4: Long-Lived Artifacts (Most Complex)

- **OVEntry:** `"FDO-OVEntry-v1"` -- existing vouchers must remain verifiable;
  verifier must check voucher version to determine expected external_aad
- **FSIM.MetaPayload:** `"FDO-FSIM-MetaPayload-v1"` -- existing signed
  metadata must remain verifiable

## 10. Open Questions

1. **Tag encoding:** Should external_aad be the raw ASCII bytes of the tag
   string, or CBOR-encoded as a tstr? Raw bytes are simpler; CBOR-encoded is
   more consistent with EDHOC's approach (which CBOR-encodes an array). The
   examples above use raw ASCII bytes.

2. **Tag registry:** Should there be a formal IANA-style registry of FDO
   external_aad tags, or is the `FDO-<operation>-v<n>` convention sufficient?

3. **Should external_aad include dynamic data?** EDHOC includes transcript
   hashes. We could include the GUID, protocol version, or session nonce in
   external_aad in addition to the fixed tag. This provides stronger binding
   but increases complexity. Fixed tags are sufficient for domain separation;
   nonces already provide session binding in the payload.

4. **OVEntry migration:** How do verifiers handle vouchers containing a mix
   of old-style (no AAD) and new-style (with AAD) entries? The voucher format
   would need a version indicator, or verifiers must try both.
