# DI Factory Authentication: Analysis

**Status:** Draft / Discussion
**Date:** 2026-03-18
**Related:** `diun.md`, `cose-domain-separation-proposal.md`,
`proposed-amendment-securing-fdo-in-tpm.md`, `tpm-spec-gap-analysis.md`

## 1. Problem Statement

The FDO specification defines Device Initialization (DI) using a Trust On
First Use (TOFU) model. The device blindly accepts whatever manufacturer
public key is sent in DI.SetCredentials -- no verification of the factory's
identity occurs during DI. The OVHeader is sent unsigned.

This means:

- A rogue factory (or MITM on the factory network) can initialize devices
  with its own key, taking permanent control of the device's onboarding path.
- A misconfigured factory (wrong HSM, wrong key reference, key rotation
  mistake) can produce devices that pass DI but fail at onboarding --
  potentially thousands of them before anyone notices.

## 2. How DI Works Today

### 2.1 FDO Spec (§7.2) -- The Base Protocol

Four messages, no authentication of the server:

```
Device -> Server:  DI.AppStart(10)       [DeviceMfgInfo]
Server -> Device:  DI.SetCredentials(11) [CapFlags, VendorCaps, OVHeader]
Device -> Server:  DI.SetHMAC(12)        [HMAC(OVHeader)]
Server -> Device:  DI.Done(13)
```

```cddl
;; Type 11 -- sent unsigned from server to device
DI.SetCredentials = [
    CapabilityFlags,
    VendorCapFlags,
    bstr .cbor OVHeader          ;; contains OVPublicKey, GUID, RvInfo, etc.
]
```

The device receives SetCredentials, blindly trusts the OVHeader, stores
Hash(OVHeader.OVPublicKey) as DCPubKeyHash, computes an HMAC, and sends it
back. **Nothing in this exchange is signed by anyone.** The manufacturer's
HSM is not involved at all during DI -- it is only used later when
constructing Ownership Voucher entries (after DI completes).

### 2.2 go-fdo Implementation

The go-fdo implementation (`di.go`) follows the spec exactly. `setCredentials()`
receives the OVHeader, stores the credential, computes the HMAC, and returns
it. No verification of OVPublicKey occurs. No signature is checked.

## 3. The DIUN Approach (fido-device-onboard-rs)

### 3.1 Architecture: Sidecar Pre-Authentication

The Rust implementation defines DIUN (Device Initialize over Untrusted
Networks, `diun.md`) as a **companion protocol that runs before DI**. The
key architectural decision: DI itself is completely unmodified. DIUN is a
gate in front of it.

The device's logic is:

1. **Do I have a factory trust anchor in my firmware?** (a key hash or root
   cert list, baked in at build time or programmed during board bring-up)
2. **If yes:** run DIUN. If DIUN fails, abort -- do not proceed to DI.
3. **If no:** skip DIUN entirely, proceed directly to DI (TOFU as today).

This is the right architecture. Factory authentication is a separate
concern from device initialization. It belongs in a separate protocol phase,
not bolted onto DI messages. DI remains unaltered regardless of whether
DIUN ran before it.

### 3.2 DIUN Protocol Flow

```
Device -> Server:  DIUN.Connect(210)            [Nonce, KexSuite, CipherSuite, xA]
Server -> Device:  DIUN.Accept(211)             [COSE_Sign1(xB), DIUNPubKey in X5Chain]
Device -> Server:  DIUN.RequestKeyParameters(212) [TenantId]  (encrypted)
Server -> Device:  DIUN.ProvideKeyParameters(213) [pkType, KeyStorageTypes]  (encrypted)
Device -> Server:  DIUN.ProvideKey(214)          [PublicKey, KeyStorageType]  (encrypted)
Server -> Device:  DIUN.Done(215)                [MfgStringType]  (encrypted)

;; DIUN passed. Standard DI follows, unmodified.
Device -> Server:  DI.AppStart(10)
Server -> Device:  DI.SetCredentials(11)
Device -> Server:  DI.SetHMAC(12)
Server -> Device:  DI.Done(13)
```

The trust anchor (`DIUNPubKeyHash` or `DIUNPubKeyRootCerts`) lives in the
device's firmware -- not in a TPM NV index, not in the FDO credential. It
is a firmware build-time or board-bring-up decision by the OEM, completely
outside the scope of FDO or the TPM spec.

### 3.3 What DIUN Gets Right

1. **Sidecar, not modification.** DI is not touched. The authentication
   concern is cleanly separated. If DIUN fails, the device dies before DI
   even starts. If DIUN succeeds, DI proceeds exactly as it always has.

2. **Explicit protocol.** The server knows whether the device requires
   factory authentication (because the device initiates DIUN.Connect). No
   implicit behavioral changes. No "maybe the device checked the signature,
   maybe it didn't."

3. **Challenge/response with nonce.** The device sends a nonce in
   DIUN.Connect; the server signs it in DIUN.Accept. This proves the factory
   has the key *right now*, not at some point in the past.

4. **Trust anchor is firmware, not TPM.** The trust anchor is baked into the
   device image. No TPM NV index management, no hierarchy decisions, no
   write-protection policies. The OEM controls it through their normal
   firmware build process.

### 3.4 Where DIUN Is Overcomplicated

DIUN conflates three orthogonal concerns into one protocol:

| Concern | DIUN messages | Necessary? |
|---------|---------------|------------|
| **Factory authentication** | Connect(210) + Accept(211) | Yes -- the core requirement |
| **Encrypted channel** | ECDH in Connect/Accept, AES-GCM wrapping all subsequent messages | No -- no secrets flow during DI |
| **Key type negotiation** | RequestKeyParameters(212) + ProvideKeyParameters(213) + ProvideKey(214) + Done(215) | Useful but orthogonal |

The encryption adds ECDH key exchange + AES-GCM infrastructure for no
practical benefit: DI transmits public keys, serial numbers, and OV headers
-- none of which are confidential. Passive eavesdropping is not a threat
model that encryption solves here (and active MITM is already defeated by
the authentication).

Key type negotiation (server tells device what key type to generate) is a
genuinely useful feature, but it does not need to be coupled with factory
authentication. It could be its own extension.

If DIUN were just the authentication part -- Connect + Accept, 2 messages
-- it would be dramatically simpler. The remaining 4 messages are useful
features riding on the encrypted channel, but they're not required for the
core "prove you're my factory" problem.

### 3.5 DIUN Uses a Separate Key

DIUN's `DIUNPubKey` is distinct from the manufacturer's `OVPublicKey`. This
means:

- **Two keys on the factory floor** instead of one (manufacturer key for
  voucher extension + DIUN key for factory auth).
- **Two trust anchors to pre-seed**: the device needs `DIUNPubKeyHash` in
  firmware for DIUN, and will receive `DCPubKeyHash` during DI for
  onboarding. These are hashes of different keys.
- **No binding between DIUN auth and the DI credential.** DIUN proves the
  factory is authorized to run DI, but does not bind that proof to the
  specific manufacturer key installed during DI. After DIUN succeeds, the
  device still blindly accepts whatever `OVPublicKey` is in SetCredentials.

A simpler variant could reuse the manufacturer's own key for both DIUN
authentication and voucher extension: one key, one HSM, and the trust
anchor hash is the same value that becomes DCPubKeyHash after DI. But this
is an optimization, not an architectural change.

## 4. Implications for go-fdo

### 4.1 DI remains unmodified

The conclusion from this analysis is that DI should not be changed. No
optional COSE_Sign1 field in SetCredentials, no embedded signatures, no
implicit behavioral changes based on device state. DI is DI.

### 4.2 DIUN as optional companion

If factory authentication is needed, it should be a sidecar protocol --
either DIUN as defined by the Rust implementation, or a simplified variant.
The device firmware decides whether to run it. The manufacturing server
supports it or doesn't.

### 4.3 Trust anchor is a firmware concern

The factory trust anchor (key hash or root cert list) lives in the device
firmware image. It is programmed by the OEM at build time or board
bring-up. It is not an FDO protocol concern. It is not a TPM NV index
concern. It is not part of the device credential.

This means:

- No new NV indices in the TPM spec for the trust anchor
- No TPM hierarchy decisions for trust anchor storage
- No interaction with credential reuse (the trust anchor is immutable
  firmware; the credential is mutable runtime state)
- The "fully pre-provisioned TPM" case (TPM vendor loads entire credential,
  DI never runs) is a completely separate scenario and irrelevant to
  factory authentication

### 4.4 Potential go-fdo implementation path

If we implement DIUN support in go-fdo:

1. **DIUN as a separate handler** -- not wired into the DI code path. A
   separate HTTP endpoint (`/fdo/100/msg/210` etc.) with its own state
   machine.
2. **Device client checks firmware for trust anchor** -- if present, runs
   DIUN first; if absent, skips to DI.
3. **DIUN failure = hard stop** -- the device does not fall through to DI
   on DIUN failure. It aborts.
4. **DI code untouched** -- `di.go` does not change at all.

Whether we implement full DIUN or a simplified 2-message variant is a
separate decision. The architecture is the same either way.

## 5. HSM Considerations

### 5.1 Two signing operations per device

If factory authentication is used, the manufacturer's HSM performs **two**
signing operations per device instead of one:

1. **DIUN authentication:** Sign the DIUN.Accept response (proving key
   possession to the device).
2. **Voucher extension:** Sign the first OVEntry (creating the ownership
   voucher), which happens after DI completes.

### 5.2 Why two operations are unavoidable

The only way to collapse to one would be for the device to receive and
verify the first OVEntry during DI. This is unworkable: at DI time, we may
not know who the first owner is -- OVEntries are constructed after DI, and
the first owner's public key is not yet determined.

Any form of factory attestation -- whether DIUN, a simplified variant, or
anything else -- inherently requires an additional signing operation beyond
voucher extension. This is a consequence of when DI occurs in the protocol
timeline, not a design choice.

### 5.3 Domain separation (external_aad)

Any COSE_Sign1 produced during DIUN should use domain separation via
`external_aad` to prevent the signature from being confused with other FDO
signing contexts. See `cose-domain-separation-proposal.md` for the full
analysis and proposed tags. Current DIUN does not use external_aad (same
gap as the rest of FDO).

## 6. Summary

| Approach | Modifies DI? | New msgs | New keys | Trust anchor location | Complexity |
|----------|-------------|----------|----------|----------------------|------------|
| No change (TOFU) | No | 0 | 0 | N/A | None |
| Full DIUN (Rust) | No | 6 | 1 | Firmware | High |
| Simplified DIUN (2-msg C/R) | No | 2 | 0 | Firmware | Low |

All viable approaches share the same architecture: **DI is unmodified.
Factory authentication, if needed, is a separate sidecar protocol that
runs before DI and is gated on the presence of a firmware trust anchor.**

## 7. Open Questions

1. **Full DIUN or simplified?** Implement the 6-message DIUN protocol
   (with encryption + key negotiation) or a minimal 2-message C/R
   (authentication only)?
2. **Separate key or reuse manufacturer key?** DIUN uses a separate
   `DIUNPubKey`. A simplified variant could reuse `OVPublicKey`, reducing
   to one key and one trust anchor. Trade-off: flexibility vs. simplicity.
3. **Binding DIUN to DI.** After DIUN succeeds, should the device verify
   that the `OVPublicKey` in SetCredentials matches the key authenticated
   during DIUN? (DIUN currently does not do this.)
4. Should go-fdo prioritize DIUN implementation, or is factory
   authentication a low-priority feature for our target deployments?
