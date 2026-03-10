# Proposed Amendment: Securing FDO Credentials in the TPM v1.0

**Target Specification:** securing-fdo-in-tpm-v1.0-rd-20231010  
**Status:** Draft Proposal  
**Date:** 2026-03-10  

## 1. Executive Summary

This document proposes amendments to the "Securing FDO Credentials in the TPM"
specification (Review Draft, October 2023). The amendments address architectural
concerns identified during review regarding TPM hierarchy ownership, the
Restricted Operating Environment (ROE) model, credential reuse flows, and
post-onboarding access policy.

The core thesis of these amendments is:

1. **Standardize locations, not protection policies.** The spec should mandate
   where FDO credentials are stored (NV index handles, data formats, key
   templates) so that FDO software can reliably locate them. The spec should
   not mandate which TPM hierarchy is used or what protection attributes are
   applied -- these are policy decisions that belong to the entity provisioning
   the credentials.

2. **Separate pre-onboarding security from post-onboarding access.** Before
   first onboarding, credential integrity is critical and is naturally provided
   by TPM key protections and HMAC binding. After successful onboarding, the
   proven Owner has full system control and should be explicitly permitted to
   read, modify, or delete FDO credentials as needed.

3. **Define a key preference order.** FDO software should discover and use
   device keys in a defined priority: DAK first, then LDevID, then IDevID.
   This supports the full range of deployment scenarios from TPM vendor
   provisioning through end-user brownfield re-equipping.

4. **Support credential reuse without requiring a dedicated ROE.** The current
   spec's ROE model creates a self-contradiction with credential reuse flows.
   Post-onboarding FDO operations may run as normal OS services and need
   appropriate access to TPM-stored credentials.

---

## 2. Problem Statement

### 2.1 Hierarchy Ownership Mismatch

The current spec mandates that FDO Device Key and HMAC Secret be created as
primary objects in the **Endorsement hierarchy** (normative SHALL). The stated
rationale is key stability: the Endorsement Primary Seed (EPS) is essentially
immutable, so keys derived from it are deterministically recreatable.

However, the Endorsement hierarchy is owned by the **TPM silicon vendor**
(Infineon, STMicro, Nuvoton, etc.), not the equipment OEM. In the common
manufacturing scenario where an OEM performs Device Initialization on a
production line, the OEM:

- Does NOT own the Endorsement hierarchy
- Does NOT control whether Endorsement authorization remains empty
- DOES control the Platform hierarchy (through firmware/BIOS)
- DOES control the Owner hierarchy (as initial system integrator)

The spec's hierarchy choice is natural for the TPM vendor provisioning case
(section 3.3.2) but creates an ownership mismatch for the more common OEM
provisioning case (section 3.3.1) and supply-chain provisioning case (section
3.3.3).

Furthermore, if a downstream entity or OS sets the Endorsement authorization
after manufacturing, the ROE cannot recreate keys unless it knows the new
Endorsement auth. The spec acknowledges this problem (section 4.6) but does not
resolve it, recommending persistence as a workaround.

### 2.2 The ROE Model vs Real-World Deployment

The current spec assumes the ROE is one of:

- A hardware-isolated execution environment (dedicated processor, TEE)
- A time-separated boot phase (initrd, early systemd service) that locks TPM
  access before the OS fully starts

Both models assume the ROE has special TPM access that normal OS code does not.
This assumption breaks down in several real-world scenarios:

1. **Post-onboarding operations.** After the first Owner onboards the device
   via TO2, subsequent FDO operations (credential reuse, re-onboarding) may be
   triggered by normal OS services, not a dedicated ROE. The Owner may install
   an FDO client as a regular application.

2. **ROE replacement.** The Owner, having full system control via FSIM, may
   replace the original ROE software entirely. The replacement FDO client may
   not have the same TPM access privileges as the manufacturer's original ROE.

3. **Brownfield deployment.** An end user re-equipping existing machines with
   FDO may not have any ROE infrastructure at all. They need to provision FDO
   credentials and run FDO as normal OS software.

The current NV index attributes (`OWNERWRITE=0`, `OWNERREAD=0` for DCTPM and
key Unique Strings) prevent normal OS code from accessing credentials, making
post-onboarding credential reuse impossible without either:

- Knowing the ROE's authValue secret (which may not be available to replacement
  software)
- Running FDO exclusively at boot time with time-based locking (which
  prevents runtime re-onboarding)
- Using empty authValue without locking (which abandons the security model
  entirely)

### 2.3 Credential Reuse Self-Contradiction

The current spec's protection model contradicts its own credential reuse flow:

- Credential reuse requires writing new GUID, RVInfo, PubKeyHash, and HMAC
  Unique String to NV indices
- These NV indices have `OWNERWRITE=0`, accessible only via authValue
- Keys are under Endorsement hierarchy
- After `TPM2_Clear` (typical in resale), Endorsement auth may have been
  changed by the previous Owner
- If keys are not persisted, the ROE cannot recreate them without Endorsement
  auth

The spec's own credential reuse mechanism breaks in the realistic scenario it
is designed to support.

### 2.4 Post-Onboarding Security Model is Over-Specified

The current spec treats FDO credential protection as absolute: credentials must
be locked away from all non-ROE access at all times. This does not reflect the
actual post-onboarding threat model.

After a successful TO2 onboarding:

- The Owner has been mutually authenticated
- The Owner has full system control via FSIM
- The Owner can install arbitrary software, reflash the OS, replace the ROE,
  rewrite credentials, or wipe the device entirely
- "Protecting credentials from the Owner" is therefore incoherent -- the Owner
  already has the ability to do anything to the system

What IS important:

- **Before first onboarding:** Credential integrity must be maintained so the
  device onboards to the correct Owner. The TPM's own key protections
  (fixedTPM, non-exportable) and the HMAC binding between credentials and
  Ownership Voucher already provide this.
- **At onboarding time:** The device must prove provenance -- that the Device
  Key genuinely resides in this TPM and matches the Ownership Voucher. This
  is a property of the TPM key itself, not the NV index attributes.
- **After onboarding:** The proven Owner should be explicitly permitted to
  manage FDO credentials through the Owner hierarchy.

The DCActive flag already follows this model correctly: `OWNERWRITE=1`,
`OWNERREAD=1`, empty authValue. The spec recognized that the Owner needs to
toggle this flag for resale. The same logic applies to all FDO credentials
post-onboarding.

---

## 3. Proposed Key Preference Order

### 3.1 Overview

FDO ROE software discovering device keys in the TPM SHALL use the following
order of preference:

| Priority | Key Type | Description |
|----------|----------|-------------|
| 1 | **DAK** (Device Attestation Key) | Purpose-built key for FDO, provisioned at any point in the device lifecycle |
| 2 | **LDevID** | Locally significant device identity, provisioned by the current Owner |
| 3 | **IDevID** | Permanent hardware identity, provisioned by TPM or platform manufacturer |

The ROE checks for each key at its standard NV index handle. It uses the first
key it finds, in priority order.

### 3.2 Rationale

This order follows a natural specificity gradient:

- **DAK** is the most specific: it exists solely for FDO and is provisioned by
  whichever entity (TPM vendor, OEM, supply chain, end user) decided to enable
  FDO on this device. Its protection level and hierarchy placement are policy
  decisions of the provisioning entity.

- **LDevID** is owner-scoped: it was created by the current device operator,
  represents their relationship with the device, and follows TCG standards for
  locally significant identity. It is the standard mechanism for
  owner-provisioned device identity.

- **IDevID** is the fallback: it is the permanent hardware identity, always
  present (unless deliberately wiped), and proves the device's manufacturing
  provenance. It should function as a bootstrap identity for initial
  onboarding, not as the long-term operational FDO credential.

### 3.3 Key Lifecycle Across Ownership Changes

The preference order supports a natural identity lifecycle:

```
Manufacturing:
  TPM vendor burns IDevID into Endorsement hierarchy (locked)
  OEM optionally provisions DAK in Platform hierarchy

First Boot / Initial Onboarding:
  ROE finds DAK (priority 1) or falls back to IDevID (priority 3)
  TO2 completes, Owner has full system control

Post-Onboarding (Owner in control):
  Owner optionally creates LDevID (now priority 2 is populated)
  Owner optionally rewrites DAK (if policy allows)
  Owner generates new Ownership Voucher referencing chosen key
  IDevID returns to dormant -- still in TPM, still provable, not actively used

Resale / Re-provisioning:
  Owner wipes LDevID and/or DAK
  Device falls back to next available key in preference order
  New Owner onboards, cycle repeats
```

### 3.4 Who Provisions Each Key

| Key | Provisioning Entity | Typical Hierarchy | Rewritable? |
|-----|---------------------|-------------------|-------------|
| **IDevID** | TPM vendor or platform manufacturer | Endorsement | No (permanent hardware identity) |
| **DAK** | OEM, supply chain entity, or end user | Platform or Owner (provisioner's choice) | Policy choice of the provisioning entity |
| **LDevID** | Current device Owner/operator | Owner | Yes, by design (TCG DevID spec) |

The spec does not mandate which hierarchy is used for DAK or LDevID. The
provisioning entity selects the hierarchy appropriate to their role and
security requirements. The spec mandates only the NV index locations and data
formats so that FDO software can discover and use the keys.

---

## 4. Credential Reuse Pathways

After a successful TO2 onboarding, there are two primary pathways for enabling
subsequent re-onboarding (credential reuse):

### 4.1 Pathway A: Rewrite the DAK

The Owner (or Owner-installed software) writes a new DAK Unique String to the
NV index, causing a new DAK to be derived inside the TPM. A new Ownership
Voucher is generated referencing the new DAK's public key. The old Ownership
Voucher is cryptographically invalidated (the HMAC computed from the old
credentials will not match).

**Requirements:**

- DAK NV index must be writable by the Owner hierarchy (or by the FDO client
  application via authValue)
- The entity performing the rewrite must have access to the TPM's HMAC
  operation to generate the new Ownership Voucher
- The new Ownership Voucher must be generated on the device (the HMAC secret
  cannot be extracted from the TPM)

**Implication for spec:** Providers SHOULD allow DAK NV indices to be rewritten
by the Owner hierarchy post-onboarding. Locking DAK against rewrite effectively
prevents credential reuse through this pathway. This should be a conscious,
documented policy choice -- not a default.

### 4.2 Pathway B: Create an LDevID

The Owner creates an LDevID in the TPM and updates DCTPM to set
`DeviceKeyType=2` and `DeviceKeyHandle` to the LDevID's handle. A new
Ownership Voucher is generated referencing the LDevID's public key.

The management of LDevID keys -- including how they are created, whether a
certificate is issued, and by what CA -- is entirely governed by the TCG DevID
specification and is outside the scope of this spec. FDO does not inspect or
validate device key certificates during protocol execution. It uses the key at
the referenced handle for signing and verifies the HMAC binding to the
Ownership Voucher. If the Owner mints a key, places it in the LDevID slot, and
references it in a new Ownership Voucher, that is sufficient for FDO's
purposes.

**Requirements:**

- DCTPM NV index must be writable to update DeviceKeyType and DeviceKeyHandle
- The entity performing the update must have access to the TPM's HMAC operation
  to generate the new Ownership Voucher

**Implication for spec:** This pathway follows TCG-standard practices for
owner-provisioned identity. It does not touch the manufacturer's DAK or IDevID.
It provides clean separation of identities across successive owners. This spec
does not define or constrain how LDevID keys are managed -- that is the Owner's
business, per TCG processes.

### 4.3 Operational Note: New Ownership Voucher Generation

Both pathways require generating a new Ownership Voucher after changing the
device key reference. This operation requires:

1. The new device key's public key / certificate
2. The ability to compute an HMAC inside the TPM (the HMAC secret cannot leave
   the TPM)
3. Writing updated credential data (GUID, RVInfo, PubKeyHash) to the DCTPM NV
   index

Because the HMAC secret is non-exportable, the new Ownership Voucher MUST be
generated by an entity with TPM access -- typically the Owner's management
agent or FDO client running on the device. This is a natural consequence of the
TPM security model and should be explicitly noted in the spec.

### 4.4 Unique Strings and Key Rotation Mechanics

The spec's mechanism for key rotation relies on **Unique Strings** -- random
values stored in NV indices (`0x01D10003` for HMAC, `0x01D10004` for Device
Key) that are fed into the `TPM2_CreatePrimary` template's `Unique` field. The
primary key derivation is: `Primary Seed + Template + Unique String = Key`.
Writing a new random Unique String and calling `CreatePrimary` produces a
deterministically different key.

The current spec mandates (SHALL) that a Unique String always be used when
creating the FDO Device Key (section 4.6). This proposal amends this as
follows:

**Unique Strings SHOULD be used. They are REQUIRED if key rotation is desired,
OPTIONAL if the provisioning entity does not intend to rotate the key.**

Rationale: A manufacturer provisioning the initial DAK may have no need for
rotation -- the key is burned once, and any subsequent identity change will
use a different key type (LDevID) or a fresh DAK provisioned by the new Owner.
Requiring a Unique String in this case consumes NV storage (32-96 bytes
depending on algorithm) for a capability that will never be used. On the other
hand, any entity that intends to support credential reuse via DAK rewrite
(Pathway A) MUST use a Unique String, because rotation is impossible without
one.

**Unique String security properties:**

- **Erasing a Unique String does not "roll back" the key.** If a key was
  created with Unique String U1 (`Seed + Template + U1 = Key_A`), and the
  string is erased (zeroed), `CreatePrimary` with zeros produces a different
  key (`Seed + Template + zeros = Key_B`), not Key_A. The original key is
  irrecoverable unless U1 is restored.

- **Exception:** If the original key was also created with zeros/empty (no
  Unique String), then erasing returns to the same derivation and the same key.
  This is a rollback risk only in the degenerate case where rotation was never
  used.

- **Modifying the Unique String requires NV write access.** Under the current
  spec, Unique String NV indices are Profile B (`OWNERWRITE=0`,
  `PLATFORMCREATE=1`), so modification requires Platform auth or authValue.
  Under the proposed amendment, the protection level is a policy choice --
  but in all cases, only an entity with authorized NV write access can trigger
  key rotation. This is not a meaningful attack surface: any entity that can
  write the Unique String NV index already has sufficient TPM access to perform
  far more consequential operations.

- **The Unique String itself is not secret.** It influences key derivation
  but does not need to be confidential. The TPM's key derivation function
  ensures that knowing the Unique String does not help an attacker extract the
  private key. The Unique String needs integrity protection (to prevent
  unauthorized rotation), not confidentiality.

---

## 5. Revised Security Model

### 5.1 Pre-Onboarding: Credential Integrity

Before the first successful TO2, FDO credential integrity is critical. The
device has not yet been claimed by an Owner, and the credentials must be intact
for onboarding to succeed.

**Existing protections that are sufficient:**

- **TPM key protections:** The Device Key (DAK, LDevID, or IDevID) is created
  with `fixedTPM=1`, `fixedParent=1`, `sensitiveDataOrigin=1`. The private key
  cannot be extracted from the TPM. This is the fundamental provenance
  guarantee and is independent of NV index protection.

- **HMAC binding:** The Ownership Voucher contains an HMAC computed over the
  device credentials using the HMAC secret inside the TPM. If an attacker
  modifies NV credential data but cannot control the HMAC key, the HMAC will
  not match the Ownership Voucher and TO2 will fail. Tamper is
  cryptographically detectable.

- **Platform hierarchy protection:** NV indices created with
  `TPMA_NV_PLATFORMCREATE=1` can only be deleted by Platform authorization.
  The manufacturer controls Platform hierarchy during the pre-onboarding
  window. This provides supply-chain protection without requiring elaborate
  ROE mechanisms.

**What the spec should NOT mandate for this phase:**

- A specific TPM hierarchy for key creation (let the provisioning entity
  choose)
- Elaborate NV index authValue schemes (the HMAC binding already provides
  tamper detection)

### 5.2 At Onboarding Time: Proving Provenance

During TO2, the critical security property is: the device can prove that its
Device Key genuinely resides in this TPM and corresponds to the public key in
the Ownership Voucher.

This is proven by the device signing protocol messages with the Device Key. The
TPM guarantees this signature can only be produced by the TPM that holds the
key. This property depends entirely on the TPM's key protections -- not on NV
index access controls.

The HMAC verification confirms that the credential data (GUID, RVInfo,
PubKeyHash) has not been tampered with since the Ownership Voucher was created.
This is computed inside the TPM and verified by the Owner.

### 5.3 Post-Onboarding: Owner Has Full Control

After a successful TO2:

- The Owner has been mutually authenticated via the Ownership Voucher
- The Owner has full system control via FSIM (can install software, configure
  system, provision additional credentials)
- The Owner can replace the ROE software, reflash the OS, or wipe the device
- The Owner can cause credential reuse (re-onboarding) or credential deletion

**Therefore:**

- The Owner hierarchy SHOULD have read and write access to all FDO credential
  NV indices after onboarding
- The FDO Active flag already follows this model (`OWNERWRITE=1`,
  `OWNERREAD=1`); the same pattern should extend to DCTPM and key Unique
  Strings
- The spec should explicitly state that post-onboarding credential management
  is the Owner's prerogative, including the right to:
  - Rewrite the DAK for credential reuse
  - Create an LDevID to replace the onboarding key
  - Wipe all FDO credentials to decommission FDO
  - Wipe the IDevID in favor of an LDevID for privacy (see section 6)

### 5.4 Threat Model Clarification

The current spec's implicit threat model -- "protect FDO credentials from all
non-ROE access at all times" -- conflates two distinct concerns:

| Concern | Pre-Onboarding | Post-Onboarding |
|---------|----------------|-----------------|
| **Supply chain tampering** | Real threat. Mitigated by TPM key protections and HMAC binding. | Not applicable -- Owner has full control. |
| **Malware modifying credentials** | Low risk (device has generic OS image, limited attack surface). | If malware has root access, the system is already fully compromised. Protecting FDO credentials does not meaningfully improve security posture. |
| **Credential theft / extraction** | Device Key private material is always protected by TPM hardware (`fixedTPM=1`). | Same. NV index access controls do not add protection for key material. |
| **Unauthorized re-onboarding** | Requires valid Ownership Voucher AND matching HMAC. NV tampering alone is insufficient. | The Owner authorizes re-onboarding by setting Active=True and providing a valid OV. |

The meaningful security boundary is the TPM's own key protections (hardware
enforced, non-extractable keys). NV index access controls provide a secondary
layer that is useful pre-onboarding but should not obstruct legitimate
post-onboarding operations.

---

## 6. Privacy and Identity Lifecycle

### 6.1 IDevID as Bootstrap, Not Operational Identity

IDevID is the permanent hardware identity -- analogous to a birth certificate.
It proves manufacturing provenance but should not be the long-term FDO
credential referenced in Ownership Vouchers that circulate through the supply
chain.

The proposed key preference order supports a model where IDevID serves as a
**bootstrap identity**:

1. IDevID is used for the initial onboarding when no DAK or LDevID exists
2. After onboarding, the Owner provisions a DAK or LDevID
3. A new Ownership Voucher is created referencing the DAK/LDevID
4. IDevID returns to dormant state -- still in the TPM, still provable if
   needed, but not referenced in the active OV
5. On resale, the Owner wipes the DAK/LDevID; the device falls back to IDevID
   for the next onboarding
6. The cycle repeats with the new Owner

IDevID is only visible to each new Owner during the brief initial onboarding
handshake, not in any persisted Ownership Voucher that circulates through
supply chain intermediaries.

### 6.2 LDevID for Owner-Scoped Privacy

LDevID provides cross-owner unlinkability:

- Owner 1 onboards with IDevID, issues LDevID-1, creates OV referencing
  LDevID-1
- On resale, Owner 1 wipes LDevID-1
- Owner 2 onboards with IDevID (brief exposure), issues LDevID-2, creates OV
  referencing LDevID-2
- Owner 1 cannot correlate via LDevID-1 (wiped), Owner 2 does not see
  LDevID-1

Each owner operates with their own LDevID. The IDevID is exposed only
momentarily during ownership transitions.

### 6.3 Factory Reset Scenarios

The key preference order and rewritable credentials enable several reset
scenarios:

**Soft Reset (wipe LDevID/DAK, keep IDevID):**

The device falls back to IDevID for the next onboarding. This is equivalent to
returning the device to its manufacturing identity. The previous Owner's
LDevID/DAK is erased, removing their identity from the device. The device can
be re-onboarded as if it came directly from the factory.

Privacy note: IDevID is a permanent identifier. If previous owners retained the
IDevID public key (from earlier Ownership Vouchers or onboarding logs), the
device is correlatable across owners via IDevID. This is acceptable when device
tracking is desired (e.g., enterprise asset management) and mitigated by the
LDevID model when privacy is required.

**Hard Reset (wipe everything, re-initialize):**

All FDO credentials are deleted, including DAK and potentially LDevID. The
device requires fresh Device Initialization (DI). If the IDevID is retained,
it can serve as the bootstrap key for re-initialization. If the IDevID is also
wiped (via `TPM2_ChangeEPS` or equivalent), the device has no provable identity
and must be treated as a blank device.

This is the strongest anonymity option: no previous owner or manufacturer can
correlate the device to its history. However, hardware provenance is also lost.
This tradeoff is appropriate for specific use cases (e.g., device
decommissioning, regulatory requirements for data destruction).

**Privacy-Preserving Resale (LDevID rotation):**

The selling Owner issues a transitional LDevID (or allows the buying Owner to
do so via FDO credential reuse), then wipes all previous LDevIDs. The new OV
references only the new LDevID. The selling Owner's identity is erased from the
device, and the buying Owner has a fresh owner-scoped identity.

This is the recommended approach when privacy across ownership boundaries is
required.

---

## 7. Proposed Architectural Changes (Summary)

### 7.1 What Remains Normative

The following elements remain normative (mandatory for compliance):

- **NV index handle assignments** (section 4.2): Standardized locations so FDO
  software can discover credentials
- **DCTPM CBOR structure** (section 4.5): Standardized data format for
  credential interchange
- **Key templates** (section 8.2): Standardized key properties (fixedTPM,
  sign-only, non-exportable) that provide the fundamental security guarantees
- **Key preference order**: DAK > LDevID > IDevID discovery and usage priority
- **DeviceKeyType enumeration**: Extended to explicitly enumerate DAK, LDevID,
  and IDevID with defined priority semantics

### 7.2 What Becomes Informative (Guidance, Not Mandate)

The following elements should be changed from normative to informative:

- **Hierarchy selection for key creation**: The current SHALL requirement for
  Endorsement hierarchy should become a MAY with guidance. The provisioning
  entity selects the hierarchy appropriate to their role (TPM vendor uses
  Endorsement, OEM uses Platform, end user uses Owner).
- **NV index protection attributes**: The current mandatory attribute tables
  (Tables 9, 11) should become recommended profiles for different deployment
  scenarios, not a single mandatory configuration.
- **ROE separation model**: The current normative requirements for logical or
  time-based ROE separation should become informative guidance. The spec should
  acknowledge that post-onboarding FDO operations may run as normal OS
  services.

### 7.3 What Is Added

- **Post-onboarding access model**: Explicit statement that after successful
  TO2, the Owner hierarchy SHOULD have read/write access to all FDO credential
  NV indices. The DCActive flag's existing attributes (`OWNERWRITE=1`,
  `OWNERREAD=1`) should be the model for all credential indices
  post-onboarding.
- **Key preference order**: Normative definition of DAK > LDevID > IDevID
  discovery and usage priority.
- **Credential reuse pathways**: Explicit documentation of the two pathways
  (DAK rewrite, LDevID creation) with operational requirements.
- **New Ownership Voucher generation**: Explicit note that new OV generation
  requires on-device TPM access (HMAC secret is non-exportable).
- **Privacy lifecycle guidance**: Informative section describing IDevID as
  bootstrap identity, LDevID for owner-scoped privacy, and factory reset
  scenarios.
- **Threat model clarification**: Explicit separation of pre-onboarding and
  post-onboarding security concerns, with clear statement of what TPM key
  protections already provide vs what NV index access controls add.

### 7.4 Roles and Responsibilities

| Role | Provisions | Hierarchy | Locks? | Survives TPM2_Clear? |
|------|-----------|-----------|--------|---------------------|
| **TPM Vendor** | IDevID, EK | Endorsement | Yes (permanent identity) | Yes (EPS-derived) |
| **Platform OEM** | DAK (optional), FDO NV indices | Platform | Policy choice | Yes (PLATFORMCREATE=1) |
| **Supply Chain** | DAK or credential updates | Platform or Owner | Policy choice | Depends on hierarchy |
| **Device Owner** | LDevID, credential reuse, Active flag | Owner | No (Owner needs ongoing access) | No (Owner hierarchy reset on TPM2_Clear) |

Each role operates within its natural hierarchy. The spec does not require any
role to borrow another role's hierarchy.

---

## 8. Open Questions for Working Group

1. **Should the spec define recommended NV attribute profiles for common
   deployment scenarios?** For example: "Manufacturing Profile" (PLATFORMCREATE,
   locked), "Enterprise Profile" (OWNERWRITE enabled), "Brownfield Profile"
   (minimal restrictions). This would provide actionable guidance without
   mandating a single configuration.

2. **Should DAK rewritability be SHOULD or MAY?** The proposal suggests
   providers SHOULD allow DAK rewrite. An alternative is MAY, with a note that
   locking DAK prevents credential reuse pathway A. The working group should
   decide based on the expected prevalence of credential reuse scenarios.

3. **Backward compatibility.** Implementations conforming to the current spec
   (Endorsement hierarchy, strict ROE model) should remain valid under the
   amended spec. The amendments should be additive -- relaxing mandates to
   allow additional deployment models without invalidating existing ones.

4. **Should the Active flag remain universally writable, or should its
   protection also become a policy choice?** The current design (empty
   authValue, OWNERWRITE=1) is convenient but means any OS-level process can
   toggle FDO on/off. Some deployments may want to restrict this.

5. **Handle and NV Index allocation (CRITICAL).** The current spec uses
   placeholder handle values (e.g., `0x01D10000`-`0x01D10005` for NV indices,
   `0x81020002`-`0x81020003` for persistent objects) that are appropriate for
   testing only. The spec itself notes: *"The values presented are appropriate
   for testing, but not for released products."* The current expectation is
   that TCG will delegate the range `0x01D10000`-`0x01D100FF` to FIDO, but
   FIDO has not yet developed governance around this allocation or determined
   how to record or disclose these decisions. **Final, officially assigned
   handle values and NV index ranges must be obtained from TCG and FIDO before
   this specification can move beyond draft status.** This includes handles for
   any new key types or NV indices introduced by this amendment (e.g., if the
   key preference order requires distinguishable handles for DAK, LDevID, and
   IDevID). This is a blocking prerequisite for any production implementation.

---

## 9. Next Steps

1. Review this high-level proposal within the working group
2. **Obtain formal handle and NV index allocations from TCG/FIDO** -- this is
   a prerequisite for finalizing the spec and must be initiated in parallel
   with the technical review
3. Draft specific normative and informative text changes to the spec sections,
   tables, and CDDL definitions identified above
4. Develop test vectors for the key preference order and credential reuse
   pathways
5. Validate against existing FDO TPM implementations for backward compatibility
