# Design Proposals

Copyright &copy; 2026 Dell Technologies and FIDO Alliance
Author: Brad Goodman, Dell Technologies

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

---

This document captures design proposals for protocol and FSIM extensions
that require significant design work before implementation.  Each proposal
is at the *idea* stage -- the intent and motivation are well understood, but
the wire format, FSIM boundaries, and failure semantics are not yet decided.

---

## 1. Deferred Onboarding (`fdo.defer` FSIM)

### Problem

A device completes TO2 authentication with a server that holds its voucher,
but the server does not yet have installation instructions (no BMO image, no
autoinstall config, no payload) for this particular device.  Today the only
options are:

- **Server rejects TO2** -- the device retries, but there is no standard way
  to communicate "come back later" vs "you are not authorized."
- **Server completes TO2 with empty ServiceInfo** -- the device considers
  onboarding successful but received nothing, leaving it in an undefined
  state.

Neither is satisfactory.  The server needs a way to tell the device:
"I know you, I own you, but I'm not ready for you yet."

### Desired Behaviour

The server should be able to tell the device one of:

| Strategy | Description |
| -------- | ----------- |
| **Retry later** | "Abort this TO2 session and come back in N seconds." The device re-enters the TO1/TO2 loop after a delay. Credential state is unchanged. |
| **Wait** | "Stay in this session and ask me again in N seconds." Note that the owner cannot push: ServiceInfo is strict request/response, each round is a separate HTTP request, and session continuity is the bearer token rather than the socket. This is device polling with an owner-supplied pace, not a long poll. |
| **Abort with reason** | "TO2 is complete but I have nothing for you. Here is a machine-readable reason code and optional human message." The device logs it and may retry on next boot or enter a dormant state. |

### Resolution

Design settled; specified as the `fdo.defer` FSIM in
`fdo-sim/fsim-repository/fdo.defer.md`.  Summary of the decisions and why:

- **FSIM, not protocol-level.**  Deferral presupposes that mutual
  authentication already succeeded, so ServiceInfo is a sufficient carrier
  and no new message type or `EMErrorCode` is needed.  More importantly,
  FDO already provides the capability negotiation this requires --
  `devmod:modules` plus `<module>:active` -- so a device that does not
  support deferral simply never sees it.
- **A dedicated module, not a key in the chunking strategy.**  Chunking is
  per-payload transport framing; deferral is a per-session disposition.
  Had every chunked FSIM been able to emit a retry directive, a session
  with `fdo.payload` + `fdo.credentials` + `fdo.sysconfig` active could
  produce three conflicting directives with no defensible reconciliation
  rule.  One module yields exactly one directive per session by
  construction.
- **Not in devmod.**  devmod is device-to-owner inventory; an
  owner-to-device directive inverts its semantics.  devmod is also base-spec
  rather than FSIM-repository, making it a far heavier change.
- **Two actions.**  `retry` (complete TO2, come back from TO1 after N
  seconds) is mandatory.  `wait` (stay in session, poll again after N
  seconds) is optional for owners and degrades to `retry` on devices that
  do not implement it.  `wait` is specified now rather than deferred
  because the party that cannot be retrofitted is the *device* -- firmware
  shipped without it could not use it until fleet turnover.
- **The owner never publishes a module manifest**, so an owner that defers
  names no other module on the wire.  There is no activation-ordering
  problem to solve.

### Credential State

Rotation exists to sever the reachability of the manufacturing and
distribution chain, and to effect genuine ownership transfer.  Neither
applies to a deferred session.  The defensible model is three-state:

| Event | Action | Rationale |
| ----- | ------ | --------- |
| First onboarding | Rotate | Severs manufacturer/reseller reachability |
| Subsequent onboardings | Reuse | Still the same owner; rotation is churn |
| Offboarding | Rotate | Actual ownership transfer |

`fdo.defer` therefore requires the owner to have selected credential reuse
in `TO2.SetupDevice`.  This was initially thought to be a hard ordering
problem, since `SetupDevice` precedes the ServiceInfo exchange and
`ReuseCredential` receives only the voucher.  It is not: the voucher
carries the GUID, and "do I have configuration for this GUID?" is exactly
the question the deferral branch turns on.  The same lookup simply runs one
message earlier.

Note that `go-fdo` is currently inconsistent here -- the 2.0 server falls
back to reuse when no callback is set (`to2_server_v200.go`), while the
example CLI defaults `-reuse-cred` to false.

### Security Consideration: Supply-Chain Exposure Window

Because deferral on first contact implies reuse, the device keeps
supply-chain-reachable credentials for the duration of the deferral --
rotation at first onboarding is what would ordinarily sever that.
Negligible for short deferrals, material for multi-day ones.  Owners should
bound total deferral time for devices that have not yet completed a first
successful onboarding.

### Interaction with BMO

BMO is terminal, so a deferral and a successful boot are mutually
exclusive.  The fallback for an unresolved deferral -- and for a device
with no deferral support at all -- is the **no-op completion** rule now
specified in `fdo.bmo.md`: completion is a function of work performed, not
protocol outcome, so a session in which nothing was installed or applied
must not be recorded as successful onboarding.

Firmware-resident implementations should prefer `retry` over `wait`, since
a device deferring from inside a chainloaded UKI holds RAM and blocks
normal boot for the duration.

### Related

- `fdo-sim/fsim-repository/fdo.defer.md` -- the specification.
- `fdo-sim/fsim-repository/fdo.bmo.md` -- no-op completion rule.
- Credential reuse protocol (`-reuse-cred`).
- TO1/TO2 retry logic in `go-fdo-endpoint/main.go` `transferOwnership()`.
- Unthrottled device polling once `deviceDone` is set
  (`to2_client_v200.go`) -- see `TODO.md`.  This is a defect independent of
  deferral, but it makes `wait` unsafe to implement until fixed.

---

## 2. Delegated Payload Attestation

### Concept

Separate the two distinct roles currently conflated in the FDO owner service:

1. **Transport (Onboarding)** -- mechanically executing the TO2 protocol,
   delivering bytes to the device.
2. **Authority (Provisioning)** -- deciding *what* gets installed, and
   attesting that the payload is authorized by the device owner.

A device owner should be able to delegate the mechanical transport of
payloads to a third-party service (cloud provider, CDN, managed service)
WITHOUT trusting that service to choose or modify what gets delivered.  The
payloads themselves carry signatures from an entity with "provision"
authority -- either the owner key directly, or a delegate certificate
carrying `OIDPermitProvision`.

The core principle: **the device does not trust the onboarding service
implicitly.  It trusts owner-signed (or provision-delegate-signed) payloads
independently of who delivered them.**

### Delegate Permission OIDs

The OID hierarchy under `1.3.6.1.4.1.45724.3.1` (defined in `delegate.go`)
already cleanly separates onboarding from provisioning:

| OID | Name | Permission |
| --- | ---- | ---------- |
| PERM.2 | `OIDPermitOnboardNewCred` | Can run TO2 (new credential) |
| PERM.3 | `OIDPermitOnboardReuseCred` | Can run TO2 (credential reuse) |
| **PERM.7** | **`OIDPermitProvision`** | **Can sign provisioning payloads** |

These are distinct by design.  A CDN with an `onboard` delegate cert can
execute TO2, but the device will reject provisioning payloads unless they
carry a separate `provision` signature.  The CDN cannot forge provision
signatures because it does not possess the owner key or a provision-delegate
private key.

### What Already Exists

Significant infrastructure for this model is already implemented and tested:

**BMO Authenticated Provisioning** (`fsim/bmo_provision.go`):

- `ProvisioningSigner` interface -- owner or delegate signs BMO messages
  (image-begin, set) as tagged COSE_Sign1 (CBOR tag 18).
- `OwnerSigner` -- signs directly with owner key.
- `DelegateSigner` -- signs with delegate key, embeds x5chain in COSE
  unprotected header.  Enforces leaf cert carries `OIDPermitProvision`.
- `VerifyBmoSigned()` -- device-side verification: checks COSE_Sign1
  signature, validates delegate chain back to TO2-proven owner key, verifies
  leaf has `OIDPermitProvision`.
- `unwrapProvisioning()` in `bmo_device.go` -- dispatches to verification
  for tagged COSE_Sign1 messages; rejects unsigned messages when owner key
  is configured (spec-compliant mode).
- Error code 15 (`BMOErrorProvisionNotAuthorized`) -- returned when
  provisioning verification fails.
- Domain-separated AAD (`cose.AADBmoProvision`) -- prevents cross-use of
  signatures between BMO and other COSE contexts.
- Server CLI: `-bmo-sign` (owner signs), `-bmo-delegate-provision
  cert.pem:key.pem` (delegate signs with provision OID).
- Full test coverage in `bmo_provision_test.go`.

**Attested Payloads** (`attested_payload.go`, `attestedpayload.md`):

- Standalone payload signing: owner-signed or delegate-signed `.fdo` files.
- Delegate chain verification requiring `OIDPermitProvision`.
- Encrypted payloads (RSA-OAEP wrapped AES key).
- Validity controls (expiration, generation/supersession).
- Offline signing -- owner signs payloads on air-gapped HSM, hands `.fdo`
  files to any delivery mechanism.
- CLI tooling: `attestpayload create` / `attestpayload verify`.

### Architecture: CDN / Third-Party Delivery

The device owner (or a provision delegate operating on the owner's behalf)
signs all provisioning assets offline:

- BMO boot image (COSE_Sign1 tagged image-begin)
- Autoinstall config (attested payload)
- ISO image (attested payload or signed manifest)
- SSH host keys (attested payload)

These signed assets are uploaded to a CDN or third-party delivery service.
The CDN holds only an `onboard` delegate certificate -- enough to run TO2
and establish the encrypted ServiceInfo channel, but NOT enough to sign
provisioning payloads.

During TO2, the device:

1. Authenticates the CDN via its onboard delegate credential (TO2 auth).
2. Receives provisioning payloads via ServiceInfo (BMO, fdo.payload, etc.).
3. Independently verifies each payload's COSE_Sign1 signature against the
   owner key (or a provision-delegate chain rooted at the owner key).
4. Rejects any payload lacking a valid provision signature, even though the
   TO2 session itself was authenticated.

If the onboarding service does NOT hold the owner key and only has an
onboard delegate cert, the device will not trust any of its provisioning
payloads (BMO, fdo.payload, fdo.credentials) unless they independently
carry owner-signed or provision-delegate signatures.

This is the same trust model as code signing in package managers: the
mirror/CDN delivers packages, but the device verifies GPG/Sigstore
signatures from the publisher.

### What Remains To Do

The BMO FSIM path is largely complete.  The gaps are in extending this
pattern to the other FSIMs and making the end-to-end CDN flow operational:

**Gap 1: `fdo.payload` attestation** -- BMO image-begin messages are
already wrapped in COSE_Sign1.  But `fdo.payload` (which delivers
autoinstall configs, ISOs, etc.) has no equivalent signing mechanism.  The
device currently trusts whatever the TO2 session delivers via `fdo.payload`.

Don't think of this as signing individual FSIM messages.  Think of it as
the device owner signing *assets* -- "this specific installer image," "this
specific autoinstall config," "these SSH keys" -- and handing those signed
assets to the CDN in a wrapper that says "I am authorizing THIS to be put
on THIS device."  The CDN conveys them; the device independently verifies
the owner's (or provision delegate's) signature.

Options for large payloads (2.8GB ISO): sign a manifest of block hashes
rather than the entire payload.  Device verifies blocks against the signed
manifest during streaming.

**Gap 2: `fdo.credentials` attestation** -- SSH keys and other credentials
delivered via `fdo.credentials` are currently trusted implicitly.  In a
delegated model, these should also carry provision signatures.

**Gap 3: `fdo.sysconfig` attestation** -- System configuration (hostname,
timezone, DNS) similarly needs attestation in a zero-trust delivery model.

**Gap 4: End-to-end CDN workflow tooling**:

- **Packaging tool** -- given a set of assets (ISO, autoinstall YAML, SSH
  keys, BMO image), produce a signed bundle that a CDN can deliver without
  modification.
- **CDN server mode** -- the go-fdo server needs a mode where it loads
  pre-signed payloads and delivers them without re-signing (it has only an
  onboard delegate, not a provision key).
- **Device-side policy** -- configuration option on endpoint/EFI client:
  "require provision signatures on all payloads" vs "accept unsigned
  payloads from authenticated TO2 sessions" (backward compat).

### Related Implementation

| File | What it does |
| ---- | ------------ |
| `delegate.go` | OID definitions including `OIDPermitProvision` (PERM.7) |
| `fsim/bmo_provision.go` | `ProvisioningSigner`, `DelegateSigner`, `VerifyBmoSigned` |
| `fsim/bmo_device.go` | `unwrapProvisioning()`, `OwnerPublicKey` trust anchor |
| `fsim/bmo_owner.go` | Server-side signing of BMO messages |
| `fsim/bmo_provision_test.go` | Tests: owner-signed, delegate-signed, wrong key, wrong OID |
| `attested_payload.go` | Standalone attested payload create/verify with delegate support |
| `attestedpayload.md` | Attested payload format specification |
| `delegate.md` | Delegate certificate creation and CSR workflows |
| `fdo.bmo.md` | BMO spec including "Authenticated Provisioning" section |

---

## Discussion

These two proposals are independent but complementary:

- **Deferred Onboarding** addresses the operational reality that not every
  device has a provisioning profile ready the moment it first contacts the
  owner service.
- **Delegated Payload Attestation** extends the existing BMO provision
  signing to ALL FSIMs, enabling a full zero-trust CDN delivery model where
  the device owner can hand off signed assets to any delivery service and
  devices independently verify payload authority.

The Deferred Onboarding proposal is now specified (`fdo.defer.md`) and
awaits implementation.  The Delegated
Payload Attestation proposal is largely an extension of existing, tested
infrastructure (BMO signing, attested payloads, delegate OIDs) to cover the
remaining FSIMs (`fdo.payload`, `fdo.credentials`, `fdo.sysconfig`) and
provide end-to-end CDN workflow tooling.
