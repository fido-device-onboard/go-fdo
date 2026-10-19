# TODO List

## Status Summary

**Completed Major Tasks:**

- ✅ **CLI Documentation**: Comprehensive CLI_COMMANDS.md created with detailed command descriptions, examples, and real-world context
- ✅ **Voucher Management**: Full documentation of `-list-vouchers` and `-voucher-export` commands
- ✅ **Server/Client Configuration**: Complete documentation of all configuration options
- ✅ **Delegate & Attested Payload**: Documentation with references to specialized markdown files
- ✅ **Troubleshooting & Workflows**: Integrated troubleshooting guide and common workflow examples

**Progress: 9/13 High Priority tasks completed (69%)**

---

## High Priority

### UPSTREAMING ORDER — port the loop fix BEFORE any streaming FSIM

- [ ] **P1: upstream the device ServiceInfo loop fix before `fdo.payload` /
  `fdo.bmo` (or any FSIM that streams content).** The FDO 2.0 core PR
  (fido-device-onboard/go-fdo #285, from `fdo20-core` / `fdo20-core-split`
  in `~/go-fdo-merge-pr/go-fdo-core20`) does NOT have it: its `to2.go`
  `exchangeServiceInfo` buffers an owner's whole IsMoreServiceInfo run in
  `NewChunkInPipe(1000)`. Nothing in #285 triggers that (no streaming FSIMs),
  but the moment payload/BMO go upstream on top of it, any FDO 2.0 device
  receiving more than 1000 chunks hangs (seen 2026-10-14: Stage 2 ISO stopped
  at chunk 1000 and sat for five days).
  - What to port from `fdo20-merge3`: `exchangeServiceInfo` in `to2.go` (the
    `handle` closure: each round's owner info goes to the modules as it
    arrives, handlers chained per round) and `TestClientLongOwnerRunFDO20` in
    `fdo_test.go` (must hang without the fix, pass with it).
  - How: a small follow-up PR once #285 merges; fold it into #285 only if a
    review-driven rebuild happens anyway.
  - Gate: do not open the payload/BMO upstream PR until this is merged or
    included in it.
  - Background: "Protocol Defects" below (the FIXED 2026-10-20 entry).

### Documentation

- [✅] Create comprehensive CLI commands documentation (`CLI_COMMANDS.md`)
- [✅] Document voucher management commands with examples
- [✅] Document server configuration options
- [✅] Document client configuration options

- [✅] Document delegate commands and workflows
- [✅] Document attested payload commands
- [ ] Create CLI command reference cheat sheet

### Protocol Defects

- [x] **FIXED 2026-10-20 (uncommitted): device deadlocked after 1000 owner
  KVs in one `IsMoreServiceInfo` run.** Regression from `e85b7b4` (H4: the
  FDO 2.0 client moved onto the shared 1.1 loop). The shared loop buffered a
  whole owner run in `NewChunkInPipe(1000)` and handed it to the modules only
  when the run ended; the payload owner streams one chunk per message with
  `IsMoreServiceInfo=true`, so any payload over 1000 chunks hung (Stage 2
  ISO stopped at chunk 1000 = 60 MB). The old 2.0 loop processed each message
  as it arrived. Fix: `exchangeServiceInfo` (`to2.go`) now hands each round's
  owner info to the modules as it is received, chained after the previous
  round's handler so ordering is kept. Test: `TestClientLongOwnerRunFDO20`
  (1500-KV run; hangs without the fix). **The same regression is in the
  upstream PR #285 (fdo20-core-split `to2.go`).**

- [ ] **(Latent, post-FDO-2.0-merge work) Device-side delay when the owner
  stalls.** In the shared 1.1/2.0 device loop `exchangeServiceInfo`
  (`to2.go`, the upstream comment "TODO: Wait a few seconds if no service
  info was sent or received in the last round"), if the owner replies with
  no ServiceInfo and `IsDone=false` while the device also has nothing to
  send, the device sends the next `DeviceServiceInfo` immediately, with no
  delay. This shouldn't happen in normal use: no existing FSIM has the owner
  hold the conversation open with nothing to send. Only a stalled owner
  backend would trigger it. Pre-existing upstream; independent of any FSIM.
  Fix: in that case only, add a small device-side wait, backing off if it
  repeats. A slow *device* module does not trigger this, because the loop
  waits for the module before the next round. (Earlier text named
  `exchangeServiceInfo20` / `deviceDone`; those were merged into the shared
  loop by the 2.0 review fixes.)
  - `fdo.defer` `wait` (`DESIGN-PROPOSALS.md` §1) is probably **not**
    blocked by this: the owner sends a real `wait N` message and the device
    module does the waiting, so the device paces itself. The remaining
    concern there is whether the owner's session/HTTP state survives N
    seconds between requests. Unverified: that a device module may block
    for N seconds in its receive handler.

- [x] **FIXED 2026-10-08:** the name comparison is skipped only for the link
  to the synthesized Owner root (bound by signature against the Owner key);
  real links still match by name. Test: `TestDelegateChainUTF8OwnerName`
  (mutation-checked). Original report: **Delegate chains with a UTF8String (or multi-RDN) top issuer were
  rejected** (found 2026-10-08 via go-fdo-meta-tool Test 26).
  `processDelegateChain` (`delegate.go` ~374) synthesizes an ephemeral Owner
  root via `GenerateDelegate(..., issuer.CommonName, ...)`, then requires
  `bytes.Equal(chain[i].RawIssuer, chain[i+1].RawSubject)` (~425). Go encodes
  the rebuilt name as PrintableString `CN=x`; OpenSSL (and RFC 5280) use
  UTF8String, and real CAs have O=/C=. So OpenSSL-issued delegate chains fail
  whenever an Owner key is supplied — BMO x5chain, meta x5chain, and TO2
  delegates alike. Fix: give the synthesized root the top cert's exact
  `RawIssuer` (or skip the name comparison for the synthesized link — its
  signature check already binds it to the Owner key). go-fdo's own tests use
  go-fdo-generated certs, which is why this was never seen. fdo-uefi-rs is
  not affected (issuers are matched by signature only).
- [ ] **Owner side never checks `ProveDevice20.hashPrev2`** (Errata 1 made it
  well-defined; the device side checks `hashPrev`). `to2_server_v200.go`.
- [ ] **Owner does not reassemble a ServiceInfo value split across
  messages** (found 2026-10-14 with standalone `payload-log-*`). The device
  chunker (`serviceinfo.ChunkReader`) splits a KV value wherever a
  `DeviceServiceInfo` fills up and continues it, same key, in the next
  message with `IsMoreServiceInfo=true`. `ServiceInfoProcessor`
  (`service_info_processor.go`) unchunks each message on its own, so the
  owner module gets a truncated value (here: "failed to decode chunk data:
  unexpected EOF" for any device log over ~13 KB). Worked around in the
  device FSIM: `sendLogBody` (`fsim/payload_device.go`) packs chunks so no KV
  straddles a message (`TestSendLogBodyPacksMessages`). Any other device
  module that sends more than one message's worth in a round hits the same
  bug. Related trap: a `yield()` while the current message is still empty
  makes `exchangeServiceInfoRound` end the round (`IsMoreServiceInfo=false`)
  and everything written after it is lost.

### Code Quality

- [✅] Fix goimports formatting issues in examples/cmd/client.go
- [ ] Add comprehensive error handling for CLI commands
- [ ] Add input validation for CLI flags

- [ ] Improve help text consistency across commands

### Testing — Four Provisioning Security Models

See `provisioning-security.md` for the narrative. The four models are:

1. **Owner service, unsigned payloads** — channel authority, Owner runs the service
2. **Delegate service, unsigned payloads** — channel authority, PERM.7 delegate runs the service
3. **Owner-signed payloads** — artifact authority, Owner signs, any (onboard) service delivers
4. **Delegate-signed payloads** — artifact authority, PERM.7 delegate signs, any service delivers

#### Status Matrix (go-fdo library + server + device)

| Model | Library | Server | Unit tests | Integration test | Negative integration |
| --- | --- | --- | --- | --- | --- |
| 1 | **Working** (Owner-direct unsigned accepted — channel authority) | Works (omit `-bmo-sign`) | unwrap tests + `TestUnsignedProvisioningAllowed_Matrix` | **`bmo-owner-unsigned`** | `bmo-delegate-unsigned-noperm` (onboard-only peer) |
| 2 | **Implemented** (delegate PERM.7 → accept unsigned) | Works (`-onboardDelegate` with PERM.7 chain) | 6 unwrap tests | **`bmo-delegate-unsigned`** | **`bmo-delegate-unsigned-noperm`** |
| 3 | Implemented | `-bmo-sign` works | Yes (5 tests) | **`bmo-signed`** | Unit: tampered / wrong key / wrong content type |
| 4 | Implemented | `-bmo-delegate-provision` works | Yes (3 tests) | **`bmo-delegate-provision`** | None |

#### Completed testing tasks

- [x] **Model 2 implementation**: Added `DelegateCanProvision()`, context plumbing
  (`WithDelegateProvisionAuthority` / `DelegateProvisionAuthorityFromContext`),
  threaded through both FDO 1.01 and 2.0 TO2 paths. `unwrapProvisioning` now
  accepts unsigned BMO when the TO2 peer proved PERM.7 delegate authority.
  6 unit tests + 2 integration tests (positive + negative).
- [x] **Model 4 integration test** (`test_bmo_delegate_provision`): Generates an
  Owner-rooted PERM.7 delegate chain, starts server with `-bmo-delegate-provision`,
  delivers BMO image, verifies payload integrity.
- [x] **Model 1 resolved (2026-10-02)**: The spec now states channel authority
  is REQUIRED and enabled by default (chunking-strategy.md §Channel Authority),
  so unsigned provisioning from the Owner itself MUST be accepted. The device
  previously rejected it whenever the Owner key was known, because the single
  `delegateHasProvision` bool could not distinguish Owner-direct from an
  onboard-only delegate. Replaced with `fdo.PeerAuthority`
  (`PeerOwnerDirect` / `PeerDelegateProvision` / `PeerDelegateOnboardOnly` /
  `PeerUnknown`), set from how ProveOVHdr was verified in both the 1.01 and 2.0
  TO2 paths; decision logic in `unsignedProvisioningAllowed`. The old
  `bmo-signed-negative` test (which asserted the non-compliant behaviour) is
  replaced by `bmo-owner-unsigned` (positive). `WithDelegateProvisionAuthority`
  / `DelegateProvisionAuthorityFromContext` kept as deprecated wrappers.
  Audit note: go-fdo was **not** vulnerable to the fdo-uefi-rs H4 bug
  (onboard-only delegate accepted) — it erred the other way.

- [x] **Delivery/authorization restructure (2026-10-02)**: generic delivery
  keys 5–9 (legacy -6..-10 aliases), meta-payload authentication (named
  signer / Owner / PERM.7 x5chain), D2/D3 fetched-content rules, generic
  artifact verification with fail-closed scope (`"fdo.scope"`), error codes
  9–19 — all in `fsim/chunking`. Also fixed: `DelegateHasPermission` was
  leaf-only (now every cert); BMO x5chain lacked CA/permission-chain checks;
  device ignored scope; URL/meta delivery accepted unauthenticated content.
  See fdo-uefi-rs/TODO.md PRIORITY section for full detail and test list.

#### Remaining testing tasks

- [x] `fdo.payload` device-side authorization (2026-10-02): `payload-begin`
  gated via shared `authorizeGated`; owner signing (`-payload-sign`);
  delivery modes; begin hash in unified + streaming modes. Tests unit +
  `payload-signed` / `payload-delegate-noperm`. Also fixed 5 payload
  integration tests that compared the source file with itself.
- [x] Removed dead `BMO.MetaPayloadVerifier` + interface; kept `CoseSign1Verifier` (used by go-fdo-meta-tool) as a wrapper over `chunking.VerifyMetaPayload`.

- [~] **Model 4 negative variants**: Wrong root, missing PERM.7, tampered delegate
  signature. Covered by unit tests (3 tests in `bmo_provision_test.go`). Integration
  tests are impractical because the server validates the delegate chain at startup
  (`initBMOProvisioningSigner`) — it refuses to start with a bad chain. A separate
  "bypass the guard" test harness would be needed, which is more test infrastructure
  than the risk warrants. The server startup failure IS the negative test at the
  integration level (demonstrated by `start9-delegate-signed.sh --no-provision`
  on the EFI client).
- [x] **Pre-signed artifact delivery** (2026-09-23): `BMOOwner.AddPreSignedImage()`
  accepts a pre-signed COSE_Sign1 body and delivers it as-is as the image-begin
  message. Server CLI: `-bmo-presigned type:cose_file:image_file`. This supports
  offline/HSM signing workflows where `fdo-meta-tool provision sign` (or similar)
  creates the signed artifact. Integration test: `bmo-presigned`.
- [x] **Scope emission** (2026-09-23): Server CLI flags `-bmo-scope-not-before`,
  `-bmo-scope-not-after`, `-bmo-scope-generation` added. When any scope flag is set
  alongside `-bmo-sign` or `-bmo-delegate-provision`, the scope is included in the
  COSE protected header. Integration test: `bmo-signed-scope`. EFI client parses
  and evaluates scope (QEMU test: `start13-bmo-signed-scope.sh`).
- [x] **Fix: BIOS params never sent** (2026-09-23): `bmo_owner.go` `produceInfo`
  had an early `moduleDone=true` return at line 263 when all images were done,
  before reaching the BIOS params sending code. Fixed by checking for pending
  BIOS params before returning done. Also fixed BIOS send state: all params sent
  in one message, so `biosParamIndex` advances to `len(biosParams)` immediately.

### Testing — General

- [✅] Integration tests working (basic, basic-reuse, kex tests passing)

- [ ] Add integration tests for voucher management commands
- [ ] Add CLI command unit tests
- [ ] Test edge cases for voucher export (empty database, invalid GUIDs, etc.)

## Medium Priority

### Features

- [ ] Add voucher search by date range
- [ ] Add voucher export in multiple formats simultaneously
- [ ] Add batch voucher operations

- [ ] Add voucher statistics and reporting
- [ ] Add voucher validation commands

### Documentation

- [ ] Update README.md with CLI command examples
- [✅] Create troubleshooting guide for CLI commands
- [✅] Document common CLI workflows and use cases
- [ ] Add CLI command migration guide from old methods

## Low Priority

### Enhancements

- [ ] Add CLI command completion scripts
- [ ] Add interactive CLI mode
- [ ] Add CLI configuration file support
- [ ] Add CLI command aliases for common operations
- [ ] Add progress indicators for long-running operations

### Documentation

- [ ] Create video tutorials for CLI commands
- [ ] Add CLI command performance benchmarks
- [ ] Document CLI command integration with other tools
- [ ] Create CLI command API documentation

---

## Design Proposals (see DESIGN-PROPOSALS.md)

- [ ] **Deferred Onboarding ("Delay" FSIM)** — mechanism for server to tell device "I own you but have nothing for you yet; retry later." Requires design of retry/wait/abort semantics, interaction with credential reuse, and backoff strategy.
- [ ] **Delegated Payload Attestation** — separate TO2 transport authority from payload signing authority. Allows third-party delivery services to mechanically run TO2 without being trusted to choose/modify payloads. Builds on existing attested payload and delegate certificate infrastructure. Requires new `provision` OID and payload signature verification at the device.

## Notes

- The voucher management commands (`-list-vouchers`, `-voucher-export`) were recently added and need comprehensive documentation
- The `-db` flag is now shared between client and server commands
- All CLI commands should follow consistent flag naming conventions
- Error messages should be user-friendly and actionable
