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

### Documentation

- [✅] Create comprehensive CLI commands documentation (`CLI_COMMANDS.md`)
- [✅] Document voucher management commands with examples
- [✅] Document server configuration options
- [✅] Document client configuration options

- [✅] Document delegate commands and workflows
- [✅] Document attested payload commands
- [ ] Create CLI command reference cheat sheet

### Protocol Defects

- [ ] **Throttle the device ServiceInfo poll loop.** In
  `exchangeServiceInfo20` (`to2_client_v200.go`), once `deviceDone` is set
  the loop skips the chunk-read branch entirely -- including its
  `time.Sleep(10ms)` -- and so re-sends an empty `DeviceServiceInfo` as
  fast as the network allows for as long as the owner keeps the exchange
  open. Any owner that stalls, deliberately or from a slow backend, is
  hammered by its own devices. Needs a minimum inter-round delay on the
  device side. This is a defect today, independent of deferred onboarding,
  but it also blocks the `wait` action of the proposed `fdo.defer` FSIM --
  see `DESIGN-PROPOSALS.md` §1.

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
|---|---|---|---|---|---|
| 1 | Working (unsigned rejected unless delegate has PERM.7) | Works (omit `-bmo-sign`) | 6 unwrap tests | `bmo` (positive) | `bmo-signed-negative` |
| 2 | **Implemented** (delegate PERM.7 → accept unsigned) | Works (`-onboardDelegate` with PERM.7 chain) | 6 unwrap tests | **`bmo-delegate-unsigned`** | **`bmo-delegate-unsigned-noperm`** |
| 3 | Implemented | `-bmo-sign` works | Yes (5 tests) | **`bmo-signed`** | `bmo-signed-negative` |
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
- [x] **Model 3 negative integration test** (`test_bmo_signed_negative`): Server
  sends unsigned BMO to a device with Owner key — device rejects it.

#### Remaining testing tasks

- [ ] **Model 1 clarification**: The go-fdo device rejects unsigned provisioning
  from the Owner itself (when no delegate is used and Owner key is present). This
  is the strict interpretation: even the Owner MUST sign. This is now documented
  and tested (`bmo-signed-negative`). If the spec intends to allow unsigned from
  a verified Owner TO2 session (channel authority), add an Owner-direct flag.
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
