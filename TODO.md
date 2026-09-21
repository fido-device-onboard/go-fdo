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

### Testing

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
