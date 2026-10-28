# AGENTS.md

This document provides guidance for AI agents and automated tools working with the go-fdo codebase.

## Agent Rules and Guidelines

### Critical Rules

- **NEVER stage or commit code** - The user will always handle commits
- **NEVER claim "all things work" without running full `make test`** - Only claim functionality after comprehensive testing
- **ALWAYS run linters before check-in** - Use `make lint` and fix any errors found
- **DO NOT make unproductive loops** - If repeatedly fixing lints, comment on the pattern and move on

### Testing Guidelines

- **Partial testing is acceptable** for debugging individual components:
  - Unit tests: `go test -v ./...` or specific packages
  - Integration tests: `./test_examples.sh <specific_test>`
- **Full testing required** before claiming functionality works:
  - Complete test suite: `make test` (runs both unit and integration)
- **Test-specific scenarios** using the comprehensive test suite in `test_examples.sh`
- **Changes to the ServiceInfo loop or chunking need a large-payload run.**
  Any change to `exchangeServiceInfo` / `exchangeServiceInfoRound` (`to2.go`),
  `to2_module.go`, `serviceinfo/` pipes or chunking, or an owner FSIM's
  send path (`fsim/*_owner.go`) MUST pass `TestClientLongOwnerRunFDO20` and a
  real transfer of more than 1000 chunks under FDO 2.0, e.g. (from `examples/`):

  ```bash
  head -c 157286400 /dev/urandom > /tmp/big.bin      # 150 MiB = 2622 x 60000-byte chunks
  go run ./cmd server -db /tmp/big.db -http 127.0.0.1:9992 -initOnly
  go run ./cmd server -db /tmp/big.db -http 127.0.0.1:9992 -reuse-cred \
      -payload application/octet-stream:/tmp/big.bin &
  go run ./cmd client -blob /tmp/big.cred -di http://127.0.0.1:9992
  go run ./cmd client -blob /tmp/big.cred -fdo-version 200 -max-owner-service-info 65532
  # expect TO2 success, "All chunks sent", and examples/big.bin identical to /tmp/big.bin
  ```

  The integration tests only use small payloads, so they pass even when large
  transfers deadlock. This is how the 2026-10-10 loop regression (2.0 devices
  hung at chunk 1000) reached a real install without any test failing.

### Upstreaming Order (fdo20-merge3 -> upstream)

`fdo20-merge3` is the source for everything still to go upstream after the
FDO 2.0 core PR (fido-device-onboard/go-fdo #285, built from `fdo20-core`).
Order matters:

1. **The device ServiceInfo loop fix MUST go upstream BEFORE (or together
   with) `fdo.payload`, `fdo.bmo`, or any FSIM that streams content.** #285
   carries the shared loop that buffers an owner's whole IsMoreServiceInfo run
   in a 1000-entry pipe; payload/BMO owners send one chunk per message with
   IsMoreServiceInfo set, so any transfer over 1000 chunks deadlocks the
   device. Port `exchangeServiceInfo` (`to2.go`, the `handle` closure that
   processes owner info as it arrives) together with its regression test
   `TestClientLongOwnerRunFDO20` (`fdo_test.go`). Details: `TODO.md`
   "UPSTREAMING ORDER".
2. Then the FSIMs, each with its tests.

### Code Quality Standards

- **Final prep for check-in**: Run `make lint` and address all linting errors
- **Use existing patterns** - Follow established code structure and naming conventions
- **Prefer minimal changes** - Make the smallest change that fixes the issue

## Project Overview

`go-fdo` is a lightweight Go library implementing FIDO Device Onboard (FDO) specifications 1.1 and 2.0. It provides device, owner service, and device initialization server roles with a focus on stdlib-only implementation.

## Key Components

### Core Library Structure

- **Base Library**: Main FDO protocol implementation in `./`
- **FSIM Modules**: Service Info Modules in `./fsim/`
- **SQLite Integration**: Database layer in `./sqlite/`
- **TPM Support**: Hardware security module integration in `./tpm/`
- **Examples**: Reference implementation in `./examples/`

### Build System

- **Go Workspaces**: Uses Go workspaces (`go.work`) for multi-module development
- **Makefile**: Provides convenience targets for development workflows
- **Test Scripts**: Comprehensive test suite in `test_examples.sh`; TPM hardware tests in `test_tpm_examples.sh`

## Development Workflow

### Initial Setup

```bash
make setup    # Initialize Go workspace (run once after clone)
```

### Go Toolchain

The system `go` on the dev box is **1.18**, which cannot build this module
(needs 1.25 for `iter`, `log/slog`, `crypto/ecdh`). The correct toolchain is
installed at `/home/bradgoodman/go`, and `GOPATH` must be pointed elsewhere or
Go warns that `GOPATH == GOROOT`:

```bash
export GOROOT=/home/bradgoodman/go
export GOPATH=/home/bradgoodman/gomods
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

### Known Pre-existing Failure

The TPM package needs OpenSSL headers (`libssl-dev`) for the `go-tpm-tools`
simulator's cgo build; without them `make lint` and `make test` stop in the
TPM package with `fatal error: openssl/aes.h`. With them installed, the base
library, FSIM, sqlite and TPM lint targets report 0 issues, and `make lint`
then stops on 4 pre-existing findings in `examples/cmd/server.go`
(gocyclo on `ownerModules`, gosec G301/G115).

### Building and Testing

```bash
make build        # Build default binary (no TPM, no CGO, static)
make build-tpm    # Build with hardware TPM support (no CGO)
make build-tpmsim # Build with TPM simulator (requires CGO + OpenSSL)
make test         # Run all tests (unit + integration)
make test-tpm     # Run TPM hardware integration tests (requires /dev/tpmrm0)
make test-tpm-sim # Run TPM simulator integration tests (no hardware needed)
make lint     # Run all linters
make          # Default: run lint + test
```

### Test Categories

#### Unit Tests

- Base library tests: `go test -v ./...`
- FSIM tests: `go test -v ./fsim/...`
- SQLite tests: `go test -v ./sqlite/...`
- TPM tests: `go test -v ./tpm/...`
- Examples tests: `go test -v ./examples/...`

#### TPM Spec Compliance Tests

Separate build tag, must run from `tpm/` directory. Two suites:
`TestSpecCompliance` (library functions the credential store uses, checked
against the spec tables) and the Phase 9 library integration tests
(`TestPhase9`). Both remove existing FDO state from the TPM first.

**Hardware TPM (Linux):** `TestSpecCompliance` creates DCTPM under the Owner
hierarchy by default, so it needs no extra setting. The Phase 9 tests still
need `FDO_TPM_OWNER_HIERARCHY=1` (Platform hierarchy is locked after boot).

```bash
cd tpm

# Spec compliance against hardware TPM
go test -v -tags=spec_compliance_test -run TestSpecCompliance -count=1

# Phase 9 library integration tests against hardware TPM
FDO_TPM_OWNER_HIERARCHY=1 go test -v -tags=spec_compliance_test -run TestPhase9 -count=1

# Both at once
FDO_TPM_OWNER_HIERARCHY=1 go test -v -tags=spec_compliance_test -count=1
```

**Software simulator (no TPM hardware needed):**

```bash
cd tpm
FDO_TPM=sim go test -v -tags=spec_compliance_test -count=1
FDO_TPM=sim FDO_TPM_PLATFORM_HIERARCHY=1 go test -v -tags=spec_compliance_test -run TestSpecCompliance -count=1
```

Store-level TPM tests: `cd cred && go test -v -tags=tpmsim -count=1`.

**Notes:**

- P-384/SHA-384 cases are skipped when the TPM does not list NIST P-384
  (or with `FDO_TPM_P384=0`).
- See `tpm/TPM_COMPLIANCE_TESTING.md` for detailed test instructions.

#### Integration Tests

Run via `./test_examples.sh` with specific test scenarios:

| Test | Description |
| ---- | ----------- |
| `basic` | Basic device initialization (DI) and transfer of ownership (TO1/TO2) |
| `basic-reuse` | Credential reuse protocol - multiple onboards without credential changes |
| `rv-blob` | Rendezvous blob registration flow |
| `kex` | Key exchange with ASYMKEX2048 (RSA keys) |
| `fdo200` | FDO 2.0 protocol |
| `fdo200-di200` | FDO 2.0 end-to-end with DI also at 2.0 (2.0 AppStart with capability flags) |
| `kex-fdo200` | FDO 2.0 key exchange negotiation: device configured for ASYMKEX2048 uses the Owner's offered DHKEXid14 |
| `delegate` | Delegate certificate support (FDO 1.01) |
| `delegate-fdo200` | Delegate certificate support with FDO 2.0 |
| `rv-verify-to1d` | RV verifies to1d at TO0 (`-rv-verify-to1d`): Owner- and redirect-delegate-signed accepted; delegate without redirect rejected |
| `attested-payload` | Attested payload creation and verification |
| `sysconfig` | System configuration FSIM |
| `payload` | File payload transfer FSIM |
| `payload-log` | Device diagnostic log upload (`payload-log-*` reverse-direction transfer), with negative control |
| `payload-log-standalone` | Report mode: device-initiated standalone log (`-payload-report`), payload rejected before any data, stored per GUID with phase/outcome; negative control: owner without `-payload-log-dir` leaves it undelivered |
| `wifi` | WiFi configuration FSIM |
| `bmo` | Bare Metal Onboarding FSIM |
| `bmo-meta-url` | BMO meta-URL delivery (unsigned meta-payload via CLI) |
| `bmo-meta-signed` | BMO signed meta-payload + tampered-signature negative test |
| `bmo-meta-delegate-signed` | Meta-payload signed by a PERM.7 delegate chain (no `meta_signer`); `fdo meta` refuses an onboard-only chain; `meta verify -owner` |
| `bmo-signed-scope` | Scope: validity window accepted; expired window and `generation` (no rollback storage) rejected |
| `bmo-owner-unsigned` | Model 1: unsigned BMO from the Owner is accepted (channel authority) |
| `payload-signed` | `payload-begin` signed by the Owner key (`-payload-sign`) |
| `payload-delegate-noperm` | Negative: unsigned `payload-begin` from an onboard-only delegate is refused |
| `rv-firmware-tags` | RV firmware extension tags (16/17/18) DI provisioning + TO1/TO2 compatibility |
| `auth` | FDOKeyAuth CLI - obtain bearer token via challenge-response handshake |
| `all` | Run all tests (default) |

#### TPM Hardware Integration Tests

Run via `./test_tpm_examples.sh` (or `make test-tpm`). Requires `/dev/tpmrm0`
and read/write access. These test DI and onboarding flows with all credential
storage going through real TPM hardware (NV indices + persistent keys).

| Test | Description |
| ---- | ----------- |
| `basic` | DI + TO1/TO2 with TPM NV credential storage |
| `basic-reuse` | DI + multiple onboards with credential reuse |
| `fdo200` | DI + TO1/TO2 with FDO 2.0 protocol |
| `all` | Run all TPM tests (default) |

```bash
./test_tpm_examples.sh all         # Run all TPM tests (hardware)
./test_tpm_examples.sh basic       # Run specific TPM test
TPM_MODE=sim ./test_tpm_examples.sh  # Use software simulator (no hardware)
TPM_DEVICE=/dev/tpm0 ./test_tpm_examples.sh  # Use alternate TPM device
```

### Running Tests

```bash
./test_examples.sh all              # Run all tests
./test_examples.sh basic           # Run specific test
./test_examples.sh fdo200          # Test FDO 2.0 protocol
```

## Code Architecture

### FDO Protocol Implementation

- **Device Initialization (DI)**: Initial device registration
- **Transfer of Ownership 1 (TO1)**: Rendezvous and owner discovery
- **Transfer of Ownership 2 (TO2)**: Secure channel establishment and configuration

### Service Info Modules (FSIM)

FSIMs extend FDO functionality with device-specific services:

- **devmod**: Device module advertisement and capabilities
- **sysconfig**: System configuration parameters
- **payload**: File transfer capabilities
- **wifi**: Network configuration
- **bmo**: Bare metal onboarding
- **attestedpayload**: Cryptographically verified payloads

### Key Interfaces

- `serviceinfo.DeviceModule`: Device-side FSIM interface
- `serviceinfo.OwnerModule`: Owner-side FSIM interface
- `fdo.TO2Config`: Configuration for TO2 protocol
- `fdo.TO2Server`: Server-side implementation
- `transfer.FDOKeyAuthClient`: Client for FDOKeyAuth challenge-response handshake
- `transfer.FDOKeyAuthServer`: Server with `KeyLookup` and `TokenIssuer` callbacks
- `transfer.VoucherStore`: Storage interface for push/pull voucher transfer

## Testing Guidelines

### Test Environment Setup

Tests use ephemeral files and databases:

- Database: `ephemeral-test-files/test.db`
- Credentials: `ephemeral-test-files/cred.bin`
- Server runs on `127.0.0.1:9999`

### Test Script Structure

Each test in `test_examples.sh` follows this pattern:

1. Clean up previous artifacts
2. Start server with specific configuration
3. Run DI (Device Initialization)
4. Run TO1/TO2 (Transfer of Ownership)
5. Verify results
6. Stop server

### Debugging Tests

- Server logs: `ephemeral-test-files/fdo_server.log`
- Use `-debug` flag for verbose protocol output
- Ephemeral files preserved for debugging

## Common Development Tasks

### FSIM Specifications Live Elsewhere

The authoritative FSIM specs are in the **`fdo-sim`** repository
(<https://github.com/bkgoodman/fdo-sim>, directory `fsim-repository/`), not in
this repo. Copies previously kept at this repo's root drifted out of sync and
were removed; see `SPECIFICATIONS.md` for the index. **Edit the spec in
`fdo-sim`** — do not re-add copies here. Implementation notes specific to this
codebase belong in `fsim/*.md`.

### Adding New FSIMs

1. Implement `serviceinfo.DeviceModule` interface
2. Add owner-side counterpart if needed
3. Register in test configuration
4. Add integration tests in `test_examples.sh`

### Protocol Version Testing

- FDO 1.01: Default behavior
- FDO 2.0: Use `-fdo-version 200` flag
- Test both versions for compatibility

### Security Testing

- Certificate validation: Test with various cert types
- Key exchange: Test ASYMKEX2048 with RSA keys
- TPM integration: Test with hardware TPM or simulator

## Build and Deployment

### FIPS Compliance

Build with Microsoft Go toolchain for FIPS 140-2 compliance:

```dockerfile
FROM mcr.microsoft.com/oss/go/microsoft/golang:1.23-fips-cbl-mariner2.0 AS build
RUN go build -tags=requirefips -o fdo ./examples/cmd
```

### Production Considerations

- Certificate revocation checking required
- Key management best practices
- Transport security requirements
- See `PRODUCTION_CONSIDERATIONS.md` for details

## File Organization

```
go-fdo/
├── README.md                    # Main documentation
├── SPECIFICATIONS.md            # Index of FSIM specs (authoritative copies live in fdo-sim)
├── Makefile                     # Build targets
├── test_examples.sh             # Integration tests
├── AGENTS.md                    # This file
├── examples/                    # Reference implementation
│   ├── cmd/                     # CLI tool (client, server, delegate, auth, etc.)
│   └── authtest/                # FDOKeyAuth test server helper
├── fsim/                        # Service Info Modules
├── sqlite/                      # Database integration
├── tpm/                         # TPM support
├── transfer/                    # Voucher Transfer Protocol (FDOKeyAuth, push, pull)
├── serviceinfo/                 # Core FSIM interfaces
├── fdo/                         # Main FDO protocol
└── internal/                    # Internal packages
```

## Agent-Specific Notes

### Code Navigation

- Use `grep` and `find` to locate implementations
- FSIM modules follow consistent naming patterns
- Test scripts serve as usage examples

### Common Patterns

- Error handling: Go-style error returns
- Logging: Structured logging with context
- Testing: Table-driven tests for unit tests
- Integration: End-to-end protocol testing

### Debugging Tips

- Enable debug logging with `-debug` flag
- Check server logs in `ephemeral-test-files/fdo_server.log`
- Use `sqlite3` to inspect database state
- Ephemeral files preserved for post-mortem analysis

## Security Considerations

### Development vs Production

- Reference implementation skips some security checks
- Certificate revocation checking disabled by default
- Production deployments must implement full security stack

### Testing Security Features

- Delegate certificate testing
- Attested payload verification
- Single-sided attestation modes
- Key exchange algorithm testing

This document should help AI agents understand the project structure, development workflow, and testing patterns for effective code analysis and modification.
