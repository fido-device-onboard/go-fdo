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
- **Test Scripts**: Comprehensive test suite in `test_examples.sh`

## Development Workflow

### Initial Setup

```bash
make setup    # Initialize Go workspace (run once after clone)
```

### Building and Testing

```bash
make build    # Build the project
make test     # Run all tests (unit + integration)
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

#### Integration Tests

Run via `./test_examples.sh` with specific test scenarios:

| Test | Description |
| ---- | ----------- |
| `basic` | Basic device initialization (DI) and transfer of ownership (TO1/TO2) |
| `basic-reuse` | Credential reuse protocol - multiple onboards without credential changes |
| `rv-blob` | Rendezvous blob registration flow |
| `kex` | Key exchange with ASYMKEX2048 (RSA keys) |
| `fdo200` | FDO 2.0 protocol |
| `delegate` | Delegate certificate support (FDO 1.01) |
| `delegate-fdo200` | Delegate certificate support with FDO 2.0 |
| `attested-payload` | Attested payload creation and verification |
| `sysconfig` | System configuration FSIM |
| `payload` | File payload transfer FSIM |
| `wifi` | WiFi configuration FSIM |
| `bmo` | Bare Metal Onboarding FSIM |
| `all` | Run all tests (default) |

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

- Server logs: `/tmp/fdo_server.log`
- Use `-debug` flag for verbose protocol output
- Ephemeral files preserved for debugging

## Common Development Tasks

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
├── Makefile                     # Build targets
├── test_examples.sh             # Integration tests
├── AGENTS.md                    # This file
├── examples/                    # Reference implementation
│   └── cmd/                     # CLI tool
├── fsim/                        # Service Info Modules
├── sqlite/                      # Database integration
├── tpm/                         # TPM support
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
- Check server logs in `/tmp/fdo_server.log`
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
