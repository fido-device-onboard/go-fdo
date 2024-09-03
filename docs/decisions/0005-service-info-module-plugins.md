# 5. Service Info Module Plugins

Date: 2024-07-12

## Status

Accepted

## Context

Currently, the library only allows implementing service info modules (FSIMs) as Go code statically compiled into the executable for both device and owner roles. This may be undesirable in cases where:

- FSIM implementers want to develop in a language other than Go
- Application packagers want to provide a generic FDO client or server
- The FDO client or server is running in lower privileges while a subset of FSIMs need elevated privileges
  - Example: Client runs in a container, FSIM runs on host to read SMBIOS tables
- Application users want to upgrade an FSIM without redeploying

## Considered Options

Dynamically linked plugins (implements callbacks in C ABI)

- Pro: Lowest system resource overhead
- Con: Module interfaces must be adapted for C types
- Con: Must compile package using this library with cgo toolchain
- Con: Applications using this library will depend on libc
- Con: Process must be restarted to reload plugins
- Con: Cannot be implemented with scripting languages

RPC-based plugins (implements REST or gRPC service)

- Pro: Existing parsing/validation libraries
- Con: Additional dependencies for HTTP, gRPC, JSON, etc.
- Con: Not friendly to most scripting languages
- Con: Some languages/libraries do not support AF_UNIX sockets on Windows
- Con: Overhead for unused features such as concurrent HTTP servers
- Con: Defaults for timeouts, auth, and encryption may need to be disabled

Stream-based plugins (implements stdin/stdout-based protocol)

- Pro: Easiest to implement in scripting languages
- Con: No existing parsing/validation libraries

## Decision

- FSIM plugins will use a stream-based protocol that reduces the burden of developing FSIMs specifically in scripting languages
- Plugins will be located in a particular directory and will be loaded and executed as needed
- Devmod, though a special case, will also be supported

## Consequences

- All supported FSIMs will need to be implemented twice - one per interface
- Example FSIMs in scripting languages should be included in code or documentation
- Internal vs external FSIM interfaces need to be clarified in all documentation

Additionally, for any plugin system, a major challenge will be handling shutdown behavior. Whether a child process should be killed or released and how long it should be given for graceful shutdown are not obvious.
