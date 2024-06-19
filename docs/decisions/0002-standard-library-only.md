# 2. Standard Library Only

Date: 2024-06-18

## Status

Accepted

## Context

"Zero dependency" (a.k.a. stdlib-only) libraries are not only a badge of honor in the Go programming community, but a guaranteed way improve library stability and reduce the amount of trust needed from library users.

FDO only requires a small set of CBOR and COSE features and most of the encryption and key exchange schemes are included or trivially built upon the Go standard library.

Other than the key exchange and service info subprotocols, FDO is largely encoding and decoding CBOR. Therefore, a CBOR library with a minimal set of features is desirable for both code readability and possibility for performance optimizations.

## Considered Options

The CBOR library [fxamacker/cbor](https://github.com/fxamacker/cbor) and COSE library [veraison/go-cose](https://github.com/veraison/go-cose) were considered. Both libraries are fairly stable and only introduce one further transient dependency ([x448/float16](github.com/x448/float16)). However, both libraries include far more features than needed for implementing FDO and `fxamacker/cbor` continues to acquire new features.

## Decision

The main module of this library will only depend on the Go standard library. Capabilities requiring 3rd party libraries must be optional and imported as a separate Go module.

CBOR and COSE libraries will include a minimum of features and be written with an emphasis on readbility over performance or extensibility, unless necessary.

## Consequences

- Must include a (partiall) CBOR implementation
- Must include a (partial) COSE implementation
- Must use interfaces to allow functionality provided by separate modules
  - Example: Signing and HMAC interfaces for TPM support (imports TCG libraries)
