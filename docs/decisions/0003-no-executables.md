# 3. No Executables

Date: 2024-06-18

## Status

Accepted

## Context

Supporting a client CLI or server binary significantly broadens the scope and support burden of this package.

## Decision

Any executable binaries will be separated from the library code and clearly marked as examples only. Changes to their interfaces will not affect the versioning of the library.

## Consequences

There will be increased burden on documentation and examples to help explain how to use this library to implement FDO clients and servers.
