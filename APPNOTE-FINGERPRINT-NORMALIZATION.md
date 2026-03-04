# Application Note: OwnerKeyFingerprint Normalization

## Summary

`did.FingerprintProtocolKey(protocol.PublicKey)` now **normalizes** the key
before computing the fingerprint. It extracts the underlying `crypto.PublicKey`
and delegates to `did.FingerprintFDO()`, which always re-encodes as
`pkEnc = X509` (DER) before CBOR-marshaling and SHA-256 hashing.

This means the fingerprint depends **only on the key material**, not on the
wire encoding (X509, X5CHAIN, or COSEKEY) used during transmission.

## What Changed

| Before | After |
| ------ | ----- |
| `FingerprintProtocolKey` hashed the raw CBOR of whatever `protocol.PublicKey` struct it received | `FingerprintProtocolKey` extracts `crypto.PublicKey`, re-encodes as X509, then hashes |
| Same key encoded as X509 vs X5CHAIN vs COSE produced **different** fingerprints | Same key **always** produces the same fingerprint regardless of encoding |

### Affected function

```go
// did/document.go
func FingerprintProtocolKey(pub protocol.PublicKey) ([]byte, error)
```

### Unaffected functions

These already used the normalized path and are unchanged:

```go
func FingerprintFDO(pub crypto.PublicKey) ([]byte, error)
func FingerprintFDOHex(pub crypto.PublicKey) string
```

## Why This Matters

The FDO voucher pipeline stores fingerprints using `FingerprintFDO(crypto.PublicKey)`.
FDOKeyAuth token scoping computes fingerprints using `FingerprintProtocolKey(protocol.PublicKey)`.
If these two paths produce different hashes for the same key, FDOKeyAuth token scoping
fails silently — the puller authenticates successfully but sees zero vouchers because
the token's fingerprint doesn't match any stored transmission records.

## What You Need To Do

### If you use `did.FingerprintProtocolKey()`

**Nothing.** The function signature is unchanged. It now returns consistent
fingerprints automatically.

### If you compute fingerprints yourself

If your code computes OwnerKeyFingerprint by directly CBOR-marshaling a
`protocol.PublicKey` and hashing, you **must** normalize first:

```go
// WRONG — encoding-dependent fingerprint
data, _ := cbor.Marshal(protoKey)
hash := sha256.Sum256(data)

// RIGHT — extract crypto key, use library function
cryptoPub, _ := protoKey.Public()
fingerprint, _ := did.FingerprintFDO(cryptoPub)
```

Or simply call the library:

```go
fingerprint, err := did.FingerprintProtocolKey(protoKey)
```

### If you store fingerprints in a database

Existing fingerprints stored via `FingerprintFDO(crypto.PublicKey)` or
`FingerprintFDOHex(crypto.PublicKey)` are **unchanged** — these already used the
normalized X509 path. No database migration is needed.

If you previously stored fingerprints computed via the old
`FingerprintProtocolKey` (raw CBOR hash), those values will no longer match.
You should re-compute and update them using the normalized function.

## Spec Reference

The voucher transfer spec (§9.8 FDOKeyAuth.Result) now includes:

> Implementations MUST normalize the Owner Key to its canonical form before
> computing the fingerprint: extract the raw public key material, re-encode it
> as a `protocol.PublicKey` with `pkEnc = X509` (DER encoding), then
> CBOR-encode and hash.

## Test Coverage

The library includes `TestFingerprintProtocolKey_ConsistentAcrossEncodings` in
`did/did_test.go` which verifies that `FingerprintProtocolKey` produces
identical fingerprints for the same key encoded as X509 and COSE, and that
both match `FingerprintFDO`.
