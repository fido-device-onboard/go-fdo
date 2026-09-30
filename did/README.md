# go-fdo/did — DID Minting and Resolution

This package provides Decentralized Identifier (DID) minting, resolution, and serving capabilities for FDO Owner Keys.

## Features

- **Key Generation** — Generate ECDSA (P-256, P-384) or RSA (2048, 3072) owner key pairs
- **DID Document Creation** — Export public keys as W3C DID Documents with JWK encoding
- **did:web Serving** — Serve DID Documents via HTTP at `/.well-known/did.json`
- **DID Resolution** — Resolve `did:web` URIs to public keys and service endpoints
- **FDO Integration** — Encode voucher recipient URLs in DID Document service entries
- **PEM Import/Export** — Load and save private/public keys in PEM format

## Usage

### Mint a DID

```go
result, err := did.Mint(
    "example.com:8080",                          // host
    "",                                           // path (empty for root)
    "https://example.com:8080/api/v1/vouchers",  // voucher recipient URL
    did.KeyConfig{Type: "EC", Curve: "P-384"},    // key config
)
// result.DIDURI       → "did:web:example.com%3A8080"
// result.PrivateKey   → crypto.Signer
// result.DIDDocument  → *did.Document (ready to serve)
```

### Serve a DID Document

```go
handler, _ := did.NewHandler(result.DIDDocument)
handler.RegisterHandlers(mux, "")
// Serves at GET /.well-known/did.json
```

### Resolve a DID

```go
resolver := did.NewResolver()
result, err := resolver.Resolve(ctx, "did:web:example.com")
// result.PublicKey            → crypto.PublicKey
// result.VoucherRecipientURL → "https://example.com/api/v1/vouchers"
```

### Export Keys

```go
privPEM, _ := did.ExportPrivateKeyPEM(result.PrivateKey)
pubPEM, _ := did.ExportPublicKeyPEM(result.PublicKey)
loaded, _ := did.LoadPrivateKeyPEM(privPEM)
```

## did:web URI Format

| Input | DID URI |
|-------|---------|
| `example.com` | `did:web:example.com` |
| `example.com:8080` | `did:web:example.com%3A8080` |
| `example.com` + path `owner1` | `did:web:example.com:owner1` |

## DID Document Structure

The generated DID Document follows the W3C DID Core specification with:

- **`@context`** — Standard DID and JWS 2020 contexts
- **`verificationMethod`** — Single `JsonWebKey2020` entry with the owner's public key
- **`authentication`** / **`assertionMethod`** — References to the verification method
- **`service`** — Optional `FDOVoucherRecipient` entry with the voucher push endpoint URL

## Testing

```bash
go test -v ./did/...
```
