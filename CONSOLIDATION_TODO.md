# Library Consolidation TODO

Instructions for AI agents working on **go-fdo-di** and **go-fdo-onboarding-service** to eliminate duplicate code by adopting the go-fdo library's `did/` and `transfer/` packages.

**Context**: Three applications (go-fdo-voucher-management "VM", go-fdo-di "DI", go-fdo-onboarding-service "Onboarding") all re-implement functionality that either already exists in this library or should be added here. The VM project has already completed its consolidation as a reference implementation. This document tells you exactly what to do in the other projects.

---

## What the Library Already Provides

### `did/` package

| Function | What It Does | Replaces |
|----------|-------------|----------|
| `did.Resolver` | Resolves `did:web` and `did:key` URIs to public keys + service endpoints | App-level `DIDResolver` / `parseDIDKey()` |
| `did.Resolver.InsecureHTTP` | Allows HTTP (not HTTPS) for `did:web` in dev/testing | App-level `InsecureHTTP` field |
| `did.ParseDIDKey(uri)` | Decodes `did:key:z...` → `crypto.PublicKey` (P-256, P-384). Zero external deps (inline base58-btc). | App-level `parseDIDKey()` + `base58` dependency |
| `did.FingerprintFDO(pub)` | SHA-256 of CBOR-encoded `protocol.PublicKey` — **spec §9.8 correct** | App-level `FingerprintPublicKey()` / `publicKeyToProtocol()` |
| `did.FingerprintFDOHex(pub)` | Hex-encoded version of above | App-level `FingerprintPublicKeyHex()` |
| `did.FingerprintProtocolKey(pub)` | Same fingerprint from a `protocol.PublicKey` directly (no round-trip) | App-level `FingerprintProtocolKey()` |
| `did.FingerprintJWK(pub)` | JWK Thumbprint (RFC 7638) — NOT FDO-spec, but useful for non-FDO contexts | — |
| `did.WebDIDToURL(uri)` | Converts `did:web:...` to `https://.../.well-known/did.json` URL | App-level `webDIDToURL()` |
| `did.NewDocument(...)` | Creates a DID Document with verification methods + service entries | App-level DID doc construction |
| `did.NewHandler(doc)` | HTTP handler serving `.well-known/did.json` | App-level DID serving code |
| `did.Mint(...)` | Generate key + DID document in one call | App-level key gen + doc construction |
| `did.LoadPrivateKeyPEM(pem)` | Load private key from PEM bytes (PKCS8, PKCS1, EC) | App-level `LoadPrivateKeyFromPEM()` |
| `did.ExportPrivateKeyPEM(key)` | Export private key as PEM | App-level PEM export |
| `did.ExportPublicKeyPEM(key)` | Export public key as PEM | App-level PEM export |
| `did.PublicKeyToJWK(pub)` | Convert crypto.PublicKey to JWK struct | App-level JWK conversion |
| `did.JWKToPublicKey(jwk)` | Convert JWK struct to crypto.PublicKey | App-level JWK parsing |

### `transfer/` package

| Type | What It Does | Replaces |
|------|-------------|----------|
| `transfer.PushSender` interface | Send vouchers to remote receiver | — |
| `transfer.PushReceiver` interface | Accept pushed vouchers | — |
| `transfer.HTTPPushSender` | HTTP multipart push client | App-level `VoucherPushClient` |
| `transfer.HTTPPushReceiver` | HTTP push receiver with validation | App-level `VoucherReceiverHandler` |
| `transfer.VoucherStore` interface | Storage abstraction for vouchers | App-level `VoucherFileStore` |
| `transfer.VoucherData` | Unified voucher metadata struct | App-level passing raw paths + `fdo.Voucher` separately |
| `transfer.PullHolder` interface | Serve vouchers to authenticated recipients | — |
| `transfer.PullInitiator` interface | Authenticate + download vouchers | — |
| `transfer.PullAuthServer` | Full PullAuth protocol server | App-level pullauth server code |
| `transfer.PullAuthClient` | Full PullAuth protocol client | App-level pullauth client code |

---

## Per-Project Instructions

### go-fdo-di (DI / Manufacturer)

DI is the **worst offender** with ~1,400 lines of duplicate code and a 635-line DID resolver that should be ~50 lines.

#### Step 1: Replace DID Resolver (CRITICAL — SECURITY BUG)

DI's `did_resolver.go` is **635 lines** with its own caching, `go-did` dependency, key generation, etc.

> **⚠️ CRITICAL BUG**: The `parseECJWK()` and `parseRSAJWK()` functions in the app-level
> DID resolver **do not actually parse JWK coordinates from the DID document**. Instead,
> they **generate brand-new random keys** and return those. This means any `did:web:`
> resolution returns a random public key that has **nothing to do with the actual DID owner**.
> Any cached "resolved" keys are garbage. The caching logic itself (store on success, keep
> on failure) is sound — the underlying JWK parse was just silently wrong.
>
> The library's `did.Resolver` performs correct JWK parsing (`did.JWKToPublicKey`), so
> switching to it fixes this bug. **Do not attempt to fix the app-level parseECJWK/parseRSAJWK
> — just delete them and use the library.**

**Replace with:**

```go
import "github.com/fido-device-onboard/go-fdo/did"

type DIDResolver struct {
    resolver *did.Resolver
    enabled  bool
}

func NewDIDResolver(enabled bool) *DIDResolver {
    return &DIDResolver{
        resolver: did.NewResolver(),
        enabled:  enabled,
    }
}

func (r *DIDResolver) ResolveDIDKey(ctx context.Context, didURI string) (crypto.PublicKey, string, error) {
    if !r.enabled {
        return nil, "", fmt.Errorf("DID resolution disabled")
    }
    result, err := r.resolver.Resolve(ctx, didURI)
    if err != nil {
        return nil, "", err
    }
    return result.PublicKey, result.VoucherRecipientURL, nil
}
```

**After**: Remove `github.com/nuts-foundation/go-did` dependency entirely. Run `go mod tidy`.

**Reference**: See `go-fdo-voucher-management/did_resolver.go` (79 lines, thin wrapper).

#### Step 2: Replace Fingerprinting

DI likely has its own `FingerprintPublicKey` / `publicKeyToProtocol`. Replace with:

```go
import "github.com/fido-device-onboard/go-fdo/did"

// Replace FingerprintPublicKeyHex(pub) with:
did.FingerprintFDOHex(pub)

// Replace FingerprintProtocolKey(pub) with:
fp, err := did.FingerprintProtocolKey(pub)
```

**IMPORTANT**: The library's `did.FingerprintFDO()` uses `protocol.NewPublicKey` + `cbor.Marshal` + SHA-256. This is the **spec-correct** algorithm (§9.8). If DI was using JWK thumbprints or PKIX-hash fingerprints, existing fingerprints stored in databases will NOT match. You may need a one-time migration or to support both during transition.

#### Step 3: Replace Push Client

DI's `voucher_push_client.go` (~132 lines) duplicates `transfer.HTTPPushSender`. Switch to:

```go
import "github.com/fido-device-onboard/go-fdo/transfer"

sender := transfer.NewHTTPPushSender(httpClient)
err := sender.Push(ctx, dest, voucherData)
```

#### Step 4: Replace Transmission Store + Retry Worker

DI's `voucher_transmission_store.go` (~454 lines) and `voucher_retry_worker.go` (~119 lines) are near-identical to VM's. These are **not yet in the library** — see "What's Missing" below. For now, keep them in-app but plan to switch when the library adds `transfer.TransmissionStore` and `transfer.RetryWorker`.

#### Step 5: Remove PEM Utility Duplicates

Replace any local `LoadPrivateKeyFromPEM`, `ExportPrivateKeyPEM`, `LoadPublicKeyFromPEM` with:

- `did.LoadPrivateKeyPEM()`
- `did.ExportPrivateKeyPEM()`
- `did.ExportPublicKeyPEM()`

Note: The library versions handle PKCS8, PKCS1, and EC PEM blocks. If DI has additional block types (e.g., `RSA PUBLIC KEY`), keep those as local extensions.

#### Step 6: Clean Up Dependencies

After all replacements, run:

```bash
go mod tidy
```

Expected removals: `github.com/nuts-foundation/go-did`, `github.com/mr-tron/base58`, `github.com/multiformats/go-multibase`, and their transitive deps.

---

### go-fdo-onboarding-service (Onboarding / Owner)

Onboarding has ~730 lines of duplicates, primarily in voucher receiving.

#### Step 1: Replace Voucher Receiver Handler

Onboarding's `voucher_receiver_handler.go` (~360 lines) duplicates the push receiver. Switch to `transfer.HTTPPushReceiver` or at minimum use `did.Resolver` for any DID resolution within the handler.

**Special concern**: Onboarding's handler has its own PEM encoding (manual base64 line-wrapping) instead of using `fdo.FormatVoucherCBORToPEM()`. Fix this:

```go
import "github.com/fido-device-onboard/go-fdo"
pemBytes := fdo.FormatVoucherCBORToPEM(cborBytes)
```

#### Step 2: Replace Token Store

Onboarding's `voucher_receiver_tokens.go` (~188 lines) is near-identical to VM's. This is **not yet in the library** — see "What's Missing" below. Keep in-app for now.

#### Step 3: Replace Any DID Resolution

If Onboarding has a `did_resolver.go` or any JWK parsing functions (`parseECJWK`, `parseRSAJWK`), check for the same **random-key-generation bug** described in the DI section above. These functions may generate new random keys instead of parsing the actual JWK coordinates from the DID document.

Replace with:

```go
resolver := did.NewResolver()
result, err := resolver.Resolve(ctx, didURI)
```

#### Step 4: Replace Fingerprinting

Same as DI Step 2 — use `did.FingerprintFDO()` / `did.FingerprintFDOHex()`.

---

## What's Missing from the Library (Future Work)

These components are duplicated across apps but **not yet in the library**. They should be added to `transfer/` before apps can fully consolidate.

### 1. TransmissionStore (~450 lines, duplicated in VM + DI)

SQLite-backed queue tracking push attempts with states (`pending`, `in_progress`, `succeeded`, `failed`), retry scheduling, owner-key fingerprint scoping.

**Interface to add to `transfer/`:**

```go
type TransmissionStore interface {
    Create(ctx context.Context, record *TransmissionRecord) error
    GetPending(ctx context.Context, limit int) ([]*TransmissionRecord, error)
    UpdateStatus(ctx context.Context, id string, status string, err error) error
    GetByVoucherID(ctx context.Context, voucherID string) (*TransmissionRecord, error)
}
```

**Reference implementation**: `go-fdo-voucher-management/voucher_transmission_store.go`

### 2. RetryWorker (~120 lines, duplicated in VM + DI)

Background goroutine that polls TransmissionStore for failed pushes and retries with exponential backoff + jitter. Honors `Retry-After` headers.

**Reference**: `go-fdo-voucher-management/voucher_retry_worker.go`

### 3. PushOrchestrator (~220 lines, duplicated in VM + DI)

Ties together: destination resolution → transmission record creation → initial push attempt → retry scheduling.

**Reference**: `go-fdo-voucher-management/voucher_push_service.go`

### 4. DestinationResolver (~120 lines, duplicated in VM + DI)

Cascade of resolution strategies: external callback → partner store lookup → DID resolution → static URL fallback.

**Reference**: `go-fdo-voucher-management/voucher_destination.go`

### 5. TokenStore / Auth Middleware (~180 lines, duplicated in VM + Onboarding)

Bearer token management (create/validate/list/revoke/audit) for push receiver authentication.

**Reference**: `go-fdo-voucher-management/voucher_receiver_tokens.go`

### 6. LoadOrGenerateKey (~80 lines, in VM only but needed by all)

3-mode key management pattern:

1. **Import**: Load existing key from PEM file
2. **First-time init**: Generate key, persist to file, reload on restart
3. **Ephemeral**: Generate key in memory (dev/testing, with warning)

**Reference**: `go-fdo-voucher-management/did_minting_setup.go:loadOrGenerateOwnerKey()`

### 7. ExternalCommandExecutor (~46 lines, duplicated in VM + DI)

Shell-out helper for external callbacks with timeout, JSON stdin/stdout.

**Reference**: `go-fdo-voucher-management/external_executor.go`

---

## Fingerprint Algorithm — CRITICAL COMPATIBILITY NOTE

The library now provides **two** fingerprint algorithms:

| Function | Algorithm | Use Case |
|----------|-----------|----------|
| `did.FingerprintFDO()` | `SHA-256(CBOR(protocol.PublicKey))` | **FDO spec §9.8** — PullAuth tokens, partner trust store, voucher routing. Use this for all FDO operations. |
| `did.FingerprintJWK()` | `SHA-256(canonical_JWK_JSON)` per RFC 7638 | General-purpose key identification. NOT for FDO protocol operations. |

**If your app was previously using a different algorithm** (e.g., `SHA-256(PKIX_DER_bytes)` or JWK thumbprint), existing fingerprints stored in databases **will not match** `FingerprintFDO()` output. Plan a migration:

1. Add a DB migration that recomputes fingerprints using `did.FingerprintFDOHex()`
2. Or support both old and new fingerprints during a transition period

---

## Verification Checklist

After consolidation, each app should pass these checks:

- [ ] `go build ./...` succeeds
- [ ] `go test ./...` passes (no regressions)
- [ ] `gofmt -l .` shows no formatting issues
- [ ] `golangci-lint run` passes
- [ ] `go mod tidy` removes old dependencies (`go-did`, `base58`, `multibase`, etc.)
- [ ] Integration tests still pass (push, pull, PullAuth workflows)
- [ ] Fingerprints in the database match `did.FingerprintFDOHex()` output
- [ ] `did:key` and `did:web` resolution works via `did.Resolver`
- [ ] PEM encoding uses `fdo.FormatVoucherPEM()` / `fdo.FormatVoucherCBORToPEM()`

---

## Reference: VM Project Consolidation (Completed)

The go-fdo-voucher-management project has completed its consolidation. Key changes:

1. **`did_resolver.go`**: 271 lines → 79 lines (thin wrapper around `did.Resolver`). **Fixed critical JWK parsing bug**: the old `parseECJWK()`/`parseRSAJWK()` functions generated random keys instead of parsing JWK coordinates from the DID document, meaning all `did:web:` resolutions returned garbage keys. The library's `did.Resolver` does correct JWK parsing.
2. **`key_utils.go`**: 236 lines → 148 lines (fingerprint functions delegate to library)
3. **`did_resolver_test.go`**: Updated to use `did.ParseDIDKey` from library
4. **`owner_key_service.go`**: Fixed bug where resolver was created with `enabled=false` (always failed)
5. **Dependencies removed**: `github.com/mr-tron/base58` and 9 transitive deps
6. **Fingerprint unified**: All code paths now use CBOR-based `did.FingerprintFDO()`

Use the VM project as a reference for how to structure the thin wrappers.
