# Library Consolidation TODO

## The Problem: Massive Code Duplication

Three applications — **go-fdo-voucher-management** (VM), **go-fdo-di** (DI), and
**go-fdo-onboarding-service** (Onboarding) — each independently re-implemented
functionality that **already exists in this library**. The library's `did/`, `transfer/`,
and `http/` packages collectively provide ~3,500 lines of tested, production-quality code
for DID operations, voucher transfer, and FDO protocol transport. The apps duplicated
large portions of this — often poorly.

**Your primary directive is: audit your app for code that duplicates library functionality,
and replace it with calls to the library.** Do not fix app-level code that the library
already does correctly. Delete it and use the library.

---

## How to Approach This

### Step 1: Understand What the Library Provides

Before changing anything, read the library packages your app depends on. The key packages
are summarized below, but you should **read the actual source** to understand the full API:

- **`did/`** (~960 lines) — DID minting, resolution, document construction, serving,
  JWK conversion, PEM utilities, fingerprinting
- **`transfer/`** (~1,750 lines) — Push sender/receiver, Pull holder/initiator, PullAuth
  client/server, voucher store interface, session management, COSE signing/verification
- **`http/`** (~680 lines) — FDO protocol HTTP transport (client `Transport` and server
  `Handler`), token management, request/response debug logging, encryption/decryption

### Step 2: Audit Your App for Duplicates

Go file-by-file through your app and ask: **"Does the library already do this?"**

Common duplications found in the apps include:

| App-level code | Library equivalent | Package |
|---|---|---|
| `did_resolver.go` (DID resolution, JWK parsing, caching) | `did.Resolver`, `did.JWKToPublicKey`, `did.ParseDIDKey` | `did/` |
| `parseDIDKey()` / base58 decoding | `did.ParseDIDKey()` (zero external deps) | `did/` |
| `parseECJWK()` / `parseRSAJWK()` | `did.JWKToPublicKey()` | `did/` |
| `webDIDToURL()` | `did.WebDIDToURL()` | `did/` |
| `FingerprintPublicKey()` / `publicKeyToProtocol()` | `did.FingerprintFDO()` / `did.FingerprintFDOHex()` | `did/` |
| `FingerprintProtocolKey()` | `did.FingerprintProtocolKey()` | `did/` |
| DID document construction | `did.NewDocument()` | `did/` |
| DID document HTTP serving | `did.NewHandler()` / `did.Handler.RegisterHandlers()` | `did/` |
| Key generation + DID creation | `did.Mint()` | `did/` |
| `LoadPrivateKeyFromPEM()` / PEM export | `did.LoadPrivateKeyPEM()` / `did.ExportPrivateKeyPEM()` / `did.ExportPublicKeyPEM()` | `did/` |
| `VoucherPushClient` (HTTP multipart push) | `transfer.HTTPPushSender` / `transfer.NewHTTPPushSender()` | `transfer/` |
| `VoucherReceiverHandler` (push receiver) | `transfer.HTTPPushReceiver` | `transfer/` |
| `VoucherFileStore` / voucher storage | `transfer.VoucherStore` interface | `transfer/` |
| Passing raw bytes + `fdo.Voucher` separately | `transfer.VoucherData` (unified struct) | `transfer/` |
| PullAuth server implementation | `transfer.PullAuthServer` (412 lines, complete) | `transfer/` |
| PullAuth client implementation | `transfer.PullAuthClient` (353 lines, complete) | `transfer/` |
| Pull list/download handler | `transfer.HTTPPullHolder` (218 lines, complete) | `transfer/` |
| Pull authenticate + download all | `transfer.HTTPPullInitiator` (215 lines, complete) | `transfer/` |
| FDO protocol HTTP handler (DI/TO1/TO2) | `http.Handler` (369 lines, handles all message types) | `http/` |
| FDO protocol HTTP client transport | `http.Transport` (198 lines, with encryption) | `http/` |
| Authorization token jar | `http.AuthorizationJar` interface + default impl | `http/` |

### Step 3: Replace, Don't Fix

For each duplicate you find:

1. **Delete the app-level implementation**
2. **Import and call the library version**
3. **Keep only thin wrappers** if your app needs app-specific behavior (e.g., caching
   around `did.Resolver`, or additional auth checks around `transfer.HTTPPushReceiver`)

### Step 4: Clean Up Dependencies

After replacing duplicates, run `go mod tidy`. You should see external dependencies
disappear (e.g., `go-did`, `base58`, `multibase`) because the library has zero external
dependencies for the same functionality.

---

## ⚠️ CRITICAL SECURITY BUG: App-Level JWK Parsing

> **The `parseECJWK()` and `parseRSAJWK()` functions in the app-level DID resolvers
> are BROKEN.** They **generate brand-new random keys** instead of parsing the JWK
> coordinates from the DID document. This means any `did:web:` resolution silently
> returns a random public key that has **nothing to do with the actual DID owner**.
> Any cached "resolved" keys are garbage.
>
> The caching logic itself (store on success, keep on failure) is sound — the
> underlying JWK parse was just silently wrong.
>
> **The fix is simple: delete `parseECJWK`/`parseRSAJWK` and use `did.Resolver`
> from the library, which calls `did.JWKToPublicKey()` with correct base64url
> decoding, coordinate validation, and curve-on-point checks.**
>
> Do NOT attempt to fix the app-level parsing functions. Just delete them.

---

## Library API Reference

### `did/` package — DID Operations

**Resolution** (replaces app-level `did_resolver.go`):

- `did.NewResolver() *Resolver` — Create resolver with 30s HTTP timeout
- `did.Resolver.Resolve(ctx, didURI) (*ResolveResult, error)` — Resolve `did:web:` or `did:key:` to public key + service endpoints
- `did.Resolver.InsecureHTTP bool` — Allow HTTP for `did:web` in dev/testing
- `did.ParseDIDKey(uri) (crypto.PublicKey, error)` — Decode `did:key:z...` → P-256/P-384 public key (inline base58-btc, zero deps)
- `did.ResolveResult` — Contains `.PublicKey`, `.VoucherRecipientURL`, `.Document`

**JWK conversion** (replaces app-level `parseECJWK`/`parseRSAJWK`):

- `did.PublicKeyToJWK(pub) (*JWK, error)` — crypto.PublicKey → JWK
- `did.JWKToPublicKey(jwk) (crypto.PublicKey, error)` — JWK → crypto.PublicKey (correct parsing!)

**DID document construction** (replaces app-level document building):

- `did.NewDocument(didURI, pub, recipientURL, holderURL) (*Document, error)` — Build complete DID Document
- `did.Document.JSON() ([]byte, error)` — Pretty-print as JSON
- `did.NewHandler(doc) (*Handler, error)` — HTTP handler for `/.well-known/did.json`
- `did.Handler.RegisterHandlers(mux, subPath)` — Register on mux

**Key minting** (replaces app-level key gen + doc creation):

- `did.Mint(host, path, recipientURL, holderURL, keyCfg) (*MintResult, error)`
- `did.MintResult` — Contains `.PrivateKey`, `.PublicKey`, `.DIDDocument`, `.DIDURI`
- `did.WebDID(host, path) string` — Construct `did:web:` URI
- `did.WebDIDToURL(didURI) (string, error)` — `did:web:` → `https://.../.well-known/did.json`

**PEM utilities** (replaces app-level PEM load/save):

- `did.LoadPrivateKeyPEM(data) (crypto.Signer, error)` — Handles PKCS8, PKCS1, EC
- `did.ExportPrivateKeyPEM(key) ([]byte, error)`
- `did.ExportPublicKeyPEM(pub) ([]byte, error)`

**Fingerprinting** (replaces app-level `FingerprintPublicKey` etc.):

- `did.FingerprintFDO(pub) ([]byte, error)` — SHA-256 of CBOR-encoded `protocol.PublicKey` (**spec §9.8 correct**)
- `did.FingerprintFDOHex(pub) string` — Hex-encoded version
- `did.FingerprintProtocolKey(pub protocol.PublicKey) ([]byte, error)` — From protocol key directly
- `did.FingerprintJWK(pub) ([]byte, error)` — JWK Thumbprint (RFC 7638, NOT for FDO protocol use)

### `transfer/` package — Voucher Transfer

**Push model** (replaces app-level `VoucherPushClient`, `VoucherReceiverHandler`):

- `transfer.NewHTTPPushSender() *HTTPPushSender`
- `transfer.HTTPPushSender.Push(ctx, dest, data) error`
- `transfer.HTTPPushReceiver` — HTTP handler with `.Store`, `.Authenticate`, `.OnReceive`
- `transfer.PushDestination` — `.URL` + `.Token`
- `transfer.VoucherData` — Unified struct: `.GUID`, `.SerialNumber`, `.Voucher`, `.Raw`
- `transfer.VoucherStore` interface — `.Save()`, `.Load()`, `.GetVoucher()`, `.List()`, `.Delete()`

**Pull model** (replaces app-level PullAuth and pull handlers):

- `transfer.PullAuthServer` — Complete Holder-side PullAuth (`.HandleHello`, `.HandleProve`, `.RegisterHandlers`)
- `transfer.PullAuthClient` — Complete Recipient-side PullAuth (`.Authenticate()`)
- `transfer.HTTPPullHolder` — Serves voucher list + download (`.HandleListVouchers`, `.HandleDownloadVoucher`, `.RegisterHandlers`)
- `transfer.HTTPPullInitiator` — Authenticate + list + download (`.PullAll()`)
- `transfer.PullAuthClient.PathPrefix` — Configurable Pull Service Root (defaults to `/api/v1/pull/vouchers`)
- `transfer.PullAuthServer.RegisterHandlers(mux, root...)` — Variadic root path

**Session management**:

- `transfer.SessionStore` — In-memory PullAuth session store with TTL and max-sessions
- `transfer.TokenIssuer` / `transfer.TokenValidator` — Callbacks for token lifecycle
- `transfer.VoucherLookup` — Callback for voucher existence checks

### `http/` package — FDO Protocol Transport

**Server-side** (replaces app-level FDO protocol HTTP handlers):

- `http.Handler` — Handles all DI, TO0, TO1, TO2 messages via `POST /fdo/{ver}/msg/{type}`
- Automatic encryption/decryption for TO2 messages after key exchange
- Token management via `http.AuthorizationJar`
- Content length validation
- Debug request/response logging

**Client-side** (replaces app-level FDO protocol HTTP clients):

- `http.Transport` — Sends FDO messages, handles response parsing, encryption/decryption
- `http.Transport.FdoVersion` — Supports 1.01 and 2.0
- `http.Transport.Auth` — `AuthorizationJar` for token management
- `http.Transport.BaseURL` — Target server URL

---

## Per-Project Instructions

### go-fdo-di (DI / Manufacturer)

DI is the **worst offender** with ~1,400 lines of duplicate code.

**Audit these files** — each likely has a library replacement:

| App file | Likely library replacement | Action |
|---|---|---|
| `did_resolver.go` (~635 lines) | `did.Resolver` (~50 lines wrapper) | **Delete + replace (SECURITY BUG — see above)** |
| `voucher_push_client.go` (~132 lines) | `transfer.HTTPPushSender` | Delete + replace |
| `key_utils.go` (fingerprint functions) | `did.FingerprintFDO*()` | Delete fingerprint funcs, call library |
| PEM load/save functions | `did.LoadPrivateKeyPEM()` / `did.ExportPrivateKeyPEM()` | Delete + replace |
| DID document construction | `did.NewDocument()` / `did.NewHandler()` | Delete + replace |
| JWK conversion | `did.PublicKeyToJWK()` / `did.JWKToPublicKey()` | Delete + replace |
| `voucher_transmission_store.go` (~454 lines) | Not yet in library | Keep for now |
| `voucher_retry_worker.go` (~119 lines) | Not yet in library | Keep for now |

**After cleanup**: Run `go mod tidy`. Expected removals: `go-did`, `base58`, `multibase`, and their transitive deps.

**Reference**: See `go-fdo-voucher-management/did_resolver.go` (79 lines total — that's the
entire DID resolver after consolidation, down from 635).

### go-fdo-onboarding-service (Onboarding / Owner)

Onboarding has ~730 lines of duplicates.

**Audit these files**:

| App file | Likely library replacement | Action |
|---|---|---|
| `voucher_receiver_handler.go` (~360 lines) | `transfer.HTTPPushReceiver` | Delete + replace |
| `voucher_receiver_tokens.go` (~188 lines) | Not yet in library | Keep for now |
| Any `did_resolver.go` or JWK parsing | `did.Resolver` | **Delete + replace (check for SECURITY BUG)** |
| Fingerprint functions | `did.FingerprintFDO*()` | Delete + replace |
| PEM encoding (manual base64 line-wrapping) | `fdo.FormatVoucherCBORToPEM()` | Delete + replace |

**Special concern**: Onboarding's voucher receiver may have its own PEM encoding that
does manual base64 line-wrapping instead of using `fdo.FormatVoucherCBORToPEM()`. Fix this.

---

## What's NOT Yet in the Library (Keep in App)

These components are duplicated across apps but are not yet in the library. Keep them
in-app for now, but be aware they are candidates for future library consolidation:

| Component | ~Lines | Duplicated in | Future library location |
|---|---|---|---|
| TransmissionStore (SQLite push queue) | ~450 | VM + DI | `transfer.TransmissionStore` |
| RetryWorker (exponential backoff) | ~120 | VM + DI | `transfer.RetryWorker` |
| PushOrchestrator (destination → push → retry) | ~220 | VM + DI | `transfer.PushOrchestrator` |
| DestinationResolver (callback → partner → DID → static) | ~120 | VM + DI | `transfer.DestinationResolver` |
| TokenStore / Auth Middleware (bearer tokens) | ~180 | VM + Onboarding | `transfer.TokenStore` |
| LoadOrGenerateKey (3-mode key management) | ~80 | VM only | `did.LoadOrGenerateKey` |
| ExternalCommandExecutor (shell-out helper) | ~46 | VM + DI | TBD |

---

## Fingerprint Algorithm — Compatibility Note

The library provides **two** fingerprint algorithms:

| Function | Algorithm | Use Case |
|---|---|---|
| `did.FingerprintFDO()` | `SHA-256(CBOR(protocol.PublicKey))` | **FDO spec §9.8** — use for all FDO operations |
| `did.FingerprintJWK()` | `SHA-256(canonical_JWK_JSON)` per RFC 7638 | General-purpose, NOT for FDO protocol |

**If your app used a different algorithm** (e.g., `SHA-256(PKIX_DER)` or JWK thumbprint),
existing fingerprints in databases **will not match**. Plan a migration or support both
during transition.

---

## Verification Checklist

After consolidation, each app should pass:

- [ ] `go build ./...` succeeds
- [ ] `go test ./...` passes
- [ ] `gofmt -l .` clean
- [ ] `golangci-lint run` passes
- [ ] `go mod tidy` removes old deps (`go-did`, `base58`, `multibase`, etc.)
- [ ] Integration tests pass (push, pull, PullAuth workflows)
- [ ] Fingerprints match `did.FingerprintFDOHex()` output
- [ ] `did:key` and `did:web` resolution works via `did.Resolver`

---

## Reference: VM Project Consolidation (Completed)

The go-fdo-voucher-management project has completed its consolidation and serves as the
reference for how to do this. Key outcomes:

1. **`did_resolver.go`**: 635 → 79 lines (thin wrapper around `did.Resolver`). Fixed the critical JWK parsing bug.
2. **`key_utils.go`**: 236 → 148 lines (fingerprint functions delegate to library).
3. **`did_resolver_test.go`**: Updated to use `did.ParseDIDKey` from library.
4. **Dependencies removed**: `github.com/mr-tron/base58` and 9 transitive deps.
5. **Fingerprint unified**: All code paths use CBOR-based `did.FingerprintFDO()`.

The pattern in every case was the same: find app code that duplicates library code,
delete it, import and call the library instead. The app retains only thin wrappers
for app-specific concerns (caching, config integration, etc.).
