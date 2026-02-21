# Voucher Transfer Protocol — Application Developer Guide

This document describes how to use the `transfer` and `did` packages in your own applications for voucher management. These packages are designed for **server-side applications** such as:

- **Manufacturing systems** — Push vouchers to owner services after device initialization
- **Voucher management systems** — Store, organize, and forward vouchers between parties
- **Onboarding services** — Pull vouchers from manufacturing or receive pushed vouchers

> **Important:** These packages are NOT for FDO clients (devices). Devices use the standard FDO TO1/TO2 protocols for onboarding. This library is for the server-side infrastructure that manages voucher lifecycle.

## Overview

The voucher transfer system supports two models:

| Model | Direction | Use Case |
|-------|-----------|----------|
| **Push** | Sender → Receiver | Manufacturing pushes vouchers to owner service |
| **Pull** | Initiator ← Holder | Owner service pulls vouchers from manufacturing |

Both models use HTTP and support authentication via Bearer tokens or cryptographic proof (PullAuth).

## Quick Start

### Push Model (Sender Side)

```go
package main

import (
    "context"
    "log"

    "github.com/fido-device-onboard/go-fdo/transfer"
)

func main() {
    sender := transfer.NewHTTPPushSender()

    // After device initialization, push the voucher to the owner service
    err := sender.Push(context.Background(),
        transfer.PushDestination{
            URL:   "https://owner-service.example.com/api/v1/vouchers",
            Token: "your-api-token", // Bearer token for authentication
        },
        &transfer.VoucherData{
            VoucherInfo: transfer.VoucherInfo{
                GUID:         "abc123...",
                SerialNumber: "SN-12345",
                ModelNumber:  "MODEL-A",
            },
            Voucher: voucher, // *fdo.Voucher from DI
            Raw:     rawCBOR, // CBOR-encoded voucher bytes
        },
    )
    if err != nil {
        log.Fatal(err)
    }
}
```

### Push Model (Receiver Side)

```go
package main

import (
    "net/http"

    "github.com/fido-device-onboard/go-fdo/transfer"
)

func main() {
    receiver := &transfer.HTTPPushReceiver{
        Store: yourVoucherStore, // implements transfer.VoucherStore
        Authenticate: func(r *http.Request) bool {
            // Validate Bearer token or other auth
            token := r.Header.Get("Authorization")
            return validateToken(token)
        },
        OnReceive: func(ctx context.Context, data *transfer.VoucherData, path string) {
            // Optional: trigger downstream processing
            log.Printf("Received voucher %s, stored at %s", data.GUID, path)
        },
    }

    http.Handle("/api/v1/vouchers", receiver)
    http.ListenAndServe(":8080", nil)
}
```

### Pull Model with PullAuth (Cryptographic Authentication)

The pull model uses a 3-message cryptographic handshake where the recipient proves possession of an Owner Key (or Delegate Key) to authenticate.

#### Holder Side (Serves Vouchers)

```go
package main

import (
    "crypto/ecdsa"
    "net/http"
    "time"

    "github.com/fido-device-onboard/go-fdo/protocol"
    "github.com/fido-device-onboard/go-fdo/transfer"
)

func main() {
    holderKey := loadHolderPrivateKey() // Your holder's signing key

    // PullAuth server handles the cryptographic handshake
    authServer := &transfer.PullAuthServer{
        HolderKey: holderKey,
        HashAlg:   protocol.Sha256Hash,
        Sessions:  transfer.NewSessionStore(5*time.Minute, 1000),
        IssueToken: func(ownerKey protocol.PublicKey) (string, time.Time, error) {
            // Generate a session token for authenticated owner
            token := generateToken(ownerKey)
            expiry := time.Now().Add(1 * time.Hour)
            return token, expiry, nil
        },
        LookupVouchers: func(ownerKey protocol.PublicKey) (int, error) {
            // Return count of vouchers for this owner, or -1 if none
            count := countVouchersForOwner(ownerKey)
            return count, nil
        },
    }

    // Pull holder serves the actual voucher list/download endpoints
    pullHolder := &transfer.HTTPPullHolder{
        Store: yourVoucherStore,
        ValidateToken: func(token string) ([]byte, error) {
            // Validate token and return owner key fingerprint
            return validateAndGetFingerprint(token)
        },
    }

    mux := http.NewServeMux()
    authServer.RegisterHandlers(mux)
    pullHolder.RegisterHandlers(mux)

    http.ListenAndServe(":8080", mux)
}
```

#### Initiator Side (Downloads Vouchers)

```go
package main

import (
    "context"
    "log"

    "github.com/fido-device-onboard/go-fdo/protocol"
    "github.com/fido-device-onboard/go-fdo/transfer"
)

func main() {
    ownerKey := loadOwnerPrivateKey() // Your owner's private key

    initiator := &transfer.HTTPPullInitiator{
        Auth: &transfer.PullAuthClient{
            OwnerKey: ownerKey,
            HashAlg:  protocol.Sha256Hash,
            BaseURL:  "https://manufacturing.example.com",
        },
        Store: yourVoucherStore, // Optional: persist downloaded vouchers
    }

    // PullAll authenticates, lists, and downloads all vouchers
    vouchers, err := initiator.PullAll(context.Background())
    if err != nil {
        log.Fatal(err)
    }

    for _, v := range vouchers {
        log.Printf("Downloaded voucher: %s", v.GUID)
    }
}
```

## DID Integration

The `did` package provides DID (Decentralized Identifier) support for discovering voucher recipient endpoints.

### Minting a DID for Your Service

```go
package main

import (
    "log"
    "net/http"

    "github.com/fido-device-onboard/go-fdo/did"
)

func main() {
    // Mint a new DID with owner key and voucher recipient URL
    result, err := did.Mint(
        "myservice.example.com",                    // host
        "",                                          // path (empty for root)
        "https://myservice.example.com/api/v1/vouchers", // voucher push endpoint
        did.KeyConfig{Type: "EC", Curve: "P-384"},  // key config
    )
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("DID URI: %s", result.DIDURI)
    // Output: did:web:myservice.example.com

    // Save the private key securely
    privPEM, _ := did.ExportPrivateKeyPEM(result.PrivateKey)
    saveToSecureStorage(privPEM)

    // Serve the DID document
    handler, _ := did.NewHandler(result.DIDDocument)
    mux := http.NewServeMux()
    handler.RegisterHandlers(mux, "")
    // Serves at GET /.well-known/did.json

    http.ListenAndServe(":8080", mux)
}
```

### Resolving a DID to Find Voucher Endpoint

```go
package main

import (
    "context"
    "log"

    "github.com/fido-device-onboard/go-fdo/did"
)

func main() {
    resolver := did.NewResolver()

    result, err := resolver.Resolve(context.Background(), "did:web:partner.example.com")
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Public Key: %T", result.PublicKey)
    log.Printf("Voucher Recipient URL: %s", result.VoucherRecipientURL)
    // Use VoucherRecipientURL to push vouchers to this partner
}
```

## Authentication Methods

### Token-Based Authentication (Push)

Simple Bearer token authentication for push operations:

```go
receiver := &transfer.HTTPPushReceiver{
    Store: store,
    Authenticate: func(r *http.Request) bool {
        auth := r.Header.Get("Authorization")
        if !strings.HasPrefix(auth, "Bearer ") {
            return false
        }
        token := strings.TrimPrefix(auth, "Bearer ")
        return validateAPIToken(token) // Your token validation logic
    },
}
```

### Owner Key Authentication (Pull)

Cryptographic proof of Owner Key possession via PullAuth:

```go
// The PullAuth protocol proves the initiator possesses the Owner Key
// without revealing the private key. This is the recommended method
// for pull operations as it provides strong authentication tied to
// the FDO ownership chain.

client := &transfer.PullAuthClient{
    OwnerKey:      ownerPrivateKey,     // ECDSA or RSA private key
    DelegateChain: delegateCerts,       // Optional: X.509 delegate chain
    HashAlg:       protocol.Sha384Hash, // SHA-256 or SHA-384
    BaseURL:       "https://holder.example.com",
}

result, err := client.Authenticate()
// result.SessionToken can be used for subsequent API calls
```

### Delegate Key Authentication

For delegated operations, include the delegate certificate chain:

```go
client := &transfer.PullAuthClient{
    OwnerKey:      delegatePrivateKey,
    DelegateChain: []*x509.Certificate{delegateCert, intermediateCert},
    HashAlg:       protocol.Sha256Hash,
    BaseURL:       "https://holder.example.com",
}
```

The delegate chain must be rooted at the Owner Key and the leaf certificate must contain the `fdo-ekt-permit-voucher-claim` EKU (OID `1.3.6.1.4.1.45724.3.1.5`).

## Implementing VoucherStore

Both push and pull operations use the `VoucherStore` interface:

```go
type VoucherStore interface {
    Save(ctx context.Context, data *VoucherData) (string, error)
    Load(ctx context.Context, guid string) (*VoucherData, error)
    GetVoucher(ctx context.Context, ownerKeyFingerprint []byte, guid string) (*VoucherData, error)
    List(ctx context.Context, ownerKeyFingerprint []byte, continuation string, limit int) (*VoucherListResponse, error)
    Delete(ctx context.Context, guid string) error
}
```

Example SQLite implementation:

```go
type SQLiteVoucherStore struct {
    db *sql.DB
}

func (s *SQLiteVoucherStore) Save(ctx context.Context, data *transfer.VoucherData) (string, error) {
    _, err := s.db.ExecContext(ctx,
        `INSERT INTO vouchers (guid, serial, model, device_info, raw) VALUES (?, ?, ?, ?, ?)`,
        data.GUID, data.SerialNumber, data.ModelNumber, data.DeviceInfo, data.Raw,
    )
    return data.GUID, err
}

func (s *SQLiteVoucherStore) Load(ctx context.Context, guid string) (*transfer.VoucherData, error) {
    row := s.db.QueryRowContext(ctx,
        `SELECT guid, serial, model, device_info, raw FROM vouchers WHERE guid = ?`,
        guid,
    )
    // ... scan and return
}
```

## Error Handling

### Push Errors

```go
err := sender.Push(ctx, dest, data)
if err != nil {
    // Check for specific error types
    if strings.Contains(err.Error(), "HTTP 401") {
        // Authentication failed
    } else if strings.Contains(err.Error(), "HTTP 400") {
        // Invalid voucher data
    }
}
```

### Pull Errors

```go
result, err := client.Authenticate()
if err != nil {
    // PullAuth errors include:
    // - "HTTP 401" - Invalid signature or expired session
    // - "HTTP 404" - No vouchers for this owner key
    // - "session not found or expired" - Session timeout
}
```

## Security Considerations

1. **Transport Security**: Always use HTTPS in production
2. **Key Storage**: Store private keys securely (HSM, encrypted storage)
3. **Token Expiration**: Set reasonable token expiration times
4. **Rate Limiting**: Implement rate limiting on push/pull endpoints
5. **Audit Logging**: Log all voucher transfers for compliance

## Testing

Run the unit tests:

```bash
go test -v ./transfer/...
go test -v ./did/...
```

Run all tests including integration:

```bash
make test
```

## See Also

- [transfer/README.md](transfer/README.md) — Package-level documentation
- [did/README.md](did/README.md) — DID package documentation
- [delegate.md](delegate.md) — Delegate certificate documentation
