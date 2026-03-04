# go-fdo/transfer — Voucher Transfer Protocol

This package implements the Voucher Transfer Protocol for FIDO Device Onboard (FDO), including both **push** and **pull** models.

## FDOKeyAuth Protocol

The FDOKeyAuth protocol is a 3-message cryptographic handshake that allows a Caller to authenticate to a Server by proving possession of an enrolled key (Owner Key for pull, Supplier Key for push). All messages use CBOR encoding and COSE_Sign1 signatures, consistent with the FDO protocol.

### Protocol Flow

```
Caller                                 Server
    |                                    |
    |--- FDOKeyAuth.Hello --------------->|  (CallerKey, Nonce, ProtocolVersion)
    |                                    |
    |<-- FDOKeyAuth.Challenge ------------|  (SessionId, Nonce, HashHello, ServerSig)
    |                                    |
    |--- FDOKeyAuth.Prove --------------->|  (SessionId, Nonce, HashChallenge, CallerSig)
    |                                    |
    |<-- FDOKeyAuth.Result ---------------|  (SessionToken, Expiry, Fingerprint)
    |                                    |
```

### Message Types

- **`FDOKeyAuthHello`** — Sent by Caller with their key, optional delegate chain, a nonce, and protocol version.
- **`FDOKeyAuthChallenge`** — Sent by Server with a session ID, server nonce, echo of caller nonce, hash of Hello, and a COSE_Sign1 signature.
- **`FDOKeyAuthProve`** — Sent by Caller with the session ID, echo of server nonce, hash of Challenge, and a COSE_Sign1 signature proving key possession.
- **`FDOKeyAuthResult`** — Sent by Server with a session token, expiry, key fingerprint, and optional voucher count.

### Delegate Support

Callers can authenticate using a Delegate Key instead of the enrolled key directly. The delegate chain (X.509 certificates) must be rooted at the Caller's key and the leaf certificate must contain the `fdo-ekt-permit-voucher-claim` EKU (OID `1.3.6.1.4.1.45724.3.1.5`).

When using delegate-based auth, the Caller typically does not possess the owner's private key — only the owner's public key. The `FDOKeyAuthClient` supports this via the `CallerPublicKey` field:

```go
client := &transfer.FDOKeyAuthClient{
    CallerPublicKey: ownerPublicKey,    // Owner's public key (identifies whose vouchers to pull)
    DelegateKey:     delegatePrivKey,   // Delegate's private key (used for signing)
    DelegateChain:   delegateCertChain, // X.509 cert chain (root first, leaf last)
    BaseURL:         "https://server.example.com",
}
result, err := client.Authenticate()
```

For how to issue delegate certificates using the CSR workflow, see [delegate.md](../delegate.md#csr-workflow-multi-party-delegate-issuance).

## Voucher Transceiver

The package provides unified interfaces for both push and pull voucher transfer:

### Push Model

- **`PushSender`** — Sends vouchers via HTTP multipart upload (`HTTPPushSender`)
- **`PushReceiver`** — Receives pushed vouchers via HTTP (`HTTPPushReceiver`)

### Pull Model

- **`PullInitiator`** — Authenticates via FDOKeyAuth, lists, and downloads vouchers (`HTTPPullInitiator`)
- **`PullHolder`** — Serves vouchers to authenticated callers (`HTTPPullHolder`)

### Storage

- **`VoucherStore`** — Interface for voucher persistence (Save, Load, GetVoucher, List, Delete)

## Usage

### Server Side

```go
server := &transfer.FDOKeyAuthServer{
    ServerKey: serverPrivateKey,
    Sessions:  transfer.NewSessionStore(60*time.Second, 1000),
    IssueToken: func(callerKey protocol.PublicKey) (string, time.Time, error) {
        return generateToken(callerKey)
    },
}
server.RegisterHandlers(mux) // defaults to /api/v1/pull/vouchers/auth/{hello,prove}
// For push auth, use a different root:
// server.RegisterHandlers(mux, "/api/v1/vouchers")
```

### Client (Caller) Side

```go
client := &transfer.FDOKeyAuthClient{
    CallerKey:       ownerPrivateKey,
    BaseURL:         "https://server.example.com",
    ServerPublicKey: serverPublicKey, // optional: verify Server's signature
}
result, err := client.Authenticate()
// result.SessionToken can be used for Pull or Push API requests
```

#### ServerSignature Verification

If `ServerPublicKey` is set, the client cryptographically verifies the Server's COSE_Sign1 signature in `FDOKeyAuth.Challenge`. This proves the Server possesses the private key corresponding to its DID-published public key, preventing MITM attacks. The verification checks:

1. **Signature**: COSE_Sign1 over the challenge payload
2. **Payload contents**: type tag, both nonces, hash of Hello, and the Caller Key all match expected values

If `ServerPublicKey` is nil, verification is skipped with a warning logged. The Server's public key is typically obtained from the `FDOVoucherHolder` or `FDOVoucherRecipient` service entry in the Server's DID document.

## Testing

```bash
go test -v ./transfer/...
```
