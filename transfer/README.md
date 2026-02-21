# go-fdo/transfer — Voucher Transfer Protocol

This package implements the Voucher Transfer Protocol for FIDO Device Onboard (FDO), including both **push** and **pull** models.

## PullAuth Protocol

The PullAuth protocol is a 3-message cryptographic handshake that allows a Voucher Recipient to authenticate to a Voucher Holder by proving possession of an Owner Key (or authorized Delegate Key). All messages use CBOR encoding and COSE_Sign1 signatures, consistent with the FDO protocol.

### Protocol Flow

```
Recipient                              Holder
    |                                    |
    |--- PullAuth.Hello ----------------->|  (OwnerKey, Nonce, ProtocolVersion)
    |                                    |
    |<-- PullAuth.Challenge -------------|  (SessionId, Nonce, HashHello, HolderSig)
    |                                    |
    |--- PullAuth.Prove ----------------->|  (SessionId, Nonce, HashChallenge, RecipientSig)
    |                                    |
    |<-- PullAuth.Result ----------------|  (SessionToken, Expiry, Fingerprint)
    |                                    |
```

### Message Types

- **`PullAuthHello`** — Sent by Recipient with their Owner Key, optional delegate chain, a nonce, and protocol version.
- **`PullAuthChallenge`** — Sent by Holder with a session ID, holder nonce, echo of recipient nonce, hash of Hello, and a COSE_Sign1 signature.
- **`PullAuthProve`** — Sent by Recipient with the session ID, echo of holder nonce, hash of Challenge, and a COSE_Sign1 signature proving key possession.
- **`PullAuthResult`** — Sent by Holder with a session token, expiry, owner key fingerprint, and optional voucher count.

### Delegate Support

Recipients can authenticate using a Delegate Key instead of the Owner Key directly. The delegate chain (X.509 certificates) must be rooted at the Owner Key and the leaf certificate must contain the `fdo-ekt-permit-voucher-claim` EKU (OID `1.3.6.1.4.1.45724.3.1.5`).

## Voucher Transceiver

The package provides unified interfaces for both push and pull voucher transfer:

### Push Model

- **`PushSender`** — Sends vouchers via HTTP multipart upload (`HTTPPushSender`)
- **`PushReceiver`** — Receives pushed vouchers via HTTP (`HTTPPushReceiver`)

### Pull Model

- **`PullInitiator`** — Authenticates via PullAuth, lists, and downloads vouchers (`HTTPPullInitiator`)
- **`PullHolder`** — Serves vouchers to authenticated recipients (`HTTPPullHolder`)

### Storage

- **`VoucherStore`** — Interface for voucher persistence (Save, Load, GetVoucher, List, Delete)

## Usage

### Server (Holder) Side

```go
server := &transfer.PullAuthServer{
    HolderKey: holderPrivateKey,
    Sessions:  transfer.NewSessionStore(60*time.Second, 1000),
    IssueToken: func(ownerKey protocol.PublicKey) (string, time.Time, error) {
        return generateToken(ownerKey)
    },
}
server.RegisterHandlers(mux)
```

### Client (Recipient) Side

```go
client := &transfer.PullAuthClient{
    OwnerKey: ownerPrivateKey,
    BaseURL:  "https://holder.example.com",
}
result, err := client.Authenticate()
// result.SessionToken can be used for Pull API requests
```

## Testing

```bash
go test -v ./transfer/...
```
