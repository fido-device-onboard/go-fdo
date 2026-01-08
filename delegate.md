# Delegate Support

This document describes the FDO Delegate Protocol support in go-fdo. Delegates allow a third party to act on behalf of the device owner during onboarding (TO2) or rendezvous registration (TO0).

## Overview

In standard FDO, the owner directly signs proofs and blobs. With delegation, a delegate certificate chain authorizes a third party to sign on the owner's behalf:

- **Standard**: `Owner -> Blob` (Owner signs Blob directly)
- **Delegated**: `Owner -> Delegate -> Blob` (Owner signs Delegate cert, Delegate key signs Blob)
- **Multi-level**: `Owner -> Delegate1 -> Delegate2 -> Blob`

Delegate support is available in both FDO 1.01 and FDO 2.0 protocols.

## Quick Start

### 1. Create Owner Keys with Certificates

```bash
rm test.db
go run ./examples/cmd server -http 127.0.0.1:9999 -db ./test.db -owner-certs
```

### 2. Create a Delegate Chain

```bash
go run ./examples/cmd delegate -db test.db create myDelegate onboard,redirect SECP384R1 ec384 ec384
```

This creates a delegate chain named `myDelegate` with:

- Permissions: `onboard` (TO2) and `redirect` (TO0)
- Root: SECP384R1 owner key
- Intermediate and leaf: ec384 keys

### 3. Run Device Initialization

```bash
go run ./examples/cmd client -di http://127.0.0.1:9999
```

### 4. Run TO0 with Delegate

```bash
GUID=$(sqlite3 test.db 'select hex(guid) from vouchers;')
go run ./examples/cmd server -db test.db -to0 http://127.0.0.1:9999 -rvDelegate myDelegate -to0-guid $GUID
```

### 5. Run TO1/TO2 with Delegate

```bash
# Server with delegate for onboarding
go run ./examples/cmd server -http 127.0.0.1:9999 -db ./test.db -onboardDelegate myDelegate -reuse-cred

# Client (in another terminal)
go run ./examples/cmd client
```

## Design Notes

The "key Type" from delegate keys (certs) isn't really authoritative, because cert chains may have a combination of different keys, and because delegate chains will be used for both RV blobs and TO2 services. We have added "names" to allow people to create different chains of different types for use in either of these.

The "keyType" field however is still used primarily for compatibility, and it refers to the leaf (first) certificate in the chain - i.e. the one which directly reflects the ("owner") key of the actual server (i.e. NOT necessarily the root "owner" key).

The rest of the implementation starts with a device key (type) that is created during DI, then during onboarding, the rest of the exchanges are done to an owner key of that same type (i.e. device provides eASignInfo during TO2.HelloDevice, and Onboarding Server then provides an owner key of the same type).

There is no guarantee that an X5Chain will have all the same keys of a certain-type only, especially when onboarding devices of different types.

This means that - unlike in most cases where the implementation will automagically keep key types consistent from DI through TO0, TO1, TO2 - under delegate, the caller has the flexibility and the *responsibility* to use any cert chain, even if it is mis-aligned (or mis-rooted) with the proper owner key, as will be determined by DI (defaults to ec384).

### Dynamic Delegate Name Resolution

The equal-sign (`=`) character in Delegate Name will be substituted with the key type for the device, as indicated in the Ownership Voucher. It will resolve to a chain by one of the names: `RSA2048RESTR`, `RSAPKCS`, `RSAPSS`, `SECP256R1` or `SECP384R1`.

This allows creation of chains like `rv_RSAPKCS` which would be automatically resolved by specifying a delegateName name `rv_=`.

## Permissions

Delegate certs can be scoped to only be allowed to do specific things. Per the FDO 1.2 specification, permissions are encoded as discrete OIDs in the certificate's Extended Key Usage extension.

### Permission OIDs

All permission OIDs are under the base `1.3.6.1.4.1.45724.3.1` (PERM):

| OID | Name | Description | Used In |
| --- | ---- | ----------- | ------- |
| `PERM.1` | `permit-redirect` | Sign a redirect blob for RV server | TO0 |
| `PERM.2` | `permit-onboard-new-cred` | Onboard with new credentials | TO2 |
| `PERM.3` | `permit-onboard-reuse-cred` | Onboard with credential reuse | TO2 |
| `PERM.4` | `permit-onboard-fdo-disable` | Onboard and disable FDO | TO2 |

Full OIDs:

- `1.3.6.1.4.1.45724.3.1.1` - fdo-ekt-permit-redirect
- `1.3.6.1.4.1.45724.3.1.2` - fdo-ekt-permit-onboard-new-cred
- `1.3.6.1.4.1.45724.3.1.3` - fdo-ekt-permit-onboard-reuse-cred
- `1.3.6.1.4.1.45724.3.1.4` - fdo-ekt-permit-onboard-fdo-disable

### CLI Permission Parameters

When creating delegate chains via CLI, you can use these permission strings:

| Permission | OIDs Added | Description |
| ---------- | ---------- | ----------- |
| `onboard` | PERM.2, PERM.3, PERM.4 | Shortcut for all three onboard permissions |
| `redirect` | PERM.1 | Redirect permission (TO0) |
| `onboard-new-cred` | PERM.2 | Onboard with new credentials only |
| `onboard-reuse-cred` | PERM.3 | Onboard with credential reuse only |
| `onboard-fdo-disable` | PERM.4 | Onboard and disable FDO only |
| `claim` | Legacy | Claim permission |
| `provision` | Legacy | Provision permission |

Multiple permissions can be combined with commas, e.g., `onboard,redirect` or `onboard-new-cred,redirect`.

### Credential Reuse Enforcement

When a device requests credential reuse during TO2, the client verifies that the delegate certificate chain contains the `permit-onboard-reuse-cred` (PERM.3) OID. If this permission is missing, credential reuse is rejected even if the delegate is otherwise valid for onboarding.

**Permission Rules:**

- A delegate cert must contain a given OID to be granted that permission
- A delegate cert must be signed (directly) by owner, or by another cert with that permission
- ALL certs in the chain (from owner downward) MUST have the permission for it to be valid
- For onboarding, at least one of PERM.2, PERM.3, or PERM.4 must be present
- For credential reuse specifically, PERM.3 must be present

## Certificate Chain Structure

The first cert in the chain must always be signed by the "Owner" key. The last cert in the chain is the one whose private key is retained and used for signing.

Unlike TLS where a Root CA Certificate is created and retained, in FDO when we create an initial "Owner" key, we don't necessarily create any such certificate. Therefore, when creating a Delegate chain, an "Owner CA" cert is created at the root of each chain, signed with the Private Key of the applicable `ownerKeyType`.

## CLI Commands

### Create Delegate Chain

```bash
go run ./examples/cmd delegate -db test.db create <chainName> <permissions> <ownerKeyType> [keyType...]
```

**Parameters:**

- `chainName` - Name for this delegate chain
- `permissions` - Comma-separated: `onboard`, `redirect`, or `onboard,redirect` (see [CLI Permission Parameters](#cli-permission-parameters))
- `ownerKeyType` - Root key type: `SECP384R1`, `SECP256R1`, `RSA2048RESTR`, `RSAPKCS`, `RSAPSS`
- `keyType...` - Optional intermediate/leaf key types (e.g., `ec384`, `ec256`, `rsa2048`)

### List Delegate Chains

```bash
go run ./examples/cmd delegate -db test.db list
```

### Print Delegate Chain

```bash
go run ./examples/cmd delegate -db test.db print <chainName>
```

### Inspect Voucher

```bash
go run ./examples/cmd delegate -db test.db inspectVoucher <voucher.ov>
```

## Server Flags

| Flag | Description |
| ---- | ----------- |
| `-onboardDelegate <name>` | Use delegate chain for TO2 onboarding |
| `-rvDelegate <name>` | Use delegate chain for TO0 RV blob signing |
| `-owner-certs` | Generate owner certificates (required for delegates) |

## Full End-to-End Test

### Terminal 1 - Server

```bash
rm test.db
go run ./examples/cmd server -http 127.0.0.1:9999 -db test.db -owner-certs -onboardDelegate myDelegate -reuse-cred
```

### Terminal 2 - Client

```bash
# Create delegate chain
go run ./examples/cmd delegate -db test.db create myDelegate onboard,redirect SECP384R1 ec384 ec384

# Device initialization
go run ./examples/cmd client -di http://127.0.0.1:9999

# Register with RV using delegate
GUID=$(sqlite3 test.db 'select hex(guid) from vouchers;')
go run ./examples/cmd server -db test.db -to0 http://127.0.0.1:9999 -rvDelegate myDelegate -to0-guid $GUID

# Run TO1 only (verify RV registration)
go run ./examples/cmd client -rv-only

# Run full TO1/TO2 with FDO 1.01
go run ./examples/cmd client

# Run full TO1/TO2 with FDO 2.0
go run ./examples/cmd client -fdo-version 200
```

## Troubleshooting

### Delegate Chain Validation Error

```text
Delegate Chain Validation error - 0 not signed by 1: x509: signature algorithm specifies an RSA public key, but have public key of type *ecdsa.PublicKey
```

**Cause:** DI was run with one key type (e.g., ec384 default), but the delegate cert was rooted with a different key type (e.g., RSA).

**Solution:** Ensure the delegate chain's root key type matches the owner key type used during DI. Use the `=` wildcard in delegate names to auto-resolve key types.

### Missing Owner Certificates

```text
owner key type SECP384R1 not supported
```

**Cause:** Server was not started with `-owner-certs` flag.

**Solution:** Restart server with `-owner-certs` to generate owner certificates required for delegate chains.

## Utility Commands

### Export Owner Keys

```bash
# Public key
go run ./examples/cmd server -db test.db -print-owner-public SECP384R1 > owner.pub

# Certificate chain
go run ./examples/cmd server -db test.db -print-owner-chain SECP384R1 > owner.cert

# Private key
go run ./examples/cmd server -db test.db -print-owner-private SECP384R1 > owner.key
```

### Inspect with OpenSSL

```bash
openssl x509 -text -noout -in owner.cert
openssl pkey -pubin -text -noout -in owner.pub
openssl pkey -text -noout -in owner.key
```
