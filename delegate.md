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

## CSR Workflow (Multi-Party Delegate Issuance)

The `delegate create` command above generates both the key AND the certificate in one shot. This is convenient for testing but doesn't work for real multi-party scenarios where one entity holds the owner key and another entity needs a delegate certificate.

The **CSR workflow** separates key generation from certificate signing, which is how production delegate issuance works:

### `create` vs. CSR Workflow

| Aspect | `delegate create` | CSR Workflow |
| ------ | ----------------- | ------------ |
| **Key generation** | Single command generates key + cert | Requester generates key + CSR separately |
| **Who holds private key** | Same entity that signs the cert | Requester holds private key; signer never sees it |
| **Use case** | Testing, single-org quick setup | Production multi-party, cross-org delegation |
| **Chain depth** | Supports multi-level intermediate chains | Depth 1 (leaf signed directly by owner key) |
| **Commands** | 1 command | 3 commands (generate-csr → sign-csr → import-cert) |

### Scenario A: Intra-Org Pull (Others Pull from You)

Your organization holds the owner key. Internal teams need to pull vouchers that are still signed to your key, without a sign-over. You issue them a delegate certificate with `voucher-claim` permission.

```text
┌──────────────┐                    ┌──────────────┐
│  Internal    │  1. CSR            │  Owner Key   │
│  Service     │ ─────────────────▶ │  Holder      │
│  (requester) │                    │  (signer)    │
│              │  2. Signed cert    │              │
│              │ ◀───────────────── │              │
│              │                    └──────────────┘
│              │
│              │  3. FDOKeyAuth (delegate)
│              │ ─────────────────▶  Server Service
│              │  4. Vouchers
│              │ ◀─────────────────
└──────────────┘
```

**Steps:**

```bash
# 1. Requester generates keypair + CSR (no database needed)
go run ./examples/cmd delegate generate-csr myService ec384 -key-out myService.key.pem > myService.csr.pem

# 2. Owner-key holder signs the CSR with voucher-claim permission
go run ./examples/cmd delegate -db owner.db sign-csr myService.csr.pem myDelegate voucher-claim SECP384R1 > signed.pem

# 3. Requester imports the signed cert + their private key
go run ./examples/cmd delegate -db requester.db import-cert myDelegate signed.pem myService.key.pem

# 4. Requester pulls vouchers using delegate authentication
fdo-voucher-manager pull -url http://holder:8083 \
    -owner-pub owner-public.pem \
    -delegate-key myService.key.pem \
    -delegate-chain signed.pem \
    -output ./vouchers/
```

### Scenario B: Cross-Org Pull (You Pull from Others)

An upstream provider holds the owner key. You need to pull vouchers from them. They issue you a delegate certificate with `voucher-claim` permission.

```bash
# 1. You generate a CSR
go run ./examples/cmd delegate generate-csr myOrg ec384 -key-out myOrg.key.pem > myOrg.csr.pem
# Send myOrg.csr.pem to the upstream provider

# 2. Upstream provider signs it (on their side)
go run ./examples/cmd delegate -db upstream.db sign-csr myOrg.csr.pem partnerDelegate voucher-claim SECP384R1 > signed.pem
# They send signed.pem back to you

# 3. You import the signed cert
go run ./examples/cmd delegate -db local.db import-cert partnerDelegate signed.pem myOrg.key.pem

# 4. You pull vouchers using the delegate cert
fdo-voucher-manager pull -url http://upstream-holder:8083 \
    -owner-pub upstream-owner-public.pem \
    -delegate-key myOrg.key.pem \
    -delegate-chain signed.pem \
    -output ./vouchers/
```

### CSR Workflow CLI Commands

#### `delegate generate-csr`

Generates a new keypair and CSR. The requester runs this command. No database required.

```bash
go run ./examples/cmd delegate generate-csr <subject-CN> <key-type> [-key-out <path>]
```

- `subject-CN` — Common Name for the CSR (e.g., `myService`, `myOrg`)
- `key-type` — `ec256`, `ec384`, `rsa2048`, `rsa3072`
- `-key-out` — Path to save private key PEM (default: `<subject>.key.pem`)
- CSR PEM is written to **stdout** (pipe or redirect to file)

#### `delegate sign-csr`

Signs a CSR using the local owner key, producing a delegate certificate with scoped permissions. The owner-key holder runs this command.

```bash
go run ./examples/cmd delegate -db <db> sign-csr <csr-file> <chain-name> <permissions> <owner-key-type>
```

- `csr-file` — Path to the CSR PEM file
- `chain-name` — Name to store the chain under in the database
- `permissions` — Comma-separated permission strings (see [CLI Permission Parameters](#cli-permission-parameters))
- `owner-key-type` — `SECP384R1`, `SECP256R1`, `RSAPKCS`, etc.
- Signed cert PEM is written to **stdout**
- Chain is also stored in the database (cert-only, no private key) for inspection via `delegate print`

#### `delegate import-cert`

Imports a signed delegate certificate chain and pairs it with a local private key. The requester runs this after receiving the signed cert.

```bash
go run ./examples/cmd delegate -db <db> import-cert <chain-name> <cert-chain.pem> <private-key.pem>
```

- `chain-name` — Name to store the chain under in the database
- `cert-chain.pem` — Signed certificate chain PEM (one or more certificates)
- `private-key.pem` — Private key PEM (must match the leaf cert's public key)

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

Delegate certs can be scoped to only be allowed to do specific things. Per the FDO 2.0 specification, permissions are encoded as discrete OIDs in the certificate's Extended Key Usage extension.

### Permission OIDs

All permission OIDs are under the base `1.3.6.1.4.1.45724.3.1` (PERM):

| OID | Name | Description | Used In |
| --- | ---- | ----------- | ------- |
| `PERM.1` | `permit-redirect` | Sign a redirect blob for RV server | TO0 |
| `PERM.2` | `permit-onboard-new-cred` | Onboard with new credentials | TO2 |
| `PERM.3` | `permit-onboard-reuse-cred` | Onboard with credential reuse | TO2 |
| `PERM.4` | `permit-onboard-fdo-disable` | Onboard and disable FDO | TO2 |
| `PERM.5` | `permit-voucher-claim` | Claim (pull/download) vouchers via FDOKeyAuth | Pull API |

Full OIDs:

- `1.3.6.1.4.1.45724.3.1.1` - fdo-ekt-permit-redirect
- `1.3.6.1.4.1.45724.3.1.2` - fdo-ekt-permit-onboard-new-cred
- `1.3.6.1.4.1.45724.3.1.3` - fdo-ekt-permit-onboard-reuse-cred
- `1.3.6.1.4.1.45724.3.1.4` - fdo-ekt-permit-onboard-fdo-disable
- `1.3.6.1.4.1.45724.3.1.5` - fdo-ekt-permit-voucher-claim

### CLI Permission Parameters

When creating delegate chains via CLI, you can use these permission strings:

| Permission | OIDs Added | Description |
| ---------- | ---------- | ----------- |
| `onboard` | PERM.2, PERM.3, PERM.4 | Shortcut for all three onboard permissions |
| `redirect` | PERM.1 | Redirect permission (TO0) |
| `onboard-new-cred` | PERM.2 | Onboard with new credentials only |
| `onboard-reuse-cred` | PERM.3 | Onboard with credential reuse only |
| `onboard-fdo-disable` | PERM.4 | Onboard and disable FDO only |
| `voucher-claim` | PERM.5 | Claim (pull/download) vouchers via FDOKeyAuth |
| `claim` | Legacy | Legacy claim permission |
| `provision` | Legacy | Legacy provision permission |

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
