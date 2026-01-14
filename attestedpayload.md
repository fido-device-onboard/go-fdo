# Attested Payload

An attested payload combines data—such as a configuration, command, or state declaration—with cryptographic proof of its authenticity. The payload is digitally signed, and an Ownership Voucher is included to establish the signer's authority. This allows a device that has completed manufacturing to verify that the payload originated from its legitimate owner by validating the signature against the ownership chain.

In some cases, the payload may not be signed directly by the owner. Instead, a Delegate Certificate—signed by the owner—can authorize a third party to sign on the owner's behalf. When delegation is used, the attested payload includes this certificate chain, allowing the device to verify both the delegate's authority and the payload's integrity.

If a device's attestation key (DAK) is an RSA key, it can be used to encrypt the payload. This is useful for encrypting the payload to prevent eavesdropping.

Thus, the attested payload may consist of the following parts:

| Payload | What | When |
| ---- | ---- | ---- |
| Payload | Message (cleartext or encrypted) | Always |
| Payload Type | MIME type indicating content type | Optional |
| Payload Signature | Owner or Delegate signed | Always |
| Owner Voucher | Device voucher, proving Ownership | Always |
| Delegate Certificate Chain | Signed by owner if Delegate signed payload | Optional |
| Encrypted Payload Key | If payload is encrypted, DAK-encrypted Symmetric key and IV | Optional |

## CLI Commands

The `attestpayload` command provides two subcommands:

```bash
# Create an attested payload
go run ./examples/cmd attestpayload create [options]

# Verify an attested payload
go run ./examples/cmd attestpayload verify [options] <file.fdo>
```

### Create Options

| Option | Description |
|--------|-------------|
| `-db` | SQLite database path (default: fdo.db) |
| `-voucher` | PEM-encoded voucher file (required) |
| `-payload` | Payload text to sign |
| `-file` | Payload file to sign (alternative to -payload) |
| `-type` | MIME type of payload (e.g., text/x-shellscript) |
| `-expires` | Expiration datetime in ISO 8601 format (e.g., 2025-12-31T23:59:59Z) |
| `-id` | Identifier for grouping/ordering payloads |
| `-gen` | Generation number for supersession (higher supersedes lower) |
| `-output` | Output file (default: stdout) |
| `-encrypt` | Encrypt the payload (requires RSA device key) |
| `-delegate` | Sign with delegate chain (chain name from database) |

### Examples

```bash
# Create plaintext attested payload
go run ./examples/cmd attestpayload create -db test.db -voucher voucher.pem -payload "Hello World" -output payload.fdo

# Create attested payload with MIME type (for shell script)
go run ./examples/cmd attestpayload create -db test.db -voucher voucher.pem -payload '#!/bin/bash\necho hello' -type "text/x-shellscript" -output script.fdo

# Create attested payload with cloud-init config type
go run ./examples/cmd attestpayload create -db test.db -voucher voucher.pem -file cloud-config.yaml -type "text/cloud-config" -output config.fdo

# Create encrypted attested payload
go run ./examples/cmd attestpayload create -db test.db -voucher voucher.pem -payload "Secret data" -encrypt -output encrypted.fdo

# Create encrypted attested payload with JSON type
go run ./examples/cmd attestpayload create -db test.db -voucher voucher.pem -payload '{"secret": "value"}' -type "application/json" -encrypt -output secret.fdo

# Create delegate-signed attested payload
go run ./examples/cmd attestpayload create -db test.db -voucher voucher.pem -payload "Delegated" -delegate mychain -output delegated.fdo

# Create attested payload with validity (id and generation for supersession)
go run ./examples/cmd attestpayload create -db test.db -voucher voucher.pem -payload "Config v1" -id "network-config" -gen 1 -output config-v1.fdo

# Create newer generation to supersede previous
go run ./examples/cmd attestpayload create -db test.db -voucher voucher.pem -payload "Config v2" -id "network-config" -gen 2 -output config-v2.fdo

# Create time-limited command with expiration
go run ./examples/cmd attestpayload create -db test.db -voucher voucher.pem -payload '#!/bin/bash\nreboot' -type "text/x-shellscript" -expires "2025-06-15T12:00:00Z" -output reboot-cmd.fdo

# Verify and decrypt attested payload
go run ./examples/cmd attestpayload verify -db test.db payload.fdo
```

### Validity Options

The validity block provides lifecycle and ordering controls:

| Field | Purpose |
|-------|--------|
| `-expires` | Time-limited commands expire after this datetime |
| `-id` | Group related payloads; enables supersession and ordering |
| `-gen` | Higher generation supersedes lower for same id |

**Use cases:**
- **Declarative payloads** (configs): Use `-id` and `-gen` for versioning
- **Imperative payloads** (commands): Use `-expires` to limit execution window
- **Ordered execution**: Use `-id` with naming convention (e.g., "step-001", "step-002")

### Common MIME Types

| MIME Type | Description |
|-----------|-------------|
| `text/x-shellscript` | Shell script (cloud-init compatible) |
| `text/cloud-config` | Cloud-init YAML configuration |
| `text/cloud-boothook` | Cloud-init boot hook |
| `application/json` | JSON configuration |
| `application/x-yaml` | YAML configuration |
| `application/octet-stream` | Binary data (firmware, disk image) |
| `text/plain` | Plain text |

## Setup

Start with steps in README.md to create a database with an owner key and voucher:

```console
# Terminal 1 - Start server
rm test.db
go run ./examples/cmd server -http 127.0.0.1:9999 -db ./test.db -owner-certs

# Terminal 2 - Run DI
go run ./examples/cmd client -di http://127.0.0.1:9999
```

### Export Voucher for CLI Use

After DI, export the voucher to a PEM file:

```bash
(echo '-----BEGIN OWNERSHIP VOUCHER-----' ; sqlite3 test.db 'select hex(cbor) from vouchers;' | xxd -r -p | base64 ; echo '-----END OWNERSHIP VOUCHER-----') > voucher.pem
```

## Creating an Attested Payload

### Payload

```bash
echo '-----BEGIN PAYLOAD-----' ; echo "This is a test of the emergency broadcasting system. In the event of an actual emergency, you would be required to...." | base64 ; echo '-----END PAYLOAD-----'
```

### Generate Encrypted Payload

```bash
KEY=$(openssl rand -hex 32)
IV=$(openssl rand -hex 16)
openssl enc -aes-256-ctr -out ciphertext.bin -K "$KEY" -iv "$IV"
echo "$KEY" | openssl pkeyutl -encrypt -pubin -inkey ownerkey_rsa.pub -out encrypted_key.bin -pkeyopt rsa_padding_mode:oaep
```

> **Note:** IV, encrypted_key, and ciphertext can be transmitted in clear.

### Decrypt Encrypted Payload

```bash
KEYOUT=$(openssl pkeyutl -decrypt -in encrypted_key.bin -inkey ownerkey_rsa.key -pkeyopt rsa_padding_mode:oaep)
openssl enc -aes-256-ctr -d -in ciphertext.bin -K "$KEYOUT" -iv "$IV"
```

## Signature Format

The signature is computed over a **length-prefixed** data structure to prevent type confusion attacks:

```
len(PayloadType) || PayloadType || len(Validity) || Validity || PayloadData
```

Where:
- Length prefixes are **4-byte big-endian unsigned integers**
- PayloadType is the MIME type string (empty string if not specified)
- Validity is JSON-encoded validity block (empty if not specified)
- PayloadData is the raw payload bytes (or ciphertext if encrypted)

For a simple payload with no type or validity, the signed data is:
```
00 00 00 00  (type length = 0)
00 00 00 00  (validity length = 0)
<payload bytes>
```

### Helper Function for Shell Scripts

To build the length-prefixed signed data in shell:

```bash
# Build signed data with length prefixes
# Usage: build_signed_data <payload_type> <validity_json> <payload_data>
build_signed_data() {
    local payload_type="$1"
    local validity="$2"
    local payload="$3"
    
    # Type length (4 bytes big-endian)
    local type_len=${#payload_type}
    printf '%08x' "$type_len" | xxd -r -p
    printf '%s' "$payload_type"
    
    # Validity length (4 bytes big-endian)
    local validity_len=${#validity}
    printf '%08x' "$validity_len" | xxd -r -p
    printf '%s' "$validity"
    
    # Payload data
    printf '%s' "$payload"
}

# Example: Sign a simple payload (no type, no validity)
PAYLOAD='Hello World'
build_signed_data "" "" "$PAYLOAD" | openssl dgst -sha384 -sign owner.key -out sig.bin
```

## Quick RSA Attested Payload

> **Warning:** This works ONLY if you created Ownership Voucher with RSA2048 key like with:
>
> ```bash
> go run ./examples/cmd client -di http://127.0.0.1:9999 -di-key rsa2048
> ```
>
> These will BREAK if more than one OV in database. If unsure, start with a clean DB.

```bash
PAYLOAD='This is a test of the emergency broadcasting system'

# Extract owner RSA key
(echo '-----BEGIN PRIVATE KEY-----' ; sqlite3 test.db 'select hex(pkcs8) from owner_keys where type=1;' | xxd -r -p | base64 ; echo '-----END PRIVATE KEY-----') > owner_rsa_pvt.key
openssl pkey -in owner_rsa_pvt.key -pubout > owner_rsa_pub.key

# Build length-prefixed signed data (no type, no validity)
# Format: 4-byte type_len (0) + 4-byte validity_len (0) + payload
(printf '\x00\x00\x00\x00\x00\x00\x00\x00' ; printf '%s' "$PAYLOAD") > signed_data.bin

# Sign the length-prefixed data
openssl dgst -sha384 -sign owner_rsa_pvt.key -out sig.bin signed_data.bin

# Assemble the attested payload
(echo '-----BEGIN OWNERSHIP VOUCHER-----' ; sqlite3 test.db 'select hex(cbor) from vouchers;' | xxd -r -p | base64 ; echo '-----END OWNERSHIP VOUCHER-----') > payload_rsa.fdo
(echo '-----BEGIN PAYLOAD-----' ; printf '%s' "$PAYLOAD" | base64 ; echo '-----END PAYLOAD-----') >> payload_rsa.fdo
(echo '-----BEGIN SIGNATURE-----' ; base64 sig.bin; echo '-----END SIGNATURE-----') >> payload_rsa.fdo

# Verify
go run ./examples/cmd attestpayload verify -db test.db payload_rsa.fdo

# Cleanup
rm -f signed_data.bin sig.bin owner_rsa_pvt.key owner_rsa_pub.key
```

## Quick EC Attested Payload

```bash
PAYLOAD='This is a test of the emergency broadcasting system'

# Extract owner EC key
(echo '-----BEGIN PRIVATE KEY-----' ; sqlite3 test.db 'select hex(pkcs8) from owner_keys where type=11;' | xxd -r -p | base64 ; echo '-----END PRIVATE KEY-----') > owner_ec_pvt.key
openssl pkey -in owner_ec_pvt.key -pubout > owner_ec_pub.key

# Build length-prefixed signed data (no type, no validity)
(printf '\x00\x00\x00\x00\x00\x00\x00\x00' ; printf '%s' "$PAYLOAD") > signed_data.bin

# Sign the length-prefixed data
openssl dgst -sha384 -sign owner_ec_pvt.key -out sig.bin signed_data.bin

# Assemble the attested payload
(echo '-----BEGIN OWNERSHIP VOUCHER-----' ; sqlite3 test.db 'select hex(cbor) from vouchers;' | xxd -r -p | base64 ; echo '-----END OWNERSHIP VOUCHER-----') > payload_ec.fdo
(echo '-----BEGIN PAYLOAD-----' ; printf '%s' "$PAYLOAD" | base64 ; echo '-----END PAYLOAD-----') >> payload_ec.fdo
(echo '-----BEGIN SIGNATURE-----' ; base64 sig.bin; echo '-----END SIGNATURE-----') >> payload_ec.fdo

# Verify
go run ./examples/cmd attestpayload verify -db test.db payload_ec.fdo

# Cleanup
rm -f signed_data.bin sig.bin owner_ec_pvt.key owner_ec_pub.key
```

## Quick EC Attested Payload with Type

This example shows how to create a typed payload (with MIME type):

```bash
PAYLOAD='#!/bin/bash
echo "Hello from attested script"'
PAYLOAD_TYPE='text/x-shellscript'

# Extract owner EC key
(echo '-----BEGIN PRIVATE KEY-----' ; sqlite3 test.db 'select hex(pkcs8) from owner_keys where type=11;' | xxd -r -p | base64 ; echo '-----END PRIVATE KEY-----') > owner_ec_pvt.key

# Build length-prefixed signed data WITH type
# Format: 4-byte type_len + type + 4-byte validity_len (0) + payload
TYPE_LEN=$(printf '%s' "$PAYLOAD_TYPE" | wc -c)
(printf '%08x' "$TYPE_LEN" | xxd -r -p ; printf '%s' "$PAYLOAD_TYPE" ; printf '\x00\x00\x00\x00' ; printf '%s' "$PAYLOAD") > signed_data.bin

# Sign
openssl dgst -sha384 -sign owner_ec_pvt.key -out sig.bin signed_data.bin

# Assemble
(echo '-----BEGIN OWNERSHIP VOUCHER-----' ; sqlite3 test.db 'select hex(cbor) from vouchers;' | xxd -r -p | base64 ; echo '-----END OWNERSHIP VOUCHER-----') > payload_typed.fdo
(echo '-----BEGIN PAYLOAD TYPE-----' ; echo "$PAYLOAD_TYPE" ; echo '-----END PAYLOAD TYPE-----') >> payload_typed.fdo
(echo '-----BEGIN PAYLOAD-----' ; printf '%s' "$PAYLOAD" | base64 ; echo '-----END PAYLOAD-----') >> payload_typed.fdo
(echo '-----BEGIN SIGNATURE-----' ; base64 sig.bin; echo '-----END SIGNATURE-----') >> payload_typed.fdo

# Verify
go run ./examples/cmd attestpayload verify -db test.db payload_typed.fdo

# Cleanup
rm -f signed_data.bin sig.bin owner_ec_pvt.key
```

## Quick RSA Encrypted Attested Payload

This section demonstrates creating an **encrypted** attested payload where the payload is encrypted with AES-256-CTR and the symmetric key is wrapped with RSA-OAEP using the device's RSA public key.

> **Warning:** This works ONLY if you created Ownership Voucher with RSA2048 key:
>
> ```bash
> go run ./examples/cmd client -di http://127.0.0.1:9999 -di-key rsa2048
> ```

### Step 1: Extract Keys from Database

```bash
# Extract owner's RSA private key for signing
(echo '-----BEGIN PRIVATE KEY-----' ; sqlite3 test.db 'select hex(pkcs8) from owner_keys where type=1;' | xxd -r -p | base64 ; echo '-----END PRIVATE KEY-----') > owner_rsa_pvt.key
openssl pkey -in owner_rsa_pvt.key -pubout > owner_rsa_pub.key
```

### Step 2: Create Encrypted Payload

```bash
# Define the secret payload
PAYLOAD='This is a SECRET payload that will be encrypted'

# Generate random AES-256 key and IV
KEY=$(openssl rand -hex 32)
IV=$(openssl rand -hex 16)

# Encrypt the payload with AES-256-CTR
CIPHERTEXT=$(echo -n "$PAYLOAD" | openssl enc -aes-256-ctr -K "$KEY" -iv "$IV" | base64)

# Wrap the symmetric key with RSA-OAEP (using device's RSA public key)
# Note: In production, use the device's public key from the voucher, not owner's key
WEK=$(echo -n "$KEY" | xxd -r -p | openssl pkeyutl -encrypt -pubin -inkey owner_rsa_pub.key -pkeyopt rsa_padding_mode:oaep | base64)
```

### Step 3: Sign the Ciphertext

The signature is computed over the **length-prefixed ciphertext**, not the plaintext. This proves the owner created this specific encrypted payload.

```bash
# Build length-prefixed signed data (no type, no validity) with CIPHERTEXT
# Format: 4-byte type_len (0) + 4-byte validity_len (0) + ciphertext
echo -n "$PAYLOAD" | openssl enc -aes-256-ctr -K "$KEY" -iv "$IV" > ciphertext.bin
(printf '\x00\x00\x00\x00\x00\x00\x00\x00' ; cat ciphertext.bin) > signed_data.bin

# Sign the length-prefixed data
openssl dgst -sha384 -sign owner_rsa_pvt.key -out sig.bin signed_data.bin
```

### Step 4: Assemble the Encrypted Attested Payload

```bash
# Start with the ownership voucher
(echo '-----BEGIN OWNERSHIP VOUCHER-----' ; sqlite3 test.db 'select hex(cbor) from vouchers;' | xxd -r -p | base64 ; echo '-----END OWNERSHIP VOUCHER-----') > encrypted_payload.fdo

# Add the IV
(echo "-----BEGIN IV-----" ; echo "$IV" ; echo "-----END IV-----") >> encrypted_payload.fdo

# Add the wrapped encryption key
(echo "-----BEGIN WRAPPED ENCRYPTION KEY-----" ; echo "$WEK" ; echo "-----END WRAPPED ENCRYPTION KEY-----") >> encrypted_payload.fdo

# Add the ciphertext
(echo "-----BEGIN CIPHERTEXT-----" ; echo "$CIPHERTEXT" ; echo "-----END CIPHERTEXT-----") >> encrypted_payload.fdo

# Add the signature
(echo "-----BEGIN SIGNATURE-----" ; base64 sig.bin ; echo "-----END SIGNATURE-----") >> encrypted_payload.fdo
```

### Step 5: Verify and Decrypt

```bash
# Verify signature and decrypt the payload
go run ./examples/cmd attestpayload verify -db test.db encrypted_payload.fdo
```

Expected output:
```
Block "OWNERSHIP VOUCHER"  -  XXX bytes
...
Block "IV"  -  32 bytes
IV Data <hex>
Block "WRAPPED ENCRYPTION KEY"  -  XXX bytes
Wrapped Encryption Key <hex>
Block "CIPHERTEXT"  -  XXX bytes
Ciphertext Data <hex>
Block "SIGNATURE"  -  XXX bytes
...
Decrypted payload (XX bytes):
This is a SECRET payload that will be encrypted
```

### Manual Decryption (for verification)

You can also manually decrypt to verify:

```bash
# Unwrap the symmetric key
KEYOUT=$(echo "$WEK" | base64 -d | openssl pkeyutl -decrypt -inkey owner_rsa_pvt.key -pkeyopt rsa_padding_mode:oaep | xxd -p)

# Decrypt the ciphertext
echo "$CIPHERTEXT" | base64 -d | openssl enc -aes-256-ctr -d -K "$KEYOUT" -iv "$IV"
```

## Verifying Go CLI-Created Payloads with OpenSSL

You can verify payloads created by the Go CLI using standard OpenSSL commands. This demonstrates interoperability.

### Extract Components from .fdo File

```bash
# Parse the .fdo file to extract components
# Assuming payload.fdo was created by: go run ./cmd attestpayload create ...

# Extract payload (base64 decode the PAYLOAD block)
sed -n '/-----BEGIN PAYLOAD-----/,/-----END PAYLOAD-----/p' payload.fdo | grep -v '^-----' | base64 -d > extracted_payload.bin

# Extract signature
sed -n '/-----BEGIN SIGNATURE-----/,/-----END SIGNATURE-----/p' payload.fdo | grep -v '^-----' | base64 -d > extracted_sig.bin

# Extract payload type (if present)
PAYLOAD_TYPE=$(sed -n '/-----BEGIN PAYLOAD TYPE-----/,/-----END PAYLOAD TYPE-----/p' payload.fdo | grep -v '^-----' | tr -d '\n')

# Extract validity (if present)
VALIDITY=$(sed -n '/-----BEGIN VALIDITY-----/,/-----END VALIDITY-----/p' payload.fdo | grep -v '^-----' | tr -d '\n')
```

### Verify Signature with OpenSSL

```bash
# Extract owner public key from database
(echo '-----BEGIN PRIVATE KEY-----' ; sqlite3 test.db 'select hex(pkcs8) from owner_keys where type=11;' | xxd -r -p | base64 ; echo '-----END PRIVATE KEY-----') > owner_ec_pvt.key
openssl pkey -in owner_ec_pvt.key -pubout > owner_ec_pub.key

# Build the length-prefixed signed data
TYPE_LEN=${#PAYLOAD_TYPE}
VALIDITY_LEN=${#VALIDITY}

# Create signed_data.bin with length prefixes
(
    printf '%08x' "$TYPE_LEN" | xxd -r -p
    printf '%s' "$PAYLOAD_TYPE"
    printf '%08x' "$VALIDITY_LEN" | xxd -r -p
    printf '%s' "$VALIDITY"
    cat extracted_payload.bin
) > signed_data.bin

# Verify the signature
openssl dgst -sha384 -verify owner_ec_pub.key -signature extracted_sig.bin signed_data.bin
# Should output: "Verified OK"
```

## Complete Test Script

Here's a complete script that tests the entire encrypted attested payload workflow with the new length-prefixed format:

```bash
#!/bin/bash
set -e

echo "=== Encrypted Attested Payload Test ==="

# Cleanup
rm -f test.db owner_rsa_pvt.key owner_rsa_pub.key sig.bin signed_data.bin ciphertext.bin encrypted_payload.fdo

# Start server in background
go run ./examples/cmd server -http 127.0.0.1:9999 -db ./test.db -owner-certs &
SERVER_PID=$!
sleep 2

# Run DI with RSA key
go run ./examples/cmd client -di http://127.0.0.1:9999 -di-key rsa2048

# Kill server
kill $SERVER_PID 2>/dev/null || true

# Extract owner key
(echo '-----BEGIN PRIVATE KEY-----' ; sqlite3 test.db 'select hex(pkcs8) from owner_keys where type=1;' | xxd -r -p | base64 ; echo '-----END PRIVATE KEY-----') > owner_rsa_pvt.key
openssl pkey -in owner_rsa_pvt.key -pubout > owner_rsa_pub.key

# Create encrypted payload
PAYLOAD='Secret configuration: {"api_key": "abc123", "endpoint": "https://secure.example.com"}'
KEY=$(openssl rand -hex 32)
IV=$(openssl rand -hex 16)

# Encrypt
echo -n "$PAYLOAD" | openssl enc -aes-256-ctr -K "$KEY" -iv "$IV" > ciphertext.bin
CIPHERTEXT=$(base64 ciphertext.bin)
WEK=$(echo -n "$KEY" | xxd -r -p | openssl pkeyutl -encrypt -pubin -inkey owner_rsa_pub.key -pkeyopt rsa_padding_mode:oaep | base64)

# Build length-prefixed signed data and sign
(printf '\x00\x00\x00\x00\x00\x00\x00\x00' ; cat ciphertext.bin) > signed_data.bin
openssl dgst -sha384 -sign owner_rsa_pvt.key -out sig.bin signed_data.bin

# Assemble
(echo '-----BEGIN OWNERSHIP VOUCHER-----' ; sqlite3 test.db 'select hex(cbor) from vouchers;' | xxd -r -p | base64 ; echo '-----END OWNERSHIP VOUCHER-----') > encrypted_payload.fdo
(echo "-----BEGIN IV-----" ; echo "$IV" ; echo "-----END IV-----") >> encrypted_payload.fdo
(echo "-----BEGIN WRAPPED ENCRYPTION KEY-----" ; echo "$WEK" ; echo "-----END WRAPPED ENCRYPTION KEY-----") >> encrypted_payload.fdo
(echo "-----BEGIN CIPHERTEXT-----" ; echo "$CIPHERTEXT" ; echo "-----END CIPHERTEXT-----") >> encrypted_payload.fdo
(echo "-----BEGIN SIGNATURE-----" ; base64 sig.bin ; echo "-----END SIGNATURE-----") >> encrypted_payload.fdo

echo ""
echo "=== Verifying and Decrypting ==="
go run ./examples/cmd attestpayload verify -db test.db encrypted_payload.fdo

echo ""
echo "=== Test Complete ==="
```
