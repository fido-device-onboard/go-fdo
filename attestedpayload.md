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
(echo '-----BEGIN PRIVATE KEY-----' ; sqlite3 test.db 'select hex(pkcs8) from owner_keys where type=1;' | xxd -r -p | base64 ; echo '-----END PRIVATE KEY-----') > owner_rsa_pvt.key
openssl pkey -in owner_rsa_pvt.key -pubout > owner_rsa_pub.key
echo $PAYLOAD | openssl dgst -sha384 -sign owner_rsa_pvt.key -out sig.bin
(echo '-----BEGIN OWNERSHIP VOUCHER-----' ; sqlite3 test.db 'select hex(cbor) from vouchers;' | xxd -r -p | base64 ; echo '-----END OWNERSHIP VOUCHER-----') > payload_rsa3.fdo
(echo -----BEGIN PAYLOAD----- ; echo $PAYLOAD | base64 ; echo -----END PAYLOAD-----) >> payload_rsa3.fdo
(echo -----BEGIN SIGNATURE----- ; base64 sig.bin; echo -----END SIGNATURE-----) >> payload_rsa3.fdo
go run ./examples/cmd attestpayload verify -db test.db payload_rsa3.fdo
```

## Quick EC Attested Payload

```bash
PAYLOAD='This is a test of the emergency broadcasting system'
(echo '-----BEGIN PRIVATE KEY-----' ; sqlite3 test.db 'select hex(pkcs8) from owner_keys where type=11;' | xxd -r -p | base64 ; echo '-----END PRIVATE KEY-----') > owner_ec_pvt.key
openssl pkey -in owner_ec_pvt.key -pubout > owner_ec_pub.key
echo $PAYLOAD | openssl dgst -sha384 -sign owner_ec_pvt.key -out sig.bin
(echo '-----BEGIN OWNERSHIP VOUCHER-----' ; sqlite3 test.db 'select hex(cbor) from vouchers;' | xxd -r -p | base64 ; echo '-----END OWNERSHIP VOUCHER-----') > payload_ec3.fdo
(echo -----BEGIN PAYLOAD----- ; echo $PAYLOAD | base64 ; echo -----END PAYLOAD-----) >> payload_ec3.fdo
(echo -----BEGIN SIGNATURE----- ; base64 sig.bin; echo -----END SIGNATURE-----) >> payload_ec3.fdo
go run ./examples/cmd attestpayload verify -db test.db payload_ec3.fdo
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

The signature is computed over the **ciphertext**, not the plaintext. This proves the owner created this specific encrypted payload.

```bash
# Sign the ciphertext (not the plaintext!)
echo -n "$PAYLOAD" | openssl enc -aes-256-ctr -K "$KEY" -iv "$IV" | openssl dgst -sha384 -sign owner_rsa_pvt.key -out sig.bin
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

## Complete Test Script

Here's a complete script that tests the entire encrypted attested payload workflow:

```bash
#!/bin/bash
set -e

echo "=== Encrypted Attested Payload Test ==="

# Cleanup
rm -f test.db owner_rsa_pvt.key owner_rsa_pub.key sig.bin encrypted_payload.fdo

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
CIPHERTEXT=$(echo -n "$PAYLOAD" | openssl enc -aes-256-ctr -K "$KEY" -iv "$IV" | base64)
WEK=$(echo -n "$KEY" | xxd -r -p | openssl pkeyutl -encrypt -pubin -inkey owner_rsa_pub.key -pkeyopt rsa_padding_mode:oaep | base64)

# Sign ciphertext
echo -n "$PAYLOAD" | openssl enc -aes-256-ctr -K "$KEY" -iv "$IV" | openssl dgst -sha384 -sign owner_rsa_pvt.key -out sig.bin

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
