# Attested Payload

An attested payload combines data—such as a configuration, command, or state declaration—with cryptographic proof of its authenticity. The payload is digitally signed, and an Ownership Voucher is included to establish the signer's authority. This allows a device that has completed manufacturing to verify that the payload originated from its legitimate owner by validating the signature against the ownership chain.

In some cases, the payload may not be signed directly by the owner. Instead, a Delegate Certificate—signed by the owner—can authorize a third party to sign on the owner's behalf. When delegation is used, the attested payload includes this certificate chain, allowing the device to verify both the delegate's authority and the payload's integrity.

If a device's attestation key (DAK) is an RSA key, it can be used to encrypt the payload. This is useful for encrypting the payload to prevent eavesdropping.

Thus, the attested payload may consist of the following parts:

| Payload | What | When |
| ---- | ---- | ---- |
| Payload | Message (cleartext or encrypted) | Always |
| Payload Signature | Owner or Delegate signed | Always |
| Owner Voucher | Device voucher, proving Ownership | Always |
| Delegate Certificate Chain | Signed by owner if Delegate signed payload | Optional |
| Encrypted Payload Key | If payload is encrypted, DAK-encrypted Symmetric key and IV | Optional |

## Setup

Start with steps in README.md to create a database with an owner key and voucher:

```console
# Terminal 1 - Start server
rm test.db
go run ./examples/cmd server -http 127.0.0.1:9999 -db ./test.db -owner-certs

# Terminal 2 - Run DI
go run ./examples/cmd client -di http://127.0.0.1:9999
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
go run ./examples/cmd delegate -db test.db attestPayload payload_rsa3.fdo
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
go run ./examples/cmd delegate -db test.db attestPayload payload_ec3.fdo
```

## Quick RSA Key Encryption

```bash
KEY=$(openssl rand -hex 32)
IV=$(openssl rand -hex 16)
CIPHERTEXT=$(echo $PAYLOAD | openssl enc -aes-256-ctr -K "$KEY" -iv "$IV" | base64)
WEK=$(echo "$KEY" | openssl pkeyutl -encrypt -pubin -inkey owner_rsa_pub.key -pkeyopt rsa_padding_mode:oaep | base64)

echo -e "-----BEGIN IV-----\n$IV\n-----END IV-----"
echo -e "-----BEGIN WRAPPED ENCRYPTION KEY-----\n$WEK\n-----END WRAPPED ENCRYPTION KEY-----"
echo -e "-----BEGIN CIPHERTEXT-----\n$CIPHERTEXT\n-----END CIPHERTEXT-----"
```
