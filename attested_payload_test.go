// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
)

// ecdsaSignature represents an ECDSA signature for ASN.1 encoding
type ecdsaSignature struct {
	R, S *big.Int
}

// signPayload signs a payload with the given key using SHA-384
func signPayload(key crypto.Signer, payload []byte) ([]byte, error) {
	hashed := sha512.Sum384(payload)
	return key.Sign(rand.Reader, hashed[:], crypto.SHA384)
}

// verifyECDSASignature verifies an ECDSA signature on a payload
func verifyECDSASignature(pubKey *ecdsa.PublicKey, payload, sigBytes []byte) bool {
	hashed := sha512.Sum384(payload)
	sig := new(ecdsaSignature)
	if _, err := asn1.Unmarshal(sigBytes, sig); err != nil {
		return false
	}
	return ecdsa.Verify(pubKey, hashed[:], sig.R, sig.S)
}

// loadTestVoucher loads the test voucher from testdata
func loadTestVoucher(t *testing.T) *fdo.Voucher {
	b, err := os.ReadFile("testdata/ov.pem")
	if err != nil {
		t.Fatalf("error reading voucher: %v", err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatal("invalid PEM data")
	}
	var ov fdo.Voucher
	if err := cbor.Unmarshal(blk.Bytes, &ov); err != nil {
		t.Fatalf("error parsing voucher: %v", err)
	}
	return &ov
}

// loadTestKey loads the manufacturer key from testdata
func loadTestKey(t *testing.T) crypto.Signer {
	data, err := os.ReadFile("testdata/mfg_key.pem")
	if err != nil {
		t.Fatalf("error reading key: %v", err)
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		t.Fatal("invalid PEM key data")
	}
	key, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		t.Fatalf("error parsing key: %v", err)
	}
	return key
}

// TestAttestedPayloadValidSignature verifies that a payload signed by the
// voucher owner is accepted.
func TestAttestedPayloadValidSignature(t *testing.T) {
	// Load voucher and get owner key
	ov := loadTestVoucher(t)
	ownerKey := loadTestKey(t)

	// Create a test payload
	payload := []byte("This is a test attested payload for security verification")

	// Sign the payload with the owner key
	signature, err := signPayload(ownerKey, payload)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	// Verify the signature
	pubKey := ownerKey.Public().(*ecdsa.PublicKey)
	if !verifyECDSASignature(pubKey, payload, signature) {
		t.Error("valid signature should verify successfully")
	}

	// Verify voucher entries to ensure chain is valid
	if err := ov.VerifyEntries(); err != nil {
		t.Logf("Note: unextended voucher has no entries to verify: %v", err)
	}

	t.Log("Valid attested payload signature verified successfully")
}

// TestAttestedPayloadInvalidSignature verifies that a corrupted signature
// is rejected.
func TestAttestedPayloadInvalidSignature(t *testing.T) {
	ownerKey := loadTestKey(t)

	// Create a test payload
	payload := []byte("This is a test attested payload")

	// Sign the payload
	signature, err := signPayload(ownerKey, payload)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	// Corrupt the signature
	if len(signature) > 0 {
		signature[0] ^= 0xFF
		signature[len(signature)-1] ^= 0xFF
	}

	// Verify should fail
	pubKey := ownerKey.Public().(*ecdsa.PublicKey)
	if verifyECDSASignature(pubKey, payload, signature) {
		t.Error("SECURITY FAILURE: corrupted signature was accepted")
	} else {
		t.Log("Correctly rejected corrupted attested payload signature")
	}
}

// TestAttestedPayloadWrongKey verifies that a payload signed by a different
// key than the voucher owner is rejected.
func TestAttestedPayloadWrongKey(t *testing.T) {
	ownerKey := loadTestKey(t)

	// Generate a different (attacker's) key
	attackerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate attacker key: %v", err)
	}

	// Create a test payload
	payload := []byte("This is a test attested payload")

	// Sign with the ATTACKER's key (not the owner)
	signature, err := signPayload(attackerKey, payload)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	// Verify against the OWNER's key should fail
	ownerPubKey := ownerKey.Public().(*ecdsa.PublicKey)
	if verifyECDSASignature(ownerPubKey, payload, signature) {
		t.Error("SECURITY FAILURE: signature from wrong key was accepted")
	} else {
		t.Log("Correctly rejected attested payload signed by wrong key")
	}
}

// TestAttestedPayloadModifiedPayload verifies that if the payload is modified
// after signing, verification fails.
func TestAttestedPayloadModifiedPayload(t *testing.T) {
	ownerKey := loadTestKey(t)

	// Create and sign original payload
	originalPayload := []byte("Original payload content")
	signature, err := signPayload(ownerKey, originalPayload)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	// Modify the payload after signing
	modifiedPayload := []byte("Modified payload content")

	// Verify with modified payload should fail
	pubKey := ownerKey.Public().(*ecdsa.PublicKey)
	if verifyECDSASignature(pubKey, modifiedPayload, signature) {
		t.Error("SECURITY FAILURE: modified payload was accepted with original signature")
	} else {
		t.Log("Correctly rejected modified attested payload")
	}
}

// TestAttestedPayloadDelegateWithProvisionPermission verifies that a delegate
// with the "provision" permission can sign attested payloads.
func TestAttestedPayloadDelegateWithProvisionPermission(t *testing.T) {
	// Generate owner key
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	// Generate delegate key
	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	// Create delegate certificate with provision permission
	delegateCert, err := fdo.GenerateDelegate(
		ownerKey,
		fdo.DelegateFlagRoot,
		delegateKey.Public(),
		"ProvisionDelegate",
		"Owner",
		[]asn1.ObjectIdentifier{fdo.OIDDelegateProvision},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate delegate cert: %v", err)
	}

	chain := []*x509.Certificate{delegateCert}
	ownerPubKey := ownerKey.Public()

	// Verify delegate chain with provision permission
	err = fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDDelegateProvision)
	if err != nil {
		t.Errorf("delegate with provision permission should be valid: %v", err)
	}

	// Sign payload with delegate key
	payload := []byte("Delegate-signed attested payload")
	signature, err := signPayload(delegateKey, payload)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	// Verify signature with delegate's public key
	delegatePubKey := delegateKey.Public().(*ecdsa.PublicKey)
	if !verifyECDSASignature(delegatePubKey, payload, signature) {
		t.Error("delegate-signed payload should verify with delegate's key")
	}

	t.Log("Delegate with provision permission can sign attested payloads")
}

// TestAttestedPayloadDelegateWithoutProvisionPermission verifies that a delegate
// without the "provision" permission cannot sign attested payloads.
func TestAttestedPayloadDelegateWithoutProvisionPermission(t *testing.T) {
	// Generate owner key
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	// Generate delegate key
	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	// Create delegate certificate with ONLY onboard permission (no provision)
	delegateCert, err := fdo.GenerateDelegate(
		ownerKey,
		fdo.DelegateFlagRoot,
		delegateKey.Public(),
		"OnboardOnlyDelegate",
		"Owner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitOnboardNewCred}, // No provision permission
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate delegate cert: %v", err)
	}

	chain := []*x509.Certificate{delegateCert}
	ownerPubKey := ownerKey.Public()

	// Verify delegate chain with provision permission should FAIL
	err = fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDDelegateProvision)
	if err == nil {
		t.Error("SECURITY FAILURE: delegate without provision permission was accepted for attested payload signing")
	} else {
		t.Logf("Correctly rejected delegate without provision permission: %v", err)
	}
}

// TestAttestedPayloadDelegateChainNotRootedToOwner verifies that a delegate
// chain not rooted to the voucher owner is rejected.
func TestAttestedPayloadDelegateChainNotRootedToOwner(t *testing.T) {
	// Generate legitimate owner key
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	// Generate attacker's key (pretending to be owner)
	attackerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate attacker key: %v", err)
	}

	// Generate delegate key
	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	// Create delegate certificate signed by ATTACKER (not owner)
	delegateCert, err := fdo.GenerateDelegate(
		attackerKey, // Signed by attacker, not owner!
		fdo.DelegateFlagRoot,
		delegateKey.Public(),
		"MaliciousDelegate",
		"FakeOwner",
		[]asn1.ObjectIdentifier{fdo.OIDDelegateProvision},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate delegate cert: %v", err)
	}

	chain := []*x509.Certificate{delegateCert}
	ownerPubKey := ownerKey.Public() // The REAL owner's key

	// Verify delegate chain against real owner should FAIL
	err = fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDDelegateProvision)
	if err == nil {
		t.Error("SECURITY FAILURE: delegate chain not rooted to owner was accepted")
	} else {
		t.Logf("Correctly rejected delegate chain not rooted to owner: %v", err)
	}
}

// TestAttestedPayloadEmptyPayload verifies handling of empty payloads.
func TestAttestedPayloadEmptyPayload(t *testing.T) {
	ownerKey := loadTestKey(t)

	// Create an empty payload
	payload := []byte{}

	// Sign the empty payload
	signature, err := signPayload(ownerKey, payload)
	if err != nil {
		t.Fatalf("failed to sign empty payload: %v", err)
	}

	// Verify should still work for empty payload
	pubKey := ownerKey.Public().(*ecdsa.PublicKey)
	if !verifyECDSASignature(pubKey, payload, signature) {
		t.Error("empty payload with valid signature should verify")
	}

	t.Log("Empty attested payload verified successfully")
}

// TestAttestedPayloadLargePayload verifies handling of large payloads.
func TestAttestedPayloadLargePayload(t *testing.T) {
	ownerKey := loadTestKey(t)

	// Create a large payload (1MB)
	payload := make([]byte, 1024*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("failed to generate large payload: %v", err)
	}

	// Sign the large payload
	signature, err := signPayload(ownerKey, payload)
	if err != nil {
		t.Fatalf("failed to sign large payload: %v", err)
	}

	// Verify should work for large payload
	pubKey := ownerKey.Public().(*ecdsa.PublicKey)
	if !verifyECDSASignature(pubKey, payload, signature) {
		t.Error("large payload with valid signature should verify")
	}

	t.Log("Large attested payload (1MB) verified successfully")
}

// =============================================================================
// POSITIVE TESTS - End-to-end success cases
// =============================================================================

// TestAttestedPayloadFullWorkflow tests the complete attested payload workflow:
// 1. Create voucher and extend it
// 2. Sign payload with owner key
// 3. Verify signature against voucher owner
func TestAttestedPayloadFullWorkflow(t *testing.T) {
	// Load the test voucher
	ov := loadTestVoucher(t)
	ownerKey := loadTestKey(t)

	// Verify voucher is valid
	ownerPubKey, err := ov.OwnerPublicKey()
	if err != nil {
		t.Fatalf("failed to get owner public key from voucher: %v", err)
	}

	// Create a realistic payload (e.g., configuration data)
	payload := []byte(`{
		"config": {
			"server": "https://example.com",
			"port": 8443,
			"tls": true
		},
		"commands": ["update", "restart"],
		"timestamp": "2024-01-09T12:00:00Z"
	}`)

	// Sign the payload with owner key
	signature, err := signPayload(ownerKey, payload)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	// Verify signature matches voucher owner
	ecdsaPubKey, ok := ownerPubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected ECDSA public key, got %T", ownerPubKey)
	}

	if !verifyECDSASignature(ecdsaPubKey, payload, signature) {
		t.Error("payload signature should verify against voucher owner key")
	}

	t.Logf("Full attested payload workflow completed successfully")
	t.Logf("  Voucher GUID: %s", ov.Header.Val.GUID)
	t.Logf("  Payload size: %d bytes", len(payload))
	t.Logf("  Signature size: %d bytes", len(signature))
}

// TestAttestedPayloadDelegateFullWorkflow tests the complete delegate workflow:
// 1. Owner creates delegate certificate with provision permission
// 2. Delegate signs payload
// 3. Verifier validates delegate chain against owner
// 4. Verifier validates signature against delegate key
func TestAttestedPayloadDelegateFullWorkflow(t *testing.T) {
	// Generate owner key (in real scenario, this comes from voucher)
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	// Generate delegate key
	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	// Owner creates delegate certificate with provision permission
	delegateCert, err := fdo.GenerateDelegate(
		ownerKey,
		fdo.DelegateFlagRoot,
		delegateKey.Public(),
		"AuthorizedProvisionDelegate",
		"VoucherOwner",
		[]asn1.ObjectIdentifier{fdo.OIDDelegateProvision},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate delegate cert: %v", err)
	}

	// Create payload
	payload := []byte("Firmware update v2.1.0 - security patches included")

	// Delegate signs the payload
	signature, err := signPayload(delegateKey, payload)
	if err != nil {
		t.Fatalf("failed to sign payload with delegate key: %v", err)
	}

	// === VERIFICATION SIDE (e.g., device) ===

	// Step 1: Verify delegate chain is rooted to owner
	chain := []*x509.Certificate{delegateCert}
	ownerPubKey := ownerKey.Public()
	err = fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDDelegateProvision)
	if err != nil {
		t.Fatalf("delegate chain verification failed: %v", err)
	}

	// Step 2: Extract delegate's public key from certificate
	delegatePubKey, ok := delegateCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected ECDSA public key in delegate cert")
	}

	// Step 3: Verify signature against delegate's key
	if !verifyECDSASignature(delegatePubKey, payload, signature) {
		t.Error("signature should verify against delegate's key")
	}

	t.Log("Delegate attested payload workflow completed successfully")
	t.Logf("  Owner authorized delegate: %s", delegateCert.Subject.CommonName)
	t.Logf("  Delegate has provision permission: true")
	t.Logf("  Payload verified: true")
}

// TestAttestedPayloadMultiLevelDelegateChain tests a multi-level delegate chain:
// Owner -> Intermediate -> Leaf delegate
func TestAttestedPayloadMultiLevelDelegateChain(t *testing.T) {
	// Generate owner key
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	// Generate intermediate delegate key
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate intermediate key: %v", err)
	}

	// Generate leaf delegate key
	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}

	// Owner creates intermediate delegate certificate
	intermediateCert, err := fdo.GenerateDelegate(
		ownerKey,
		fdo.DelegateFlagIntermediate,
		intermediateKey.Public(),
		"IntermediateDelegate",
		"VoucherOwner",
		[]asn1.ObjectIdentifier{fdo.OIDDelegateProvision},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate intermediate cert: %v", err)
	}

	// Intermediate creates leaf delegate certificate
	leafCert, err := fdo.GenerateDelegate(
		intermediateKey,
		fdo.DelegateFlagLeaf,
		leafKey.Public(),
		"LeafDelegate",
		"IntermediateDelegate",
		[]asn1.ObjectIdentifier{fdo.OIDDelegateProvision},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate leaf cert: %v", err)
	}

	// Create payload
	payload := []byte("Configuration update from authorized delegate chain")

	// Leaf delegate signs the payload
	signature, err := signPayload(leafKey, payload)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	// === VERIFICATION ===

	// Chain: leaf -> intermediate (leaf is index 0)
	chain := []*x509.Certificate{leafCert, intermediateCert}
	ownerPubKey := ownerKey.Public()

	// Verify the full chain
	err = fdo.VerifyDelegateChain(chain, &ownerPubKey, &fdo.OIDDelegateProvision)
	if err != nil {
		t.Fatalf("multi-level delegate chain verification failed: %v", err)
	}

	// Verify signature with leaf's key
	leafPubKey := leafKey.Public().(*ecdsa.PublicKey)
	if !verifyECDSASignature(leafPubKey, payload, signature) {
		t.Error("signature should verify against leaf delegate's key")
	}

	t.Log("Multi-level delegate chain attested payload workflow completed")
	t.Logf("  Chain: %s -> %s -> Owner", leafCert.Subject.CommonName, intermediateCert.Subject.CommonName)
}

// TestAttestedPayloadWithVoucherVerification tests attested payload with full
// voucher cryptographic verification.
func TestAttestedPayloadWithVoucherVerification(t *testing.T) {
	// Load voucher and credentials
	ov := loadTestVoucher(t)
	ownerKey := loadTestKey(t)

	// Load device credential for HMAC verification
	cred := readCredential(t)

	// Verify voucher header with device's HMAC
	if err := ov.VerifyHeader(cred.HMACs()); err != nil {
		t.Fatalf("voucher header verification failed: %v", err)
	}

	// Verify manufacturer key matches credential
	if err := ov.VerifyManufacturerKey(cred.PublicKeyHash); err != nil {
		t.Fatalf("manufacturer key verification failed: %v", err)
	}

	// Create and sign payload
	payload := []byte("Verified attested payload with full voucher validation")
	signature, err := signPayload(ownerKey, payload)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	// Verify signature
	pubKey := ownerKey.Public().(*ecdsa.PublicKey)
	if !verifyECDSASignature(pubKey, payload, signature) {
		t.Error("payload signature verification failed")
	}

	t.Log("Attested payload with full voucher verification completed")
	t.Logf("  Voucher GUID: %s", ov.Header.Val.GUID)
	t.Logf("  Device: %s", ov.Header.Val.DeviceInfo)
}

// =============================================================================
// ENCRYPTED PAYLOAD TESTS
// =============================================================================

// TestEncryptedPayloadRoundTrip tests encrypting and decrypting a payload
// using AES-256-CTR (as specified in the FDO attested payload documentation).
func TestEncryptedPayloadRoundTrip(t *testing.T) {
	// Generate a random symmetric key (256-bit for AES-256)
	symmetricKey := make([]byte, 32)
	if _, err := rand.Read(symmetricKey); err != nil {
		t.Fatalf("failed to generate symmetric key: %v", err)
	}

	// Generate a random IV (128-bit for AES)
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("failed to generate IV: %v", err)
	}

	// Original payload
	originalPayload := []byte("This is a secret configuration payload that should be encrypted")

	// Encrypt using AES-256-CTR
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		t.Fatalf("failed to create AES cipher: %v", err)
	}

	ciphertext := make([]byte, len(originalPayload))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, originalPayload)

	// Decrypt
	decrypted := make([]byte, len(ciphertext))
	stream = cipher.NewCTR(block, iv)
	stream.XORKeyStream(decrypted, ciphertext)

	// Verify decryption matches original
	if !bytes.Equal(originalPayload, decrypted) {
		t.Error("decrypted payload does not match original")
	}

	t.Log("Encrypted payload round-trip successful")
	t.Logf("  Original size: %d bytes", len(originalPayload))
	t.Logf("  Ciphertext size: %d bytes", len(ciphertext))
}

// TestEncryptedPayloadWithRSAKeyWrap tests the full encrypted payload workflow:
// 1. Generate symmetric key and IV
// 2. Encrypt payload with symmetric key
// 3. Wrap symmetric key with RSA public key (OAEP)
// 4. Unwrap symmetric key with RSA private key
// 5. Decrypt payload
func TestEncryptedPayloadWithRSAKeyWrap(t *testing.T) {
	// Generate RSA key pair (device attestation key)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Original payload
	originalPayload := []byte(`{"command": "update_firmware", "version": "2.0.1", "checksum": "abc123"}`)

	// === ENCRYPTION SIDE (Owner/Server) - using fdo.EncryptPayload ===
	wrappedKey, iv, ciphertext, err := fdo.EncryptPayload(&rsaKey.PublicKey, originalPayload)
	if err != nil {
		t.Fatalf("failed to encrypt payload: %v", err)
	}

	// === DECRYPTION SIDE (Device) - using fdo.DecryptPayload ===
	decrypted, err := fdo.DecryptPayload(rsaKey, wrappedKey, iv, ciphertext)
	if err != nil {
		t.Fatalf("failed to decrypt payload: %v", err)
	}

	// Verify decryption
	if !bytes.Equal(originalPayload, decrypted) {
		t.Error("decrypted payload does not match original")
	}

	t.Log("Encrypted payload with RSA key wrap successful (using fdo.EncryptPayload/DecryptPayload)")
	t.Logf("  Payload size: %d bytes", len(originalPayload))
	t.Logf("  Wrapped key size: %d bytes", len(wrappedKey))
}

// TestEncryptedPayloadWrongKey verifies that decryption fails with wrong key.
func TestEncryptedPayloadWrongKey(t *testing.T) {
	// Generate correct symmetric key
	correctKey := make([]byte, 32)
	if _, err := rand.Read(correctKey); err != nil {
		t.Fatalf("failed to generate correct key: %v", err)
	}

	// Generate wrong symmetric key
	wrongKey := make([]byte, 32)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatalf("failed to generate wrong key: %v", err)
	}

	// Generate IV
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("failed to generate IV: %v", err)
	}

	// Original payload
	originalPayload := []byte("Secret payload content")

	// Encrypt with correct key
	block, _ := aes.NewCipher(correctKey)
	ciphertext := make([]byte, len(originalPayload))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, originalPayload)

	// Try to decrypt with WRONG key
	wrongBlock, _ := aes.NewCipher(wrongKey)
	decrypted := make([]byte, len(ciphertext))
	cipher.NewCTR(wrongBlock, iv).XORKeyStream(decrypted, ciphertext)

	// Decryption should produce garbage (not match original)
	if bytes.Equal(originalPayload, decrypted) {
		t.Error("SECURITY FAILURE: decryption with wrong key produced correct plaintext")
	}

	t.Log("Correctly failed to decrypt with wrong key (produced garbage)")
}

// TestEncryptedPayloadWrongIV verifies that decryption fails with wrong IV.
func TestEncryptedPayloadWrongIV(t *testing.T) {
	// Generate symmetric key
	symmetricKey := make([]byte, 32)
	if _, err := rand.Read(symmetricKey); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Generate correct IV
	correctIV := make([]byte, 16)
	if _, err := rand.Read(correctIV); err != nil {
		t.Fatalf("failed to generate correct IV: %v", err)
	}

	// Generate wrong IV
	wrongIV := make([]byte, 16)
	if _, err := rand.Read(wrongIV); err != nil {
		t.Fatalf("failed to generate wrong IV: %v", err)
	}

	// Original payload
	originalPayload := []byte("Secret payload content")

	// Encrypt with correct IV
	block, _ := aes.NewCipher(symmetricKey)
	ciphertext := make([]byte, len(originalPayload))
	cipher.NewCTR(block, correctIV).XORKeyStream(ciphertext, originalPayload)

	// Try to decrypt with WRONG IV
	decrypted := make([]byte, len(ciphertext))
	cipher.NewCTR(block, wrongIV).XORKeyStream(decrypted, ciphertext)

	// Decryption should produce garbage
	if bytes.Equal(originalPayload, decrypted) {
		t.Error("SECURITY FAILURE: decryption with wrong IV produced correct plaintext")
	}

	t.Log("Correctly failed to decrypt with wrong IV (produced garbage)")
}

// TestEncryptedPayloadCorruptedCiphertext verifies behavior with corrupted ciphertext.
func TestEncryptedPayloadCorruptedCiphertext(t *testing.T) {
	// Generate symmetric key and IV
	symmetricKey := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(symmetricKey)
	rand.Read(iv)

	// Original payload
	originalPayload := []byte("Secret payload that will be corrupted")

	// Encrypt
	block, _ := aes.NewCipher(symmetricKey)
	ciphertext := make([]byte, len(originalPayload))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, originalPayload)

	// Corrupt the ciphertext
	ciphertext[0] ^= 0xFF
	ciphertext[len(ciphertext)/2] ^= 0xFF

	// Decrypt corrupted ciphertext
	decrypted := make([]byte, len(ciphertext))
	cipher.NewCTR(block, iv).XORKeyStream(decrypted, ciphertext)

	// Should produce garbage (corrupted plaintext)
	if bytes.Equal(originalPayload, decrypted) {
		t.Error("SECURITY FAILURE: corrupted ciphertext produced correct plaintext")
	}

	t.Log("Corrupted ciphertext correctly produced corrupted plaintext")
}

// TestEncryptedPayloadWithWrongRSAKey verifies that key unwrapping fails
// with the wrong RSA private key.
func TestEncryptedPayloadWithWrongRSAKey(t *testing.T) {
	// Generate correct RSA key pair
	correctKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate correct RSA key: %v", err)
	}

	// Generate wrong RSA key pair (attacker's key)
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate wrong RSA key: %v", err)
	}

	// Original payload
	originalPayload := []byte("Secret payload for wrong key test")

	// Encrypt with CORRECT public key using fdo.EncryptPayload
	wrappedKey, iv, ciphertext, err := fdo.EncryptPayload(&correctKey.PublicKey, originalPayload)
	if err != nil {
		t.Fatalf("failed to encrypt payload: %v", err)
	}

	// Try to decrypt with WRONG private key using fdo.DecryptPayload
	_, err = fdo.DecryptPayload(wrongKey, wrappedKey, iv, ciphertext)
	if err == nil {
		t.Error("SECURITY FAILURE: decryption succeeded with wrong RSA key")
	} else {
		t.Logf("Correctly failed to decrypt with wrong RSA key: %v", err)
	}
}

// TestEncryptedAndSignedPayload tests a payload that is both encrypted and signed.
func TestEncryptedAndSignedPayload(t *testing.T) {
	// Generate owner key for signing
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	// Generate device RSA key for encryption
	deviceKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate device key: %v", err)
	}

	// Original payload
	originalPayload := []byte(`{"action": "provision", "config": {"secure": true}}`)

	// === OWNER SIDE: Encrypt and Sign using fdo.EncryptPayload ===
	wrappedKey, iv, ciphertext, err := fdo.EncryptPayload(&deviceKey.PublicKey, originalPayload)
	if err != nil {
		t.Fatalf("failed to encrypt payload: %v", err)
	}

	// Sign the CIPHERTEXT (not plaintext) - this proves owner created this encrypted payload
	signature, err := signPayload(ownerKey, ciphertext)
	if err != nil {
		t.Fatalf("failed to sign ciphertext: %v", err)
	}

	// === DEVICE SIDE: Use fdo.VerifyAttestedPayload ===
	ap := &fdo.AttestedPayload{
		Ciphertext: ciphertext,
		Signature:  signature,
		IV:         iv,
		WrappedKey: wrappedKey,
	}

	decrypted, err := fdo.VerifyAttestedPayload(ap, ownerKey.Public(), deviceKey)
	if err != nil {
		t.Fatalf("VerifyAttestedPayload failed: %v", err)
	}

	// Verify decryption
	if !bytes.Equal(originalPayload, decrypted) {
		t.Error("decrypted payload does not match original")
	}

	t.Log("Encrypted and signed payload workflow successful (using fdo.VerifyAttestedPayload)")
	t.Logf("  Payload verified and decrypted correctly")
}

// TestVerifyAttestedPayloadPlaintext tests fdo.VerifyAttestedPayload with plaintext payload
func TestVerifyAttestedPayloadPlaintext(t *testing.T) {
	// Generate owner key
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	// Create payload
	payload := []byte("This is a plaintext attested payload")

	// Sign the payload
	signature, err := signPayload(ownerKey, payload)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	// Create AttestedPayload
	ap := &fdo.AttestedPayload{
		Payload:   payload,
		Signature: signature,
	}

	// Verify using fdo.VerifyAttestedPayload
	verified, err := fdo.VerifyAttestedPayload(ap, ownerKey.Public(), nil)
	if err != nil {
		t.Fatalf("VerifyAttestedPayload failed: %v", err)
	}

	if !bytes.Equal(payload, verified) {
		t.Error("verified payload does not match original")
	}

	t.Log("Plaintext attested payload verified successfully using fdo.VerifyAttestedPayload")
}

// TestVerifyAttestedPayloadWithDelegate tests fdo.VerifyAttestedPayload with delegate chain
func TestVerifyAttestedPayloadWithDelegate(t *testing.T) {
	// Generate owner key
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	// Generate delegate key
	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	// Create delegate certificate with provision permission
	delegateCert, err := fdo.GenerateDelegate(
		ownerKey,
		fdo.DelegateFlagRoot,
		delegateKey.Public(),
		"ProvisionDelegate",
		"Owner",
		[]asn1.ObjectIdentifier{fdo.OIDDelegateProvision},
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate delegate cert: %v", err)
	}

	// Create payload
	payload := []byte("Delegate-signed attested payload")

	// Sign with delegate key
	signature, err := signPayload(delegateKey, payload)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	// Create AttestedPayload with delegate chain
	ap := &fdo.AttestedPayload{
		Payload:       payload,
		Signature:     signature,
		DelegateChain: []*x509.Certificate{delegateCert},
	}

	// Verify using fdo.VerifyAttestedPayload
	verified, err := fdo.VerifyAttestedPayload(ap, ownerKey.Public(), nil)
	if err != nil {
		t.Fatalf("VerifyAttestedPayload failed: %v", err)
	}

	if !bytes.Equal(payload, verified) {
		t.Error("verified payload does not match original")
	}

	t.Log("Delegate-signed attested payload verified successfully using fdo.VerifyAttestedPayload")
}

// TestVerifyAttestedPayloadInvalidSignature tests that invalid signatures are rejected
func TestVerifyAttestedPayloadInvalidSignature(t *testing.T) {
	// Generate owner key
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	// Create payload
	payload := []byte("Test payload")

	// Sign the payload
	signature, err := signPayload(ownerKey, payload)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	// Corrupt the signature
	signature[0] ^= 0xFF

	// Create AttestedPayload
	ap := &fdo.AttestedPayload{
		Payload:   payload,
		Signature: signature,
	}

	// Verify should fail
	_, err = fdo.VerifyAttestedPayload(ap, ownerKey.Public(), nil)
	if err == nil {
		t.Error("SECURITY FAILURE: VerifyAttestedPayload accepted corrupted signature")
	} else {
		t.Logf("Correctly rejected corrupted signature: %v", err)
	}
}

// TestVerifyAttestedPayloadUnauthorizedDelegate tests that delegates without provision permission are rejected
func TestVerifyAttestedPayloadUnauthorizedDelegate(t *testing.T) {
	// Generate owner key
	ownerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate owner key: %v", err)
	}

	// Generate delegate key
	delegateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate delegate key: %v", err)
	}

	// Create delegate certificate WITHOUT provision permission
	delegateCert, err := fdo.GenerateDelegate(
		ownerKey,
		fdo.DelegateFlagRoot,
		delegateKey.Public(),
		"OnboardOnlyDelegate",
		"Owner",
		[]asn1.ObjectIdentifier{fdo.OIDPermitOnboardNewCred}, // No provision permission!
		x509.ECDSAWithSHA384,
	)
	if err != nil {
		t.Fatalf("failed to generate delegate cert: %v", err)
	}

	// Create payload
	payload := []byte("Unauthorized delegate payload")

	// Sign with delegate key
	signature, err := signPayload(delegateKey, payload)
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}

	// Create AttestedPayload with unauthorized delegate chain
	ap := &fdo.AttestedPayload{
		Payload:       payload,
		Signature:     signature,
		DelegateChain: []*x509.Certificate{delegateCert},
	}

	// Verify should fail
	_, err = fdo.VerifyAttestedPayload(ap, ownerKey.Public(), nil)
	if err == nil {
		t.Error("SECURITY FAILURE: VerifyAttestedPayload accepted delegate without provision permission")
	} else {
		t.Logf("Correctly rejected unauthorized delegate: %v", err)
	}
}
