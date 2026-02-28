// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

// helper: generate an EC key pair and return private key + CBOR-encoded COSE_Key (public)
func generateTestKey(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	coseKey, err := cose.NewKey(privKey.Public())
	if err != nil {
		t.Fatalf("failed to create COSE_Key: %v", err)
	}
	keyBytes, err := cbor.Marshal(coseKey)
	if err != nil {
		t.Fatalf("failed to marshal COSE_Key: %v", err)
	}
	return privKey, keyBytes
}

// helper: sign a payload with COSE Sign1 and return the tagged CBOR bytes
func signPayload(t *testing.T, privKey *ecdsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	s1 := cose.Sign1[[]byte, []byte]{
		Payload: cbor.NewByteWrap(payload),
	}
	if err := s1.Sign(privKey, nil, nil, nil); err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	// Marshal as tagged COSE_Sign1
	tagged := s1.Tag()
	data, err := cbor.Marshal(tagged)
	if err != nil {
		t.Fatalf("failed to marshal Sign1Tag: %v", err)
	}
	return data
}

// TestCoseSign1Verifier_ValidSignature_P256 verifies that a correctly signed
// meta-payload with a P-256 key is accepted and the inner payload is returned.
func TestCoseSign1Verifier_ValidSignature_P256(t *testing.T) {
	privKey, signerKeyBytes := generateTestKey(t, elliptic.P256())

	innerPayload := []byte("test meta-payload content for P-256")
	signedData := signPayload(t, privKey, innerPayload)

	verifier := NewCoseSign1Verifier()
	result, err := verifier.Verify(signedData, signerKeyBytes)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if string(result) != string(innerPayload) {
		t.Errorf("payload mismatch: got %q, want %q", result, innerPayload)
	}
}

// TestCoseSign1Verifier_ValidSignature_P384 verifies P-384 key support.
func TestCoseSign1Verifier_ValidSignature_P384(t *testing.T) {
	privKey, signerKeyBytes := generateTestKey(t, elliptic.P384())

	innerPayload := []byte("test meta-payload content for P-384")
	signedData := signPayload(t, privKey, innerPayload)

	verifier := NewCoseSign1Verifier()
	result, err := verifier.Verify(signedData, signerKeyBytes)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if string(result) != string(innerPayload) {
		t.Errorf("payload mismatch: got %q, want %q", result, innerPayload)
	}
}

// TestCoseSign1Verifier_ValidSignature_P521 verifies P-521 key support.
func TestCoseSign1Verifier_ValidSignature_P521(t *testing.T) {
	privKey, signerKeyBytes := generateTestKey(t, elliptic.P521())

	innerPayload := []byte("test meta-payload content for P-521")
	signedData := signPayload(t, privKey, innerPayload)

	verifier := NewCoseSign1Verifier()
	result, err := verifier.Verify(signedData, signerKeyBytes)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if string(result) != string(innerPayload) {
		t.Errorf("payload mismatch: got %q, want %q", result, innerPayload)
	}
}

// TestCoseSign1Verifier_ValidSignature_CBORPayload verifies that a CBOR-encoded
// MetaPayload (the real use case) roundtrips correctly.
func TestCoseSign1Verifier_ValidSignature_CBORPayload(t *testing.T) {
	privKey, signerKeyBytes := generateTestKey(t, elliptic.P256())

	// Create a realistic MetaPayload CBOR
	meta := MetaPayload{
		MIMEType: "application/x-raw-disk-image",
		URL:      "http://example.com/image.bin",
		HashAlg:  "sha256",
		Name:     "test-image",
	}
	metaCBOR, err := meta.MarshalCBOR()
	if err != nil {
		t.Fatalf("failed to marshal MetaPayload: %v", err)
	}

	signedData := signPayload(t, privKey, metaCBOR)

	verifier := NewCoseSign1Verifier()
	result, err := verifier.Verify(signedData, signerKeyBytes)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Verify the returned payload can be parsed back as MetaPayload
	var parsed MetaPayload
	if err := parsed.UnmarshalCBOR(result); err != nil {
		t.Fatalf("failed to unmarshal returned payload as MetaPayload: %v", err)
	}
	if parsed.MIMEType != meta.MIMEType {
		t.Errorf("MIMEType mismatch: got %q, want %q", parsed.MIMEType, meta.MIMEType)
	}
	if parsed.URL != meta.URL {
		t.Errorf("URL mismatch: got %q, want %q", parsed.URL, meta.URL)
	}
	if parsed.Name != meta.Name {
		t.Errorf("Name mismatch: got %q, want %q", parsed.Name, meta.Name)
	}
}

// TestCoseSign1Verifier_WrongKey verifies that verification fails when a
// different key is used to verify than the one that signed.
func TestCoseSign1Verifier_WrongKey(t *testing.T) {
	signingKey, _ := generateTestKey(t, elliptic.P256())
	_, wrongKeyBytes := generateTestKey(t, elliptic.P256())

	innerPayload := []byte("signed with one key, verified with another")
	signedData := signPayload(t, signingKey, innerPayload)

	verifier := NewCoseSign1Verifier()
	_, err := verifier.Verify(signedData, wrongKeyBytes)
	if err == nil {
		t.Fatal("expected verification to fail with wrong key, but it succeeded")
	}
	t.Logf("correctly rejected wrong key: %v", err)
}

// TestCoseSign1Verifier_TamperedPayload verifies that verification fails when
// the signed payload has been tampered with after signing.
func TestCoseSign1Verifier_TamperedPayload(t *testing.T) {
	privKey, signerKeyBytes := generateTestKey(t, elliptic.P256())

	innerPayload := []byte("original payload")
	signedData := signPayload(t, privKey, innerPayload)

	// Tamper with the signed data by flipping a byte in the payload area
	// The payload is embedded in the CBOR structure, so we find it and modify it
	tampered := make([]byte, len(signedData))
	copy(tampered, signedData)
	// Flip a byte somewhere in the middle (past the COSE headers, into the payload)
	if len(tampered) > 30 {
		tampered[len(tampered)/2] ^= 0xFF
	}

	verifier := NewCoseSign1Verifier()
	_, err := verifier.Verify(tampered, signerKeyBytes)
	if err == nil {
		t.Fatal("expected verification to fail with tampered payload, but it succeeded")
	}
	t.Logf("correctly rejected tampered payload: %v", err)
}

// TestCoseSign1Verifier_TamperedSignature verifies that verification fails when
// the signature bytes themselves are modified.
func TestCoseSign1Verifier_TamperedSignature(t *testing.T) {
	privKey, signerKeyBytes := generateTestKey(t, elliptic.P256())

	innerPayload := []byte("payload with tampered signature")

	// Sign normally
	s1 := cose.Sign1[[]byte, []byte]{
		Payload: cbor.NewByteWrap(innerPayload),
	}
	if err := s1.Sign(privKey, nil, nil, nil); err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Tamper with the signature
	if len(s1.Signature) > 0 {
		s1.Signature[0] ^= 0xFF
	}

	tagged := s1.Tag()
	signedData, err := cbor.Marshal(tagged)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	verifier := NewCoseSign1Verifier()
	_, err = verifier.Verify(signedData, signerKeyBytes)
	if err == nil {
		t.Fatal("expected verification to fail with tampered signature, but it succeeded")
	}
	t.Logf("correctly rejected tampered signature: %v", err)
}

// TestCoseSign1Verifier_InvalidSignerKey verifies that an invalid COSE_Key
// is properly rejected.
func TestCoseSign1Verifier_InvalidSignerKey(t *testing.T) {
	verifier := NewCoseSign1Verifier()

	tests := []struct {
		name     string
		keyBytes []byte
	}{
		{"empty key", []byte{}},
		{"garbage bytes", []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		{"valid CBOR but not a key", func() []byte { b, _ := cbor.Marshal("not a key"); return b }()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Use some dummy signed data (doesn't matter, key parsing should fail first)
			_, err := verifier.Verify([]byte{0xD2, 0x84}, tc.keyBytes)
			if err == nil {
				t.Fatal("expected error for invalid signer key, but got nil")
			}
			t.Logf("correctly rejected %s: %v", tc.name, err)
		})
	}
}

// TestCoseSign1Verifier_InvalidSignedPayload verifies that invalid COSE_Sign1
// data is properly rejected.
func TestCoseSign1Verifier_InvalidSignedPayload(t *testing.T) {
	_, signerKeyBytes := generateTestKey(t, elliptic.P256())

	verifier := NewCoseSign1Verifier()

	tests := []struct {
		name    string
		payload []byte
	}{
		{"empty payload", []byte{}},
		{"garbage bytes", []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		{"valid CBOR but not Sign1", func() []byte { b, _ := cbor.Marshal("hello"); return b }()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifier.Verify(tc.payload, signerKeyBytes)
			if err == nil {
				t.Fatal("expected error for invalid signed payload, but got nil")
			}
			t.Logf("correctly rejected %s: %v", tc.name, err)
		})
	}
}

// TestCoseSign1Verifier_CurveMismatch verifies that verification fails when
// the signing key curve doesn't match the verification key curve.
func TestCoseSign1Verifier_CurveMismatch(t *testing.T) {
	p256Key, _ := generateTestKey(t, elliptic.P256())
	_, p384KeyBytes := generateTestKey(t, elliptic.P384())

	innerPayload := []byte("signed with P-256, verified with P-384")
	signedData := signPayload(t, p256Key, innerPayload)

	verifier := NewCoseSign1Verifier()
	_, err := verifier.Verify(signedData, p384KeyBytes)
	if err == nil {
		t.Fatal("expected verification to fail with curve mismatch, but it succeeded")
	}
	t.Logf("correctly rejected curve mismatch: %v", err)
}

// TestCoseSign1Verifier_ImplementsInterface verifies that CoseSign1Verifier
// satisfies the MetaPayloadVerifier interface.
func TestCoseSign1Verifier_ImplementsInterface(t *testing.T) {
	var _ MetaPayloadVerifier = (*CoseSign1Verifier)(nil)
	var _ MetaPayloadVerifier = NewCoseSign1Verifier()
}

// TestBMOTransition_AutoInitializesVerifier verifies that the BMO module
// automatically initializes MetaPayloadVerifier on Transition(true).
func TestBMOTransition_AutoInitializesVerifier(t *testing.T) {
	bmo := &BMO{
		UnifiedHandler: &coseTestImageHandler{},
	}

	// Before transition, verifier should be nil
	if bmo.MetaPayloadVerifier != nil {
		t.Fatal("expected MetaPayloadVerifier to be nil before Transition")
	}

	// Activate the module
	if err := bmo.Transition(true); err != nil {
		t.Fatalf("Transition(true) failed: %v", err)
	}

	// After transition, verifier should be auto-initialized
	if bmo.MetaPayloadVerifier == nil {
		t.Fatal("expected MetaPayloadVerifier to be auto-initialized after Transition(true)")
	}

	// Verify it's a CoseSign1Verifier
	if _, ok := bmo.MetaPayloadVerifier.(*CoseSign1Verifier); !ok {
		t.Errorf("expected *CoseSign1Verifier, got %T", bmo.MetaPayloadVerifier)
	}
}

// TestBMOTransition_DoesNotOverrideCustomVerifier verifies that a custom
// MetaPayloadVerifier set by the application is not replaced on Transition.
func TestBMOTransition_DoesNotOverrideCustomVerifier(t *testing.T) {
	custom := &mockMetaPayloadVerifier{payload: []byte("custom")}
	bmo := &BMO{
		UnifiedHandler:      &coseTestImageHandler{},
		MetaPayloadVerifier: custom,
	}

	if err := bmo.Transition(true); err != nil {
		t.Fatalf("Transition(true) failed: %v", err)
	}

	// Should still be the custom verifier
	if bmo.MetaPayloadVerifier != custom {
		t.Error("custom MetaPayloadVerifier was overridden by Transition")
	}
}

// coseTestImageHandler is a minimal UnifiedImageHandler for testing BMO Transition behavior.
// Named differently from mockUnifiedImageHandler in bmo_url_test.go to avoid redeclaration.
type coseTestImageHandler struct{}

func (h *coseTestImageHandler) HandleImage(_ context.Context, _, _ string, _ uint64, _ map[string]any, _ []byte) (int, string, error) {
	return 0, "ok", nil
}
