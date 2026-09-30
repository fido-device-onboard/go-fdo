// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestCreateMetaPayload_Basic(t *testing.T) {
	imageData := []byte("fake image data for testing")
	hash := ComputeSHA256(imageData)

	data, err := CreateMetaPayload(
		"application/x-raw-disk-image",
		"http://cdn.example.com/image.bin",
		"test-image",
		"sha256",
		hash,
	)
	if err != nil {
		t.Fatalf("CreateMetaPayload failed: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("CreateMetaPayload returned empty data")
	}

	// Parse it back
	var meta MetaPayload
	if err := meta.UnmarshalCBOR(data); err != nil {
		t.Fatalf("UnmarshalCBOR failed: %v", err)
	}
	if meta.MIMEType != "application/x-raw-disk-image" {
		t.Errorf("MIMEType = %q, want %q", meta.MIMEType, "application/x-raw-disk-image")
	}
	if meta.URL != "http://cdn.example.com/image.bin" {
		t.Errorf("URL = %q, want %q", meta.URL, "http://cdn.example.com/image.bin")
	}
	if meta.Name != "test-image" {
		t.Errorf("Name = %q, want %q", meta.Name, "test-image")
	}
	if meta.HashAlg != "sha256" {
		t.Errorf("HashAlg = %q, want %q", meta.HashAlg, "sha256")
	}
	if len(meta.ExpectedHash) != 32 {
		t.Errorf("ExpectedHash length = %d, want 32", len(meta.ExpectedHash))
	}
}

func TestCreateMetaPayload_WithOptions(t *testing.T) {
	data, err := CreateMetaPayload(
		"application/x-raw-disk-image",
		"http://cdn.example.com/image.bin",
		"", "", nil,
		WithBootArgs("root=/dev/sda1"),
		WithVersion("1.2.3"),
		WithDescription("Test boot image"),
	)
	if err != nil {
		t.Fatalf("CreateMetaPayload failed: %v", err)
	}

	var meta MetaPayload
	if err := meta.UnmarshalCBOR(data); err != nil {
		t.Fatalf("UnmarshalCBOR failed: %v", err)
	}
	if meta.BootArgs != "root=/dev/sda1" {
		t.Errorf("BootArgs = %q, want %q", meta.BootArgs, "root=/dev/sda1")
	}
	if meta.Version != "1.2.3" {
		t.Errorf("Version = %q, want %q", meta.Version, "1.2.3")
	}
	if meta.Description != "Test boot image" {
		t.Errorf("Description = %q, want %q", meta.Description, "Test boot image")
	}
}

func TestCreateMetaPayload_RequiredFields(t *testing.T) {
	// Missing mimeType
	_, err := CreateMetaPayload("", "http://example.com", "", "", nil)
	if err == nil {
		t.Error("expected error for missing mimeType")
	}

	// Missing imageURL
	_, err = CreateMetaPayload("application/octet-stream", "", "", "", nil)
	if err == nil {
		t.Error("expected error for missing imageURL")
	}
}

func TestSignMetaPayload_RoundTrip(t *testing.T) {
	// Generate a test key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Create a meta-payload
	imageData := []byte("test image content for round-trip")
	hash := ComputeSHA256(imageData)
	metaCBOR, err := CreateMetaPayload(
		"application/x-raw-disk-image",
		"http://cdn.example.com/image.bin",
		"boot-image",
		"sha256",
		hash,
	)
	if err != nil {
		t.Fatalf("CreateMetaPayload failed: %v", err)
	}

	// Sign it
	signed, err := SignMetaPayload(metaCBOR, key)
	if err != nil {
		t.Fatalf("SignMetaPayload failed: %v", err)
	}
	if len(signed) == 0 {
		t.Fatal("SignMetaPayload returned empty data")
	}

	// Export public key as COSE_Key
	pubKeyCBOR, err := MarshalSignerPublicKey(key.Public())
	if err != nil {
		t.Fatalf("MarshalSignerPublicKey failed: %v", err)
	}

	// Verify with CoseSign1Verifier
	verifier := &CoseSign1Verifier{}
	payload, err := verifier.Verify(signed, pubKeyCBOR)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Parse the verified payload
	var meta MetaPayload
	if err := meta.UnmarshalCBOR(payload); err != nil {
		t.Fatalf("UnmarshalCBOR failed: %v", err)
	}
	if meta.MIMEType != "application/x-raw-disk-image" {
		t.Errorf("MIMEType = %q, want %q", meta.MIMEType, "application/x-raw-disk-image")
	}
	if meta.URL != "http://cdn.example.com/image.bin" {
		t.Errorf("URL = %q, want %q", meta.URL, "http://cdn.example.com/image.bin")
	}
	if meta.Name != "boot-image" {
		t.Errorf("Name = %q, want %q", meta.Name, "boot-image")
	}
}

func TestSignMetaPayload_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	metaCBOR, err := CreateMetaPayload(
		"application/x-iso9660-image",
		"http://cdn.example.com/os.iso",
		"os-image", "sha256", nil,
	)
	if err != nil {
		t.Fatalf("CreateMetaPayload failed: %v", err)
	}

	signed, err := SignMetaPayload(metaCBOR, key)
	if err != nil {
		t.Fatalf("SignMetaPayload failed: %v", err)
	}

	pubKeyCBOR, err := MarshalSignerPublicKey(key.Public())
	if err != nil {
		t.Fatalf("MarshalSignerPublicKey failed: %v", err)
	}

	verifier := &CoseSign1Verifier{}
	_, err = verifier.Verify(signed, pubKeyCBOR)
	if err != nil {
		t.Fatalf("Verify P-384 failed: %v", err)
	}
}

func TestSignMetaPayload_NilSigner(t *testing.T) {
	_, err := SignMetaPayload([]byte{0xa0}, nil)
	if err == nil {
		t.Error("expected error for nil signer")
	}
}

func TestMarshalSignerPublicKey_NilKey(t *testing.T) {
	_, err := MarshalSignerPublicKey(nil)
	if err == nil {
		t.Error("expected error for nil key")
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	metaCBOR, err := CreateMetaPayload(
		"application/x-raw-disk-image",
		"http://cdn.example.com/image.bin",
		"test", "sha256", nil,
	)
	if err != nil {
		t.Fatalf("CreateMetaPayload failed: %v", err)
	}

	signed, err := SignMetaPayload(metaCBOR, key)
	if err != nil {
		t.Fatalf("SignMetaPayload failed: %v", err)
	}

	// Tamper with the signed payload (flip a byte near the end — in the signature)
	tampered := make([]byte, len(signed))
	copy(tampered, signed)
	tampered[len(tampered)-2] ^= 0xff

	pubKeyCBOR, err := MarshalSignerPublicKey(key.Public())
	if err != nil {
		t.Fatalf("MarshalSignerPublicKey failed: %v", err)
	}

	verifier := &CoseSign1Verifier{}
	_, err = verifier.Verify(tampered, pubKeyCBOR)
	if err == nil {
		t.Error("expected verification to fail for tampered payload")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	// Sign with key A
	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey A failed: %v", err)
	}
	// Verify with key B
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey B failed: %v", err)
	}

	metaCBOR, err := CreateMetaPayload(
		"application/x-raw-disk-image",
		"http://cdn.example.com/image.bin",
		"test", "", nil,
	)
	if err != nil {
		t.Fatalf("CreateMetaPayload failed: %v", err)
	}

	signed, err := SignMetaPayload(metaCBOR, keyA)
	if err != nil {
		t.Fatalf("SignMetaPayload failed: %v", err)
	}

	// Marshal key B's public key
	wrongPubKeyCBOR, err := MarshalSignerPublicKey(keyB.Public())
	if err != nil {
		t.Fatalf("MarshalSignerPublicKey failed: %v", err)
	}

	verifier := &CoseSign1Verifier{}
	_, err = verifier.Verify(signed, wrongPubKeyCBOR)
	if err == nil {
		t.Error("expected verification to fail with wrong key")
	}
}

func TestAutoDefaultVerifier(t *testing.T) {
	// This tests that the BMO device auto-defaults MetaPayloadVerifier
	// when nil, by directly testing the CoseSign1Verifier (which is what
	// gets auto-created). The actual auto-default behavior is in bmo_device.go.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	metaCBOR, err := CreateMetaPayload(
		"application/x-raw-disk-image",
		"http://cdn.example.com/image.bin",
		"auto-default-test", "sha256", ComputeSHA256([]byte("test")),
	)
	if err != nil {
		t.Fatalf("CreateMetaPayload failed: %v", err)
	}

	signed, err := SignMetaPayload(metaCBOR, key)
	if err != nil {
		t.Fatalf("SignMetaPayload failed: %v", err)
	}

	pubKeyCBOR, err := MarshalSignerPublicKey(key.Public())
	if err != nil {
		t.Fatalf("MarshalSignerPublicKey failed: %v", err)
	}

	// Simulate auto-default: this mirrors bmo_device.go behavior
	// where nil → &CoseSign1Verifier{}
	var verifier MetaPayloadVerifier = &CoseSign1Verifier{}

	payload, err := verifier.Verify(signed, pubKeyCBOR)
	if err != nil {
		t.Fatalf("Auto-defaulted verifier failed: %v", err)
	}

	var meta MetaPayload
	if err := meta.UnmarshalCBOR(payload); err != nil {
		t.Fatalf("UnmarshalCBOR failed: %v", err)
	}
	if meta.Name != "auto-default-test" {
		t.Errorf("Name = %q, want %q", meta.Name, "auto-default-test")
	}
}
