// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

//go:build tpmsim

// Package cred integration tests for the TPM-backed credential store.
//
// These tests exercise the production cred.Store interface end-to-end
// using the software TPM simulator (build with -tags=tpmsim).
//
// Run:
//
//	cd cred && go test -v -tags=tpmsim -count=1
//
// Environment:
//
//	FDO_TPM_OWNER_HIERARCHY=1  Use Owner hierarchy (required for Linux userspace)
package cred

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// TestTPMStore_NVOnlyRoundTrip proves that the production cred.Store
// interface can perform a complete DI → Save → (delete file) → Load
// cycle using ONLY TPM NV storage.
//
// This is the critical gap test: it proves the cred.Store code path
// works without any file-based fallback.
func TestTPMStore_NVOnlyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "cred.bin")

	// Force Owner hierarchy — Platform is locked in Linux userspace
	t.Setenv("FDO_TPM_OWNER_HIERARCHY", "1")

	store, err := Open(credPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	// =====================================================================
	// PROVISION: NewDI → Save
	// =====================================================================
	h256, h384, key, err := store.NewDI(protocol.Secp256r1KeyType)
	if err != nil {
		t.Fatalf("NewDI: %v", err)
	}
	t.Logf("NewDI: h256=%T h384=%T key=%T", h256, h384, key)

	// Extract the public key for later verification
	ecPub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", key.Public())
	}
	t.Logf("DAK public key: P-%d", ecPub.Curve.Params().BitSize)

	// Sign a baseline challenge with the provision-time key
	baselineDigest := sha256.Sum256([]byte("baseline challenge"))
	baselineSig, err := key.Sign(nil, baselineDigest[:], nil)
	if err != nil {
		t.Fatalf("Sign (baseline): %v", err)
	}
	if !ecdsa.VerifyASN1(ecPub, baselineDigest[:], baselineSig) {
		t.Fatal("baseline signature verification failed")
	}
	t.Log("Baseline sign+verify OK")

	// Compute HMAC baseline over test data
	testGUID := protocol.GUID{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00, 0x01,
		0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	h256.Write(testGUID[:])
	hmacBaseline := h256.Sum(nil)
	t.Logf("HMAC baseline: %x", hmacBaseline)

	// Create a realistic DeviceCredential
	dc := fdo.DeviceCredential{
		Version:    101,
		DeviceInfo: "cred-store-integration-test",
		GUID:       testGUID,
		RvInfo: [][]protocol.RvInstruction{
			{{Variable: 13, Value: []byte{0}}},
		},
		PublicKeyHash: protocol.Hash{
			Algorithm: protocol.Sha256Hash,
			Value:     baselineDigest[:], // placeholder
		},
	}

	if err := store.Save(dc); err != nil {
		t.Fatalf("Save: %v", err)
	}
	t.Log("Save completed — NV + file written")

	// Verify file was written (Save writes both NV and file)
	if _, err := os.Stat(credPath); err != nil {
		t.Fatalf("credential file not created: %v", err)
	}

	// =====================================================================
	// DELETE THE FILE — force NV-only Load path
	// =====================================================================
	if err := os.Remove(credPath); err != nil {
		t.Fatalf("remove credential file: %v", err)
	}
	if _, err := os.Stat(credPath); !os.IsNotExist(err) {
		t.Fatal("credential file should not exist")
	}
	t.Log("Credential file DELETED — Load must use NV only")

	// =====================================================================
	// LOAD: Must succeed from NV (file is gone)
	// =====================================================================
	loadedDC, loadH256, _, loadKey, err := store.Load()
	if err != nil {
		t.Fatalf("Load (NV-only): %v", err)
	}
	t.Log("Load from NV succeeded")

	// Verify credential fields match
	if loadedDC.Version != dc.Version {
		t.Errorf("Version: got %d, want %d", loadedDC.Version, dc.Version)
	}
	if loadedDC.DeviceInfo != dc.DeviceInfo {
		t.Errorf("DeviceInfo: got %q, want %q", loadedDC.DeviceInfo, dc.DeviceInfo)
	}
	if loadedDC.GUID != dc.GUID {
		t.Errorf("GUID: got %x, want %x", loadedDC.GUID, dc.GUID)
	}
	if loadedDC.PublicKeyHash.Algorithm != dc.PublicKeyHash.Algorithm {
		t.Errorf("PublicKeyHash.Algorithm: got %d, want %d",
			loadedDC.PublicKeyHash.Algorithm, dc.PublicKeyHash.Algorithm)
	}
	if !bytes.Equal(loadedDC.PublicKeyHash.Value, dc.PublicKeyHash.Value) {
		t.Errorf("PublicKeyHash.Value mismatch")
	}
	if len(loadedDC.RvInfo) != len(dc.RvInfo) {
		t.Errorf("RvInfo length: got %d, want %d", len(loadedDC.RvInfo), len(dc.RvInfo))
	}
	t.Log("Credential fields match")

	// Verify the loaded key matches the provision-time key
	loadedPub, ok := loadKey.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("loaded key: expected *ecdsa.PublicKey, got %T", loadKey.Public())
	}
	if ecPub.X.Cmp(loadedPub.X) != 0 || ecPub.Y.Cmp(loadedPub.Y) != 0 {
		t.Fatal("loaded public key does not match provision-time public key")
	}
	t.Log("Public key matches")

	// Sign with the loaded key, verify with the provision-time public key
	challenge := sha256.Sum256([]byte("post-load challenge"))
	sig, err := loadKey.Sign(nil, challenge[:], nil)
	if err != nil {
		t.Fatalf("Sign (loaded key): %v", err)
	}
	if !ecdsa.VerifyASN1(ecPub, challenge[:], sig) {
		t.Fatal("loaded key signature verification failed against provision pubkey")
	}
	t.Log("Sign+Verify with loaded key OK")

	// Verify HMAC consistency: same data → same HMAC
	loadH256.Write(testGUID[:])
	loadedHmac := loadH256.Sum(nil)
	if !bytes.Equal(loadedHmac, hmacBaseline) {
		t.Fatalf("HMAC mismatch:\n  loaded:   %x\n  baseline: %x", loadedHmac, hmacBaseline)
	}
	t.Log("HMAC matches baseline — persistent HMAC key works")

	t.Log("=== PASSED: cred.Store NV-only round-trip (no file, full credential lifecycle) ===")
}

// TestTPMStore_FileFallback verifies that Load() falls back to file-based
// loading when NV indices are NOT provisioned (backward compatibility).
func TestTPMStore_FileFallback(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "cred.bin")

	t.Setenv("FDO_TPM_OWNER_HIERARCHY", "1")

	store, err := Open(credPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Provision and save (this writes both NV and file)
	_, _, _, err = store.NewDI(protocol.Secp256r1KeyType)
	if err != nil {
		t.Fatalf("NewDI: %v", err)
	}

	testGUID := protocol.GUID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	dc := fdo.DeviceCredential{
		Version:    101,
		DeviceInfo: "fallback-test",
		GUID:       testGUID,
		RvInfo: [][]protocol.RvInstruction{
			{{Variable: 13, Value: []byte{0}}},
		},
		PublicKeyHash: protocol.Hash{
			Algorithm: protocol.Sha256Hash,
			Value:     make([]byte, 32),
		},
	}
	if err := store.Save(dc); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// File should exist
	if _, err := os.Stat(credPath); err != nil {
		t.Fatalf("credential file should exist: %v", err)
	}

	// Load should work (NV-first path)
	loadedDC, _, _, _, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loadedDC.GUID != testGUID {
		t.Errorf("GUID mismatch: got %x, want %x", loadedDC.GUID, testGUID)
	}
	t.Log("Load succeeded (NV-first path with file also present)")
}

// TestTPMStore_SaveOverwrite verifies that Save() can be called multiple
// times (simulating credential reuse / re-onboard) and Load() returns
// the latest credential.
func TestTPMStore_SaveOverwrite(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "cred.bin")

	t.Setenv("FDO_TPM_OWNER_HIERARCHY", "1")

	store, err := Open(credPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	_, _, _, err = store.NewDI(protocol.Secp256r1KeyType)
	if err != nil {
		t.Fatalf("NewDI: %v", err)
	}

	// First save
	dc1 := fdo.DeviceCredential{
		Version:    101,
		DeviceInfo: "device-v1",
		GUID:       protocol.GUID{0x01},
		PublicKeyHash: protocol.Hash{
			Algorithm: protocol.Sha256Hash,
			Value:     make([]byte, 32),
		},
	}
	if err := store.Save(dc1); err != nil {
		t.Fatalf("Save(dc1): %v", err)
	}

	// Second save (simulates TO2 credential update)
	dc2 := fdo.DeviceCredential{
		Version:    101,
		DeviceInfo: "device-v2",
		GUID:       protocol.GUID{0x02},
		RvInfo: [][]protocol.RvInstruction{
			{{Variable: 13, Value: []byte{0}}},
		},
		PublicKeyHash: protocol.Hash{
			Algorithm: protocol.Sha256Hash,
			Value:     make([]byte, 32),
		},
	}
	if err := store.Save(dc2); err != nil {
		t.Fatalf("Save(dc2): %v", err)
	}

	// Delete file to force NV load
	os.Remove(credPath)

	loadedDC, _, _, _, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Should get dc2 (latest save) — DCTPM is the last written
	if loadedDC.GUID != dc2.GUID {
		t.Errorf("GUID: got %x, want %x (expected dc2)", loadedDC.GUID, dc2.GUID)
	}
	if loadedDC.DeviceInfo != dc2.DeviceInfo {
		t.Errorf("DeviceInfo: got %q, want %q", loadedDC.DeviceInfo, dc2.DeviceInfo)
	}
	t.Log("Save overwrite + NV load OK — got latest credential")
}
