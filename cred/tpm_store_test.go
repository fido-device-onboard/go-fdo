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
	"github.com/fido-device-onboard/go-fdo/tpm"
)

// TestTPMStore_NVOnlyRoundTrip proves that the production cred.Store
// interface can perform a complete DI → Save → Load cycle using ONLY
// TPM NV storage, with no file created on disk at all.
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
	t.Log("Save completed — NV only (no file)")

	// Verify NO file was created — Save no longer writes a file
	if _, err := os.Stat(credPath); !os.IsNotExist(err) {
		t.Fatal("credential file should NOT exist — Save must be NV-only")
	}
	t.Log("Confirmed: no credential file on disk")

	// =====================================================================
	// LOAD: Must succeed from NV (no file exists)
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

	t.Log("=== PASSED: cred.Store NV-only round-trip (zero files, full credential lifecycle) ===")
}

// TestTPMStore_SaveOverwrite verifies that Save() can be called multiple
// times (simulating credential reuse / re-onboard) and Load() returns
// the latest credential from NV.
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

	// Verify no file exists
	if _, err := os.Stat(credPath); !os.IsNotExist(err) {
		t.Fatal("credential file should NOT exist")
	}

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
	t.Log("Save overwrite + NV-only load OK — got latest credential")
}

// TestTPMStore_CrossConnectionPersistence proves that TPM NV state
// survives across Close → Reopen cycles on the simulator, thanks to
// the singleton simulator introduced in open_sim.go.
//
// This is the key test for integration scenarios where the device
// does DI (manufacturing), the store is closed, and later reopened
// for TO1/TO2 onboarding.
func TestTPMStore_CrossConnectionPersistence(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "cred.bin")

	t.Setenv("FDO_TPM_OWNER_HIERARCHY", "1")

	// =====================================================================
	// CONNECTION 1: DI + Save (manufacturing)
	// =====================================================================
	t.Log("--- Connection 1: Device Initialization ---")
	store1, err := Open(credPath)
	if err != nil {
		t.Fatalf("Open (conn 1): %v", err)
	}

	h256, _, key, err := store1.NewDI(protocol.Secp256r1KeyType)
	if err != nil {
		t.Fatalf("NewDI: %v", err)
	}

	// Capture provision-time key for later comparison
	ecPub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", key.Public())
	}
	t.Logf("DAK public key (conn 1): P-%d X=%x", ecPub.Curve.Params().BitSize, ecPub.X.Bytes())

	// Compute HMAC baseline
	testGUID := protocol.GUID{0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44,
		0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xEE, 0xFF}
	h256.Write(testGUID[:])
	hmacBaseline := h256.Sum(nil)

	dc := fdo.DeviceCredential{
		Version:    101,
		DeviceInfo: "cross-conn-test-device",
		GUID:       testGUID,
		RvInfo: [][]protocol.RvInstruction{
			{{Variable: 13, Value: []byte{0}}},
		},
		PublicKeyHash: protocol.Hash{
			Algorithm: protocol.Sha256Hash,
			Value:     make([]byte, 32),
		},
	}
	if err := store1.Save(dc); err != nil {
		t.Fatalf("Save (conn 1): %v", err)
	}
	t.Log("DI + Save completed on connection 1")

	// CLOSE connection 1 — this is the critical step
	if err := store1.Close(); err != nil {
		t.Fatalf("Close (conn 1): %v", err)
	}
	t.Log("Connection 1 closed")

	// =====================================================================
	// CONNECTION 2: Reopen + Load (onboarding)
	// =====================================================================
	t.Log("--- Connection 2: Reopen + Load (simulates onboarding) ---")
	store2, err := Open(credPath)
	if err != nil {
		t.Fatalf("Open (conn 2): %v", err)
	}
	defer func() { _ = store2.Close() }()

	loadedDC, loadH256, _, loadKey, err := store2.Load()
	if err != nil {
		t.Fatalf("Load (conn 2): %v", err)
	}
	t.Log("Load from NV succeeded on connection 2")

	// Verify credential fields survived the close/reopen
	if loadedDC.Version != dc.Version {
		t.Errorf("Version: got %d, want %d", loadedDC.Version, dc.Version)
	}
	if loadedDC.DeviceInfo != dc.DeviceInfo {
		t.Errorf("DeviceInfo: got %q, want %q", loadedDC.DeviceInfo, dc.DeviceInfo)
	}
	if loadedDC.GUID != dc.GUID {
		t.Errorf("GUID: got %x, want %x", loadedDC.GUID, dc.GUID)
	}

	// Verify the loaded key matches the provision-time key
	loadedPub, ok := loadKey.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("loaded key: expected *ecdsa.PublicKey, got %T", loadKey.Public())
	}
	if ecPub.X.Cmp(loadedPub.X) != 0 || ecPub.Y.Cmp(loadedPub.Y) != 0 {
		t.Fatal("DAK public key mismatch across connections")
	}
	t.Log("DAK public key matches across connections")

	// Verify signing works with the loaded key
	challenge := sha256.Sum256([]byte("cross-connection challenge"))
	sig, err := loadKey.Sign(nil, challenge[:], nil)
	if err != nil {
		t.Fatalf("Sign (conn 2): %v", err)
	}
	if !ecdsa.VerifyASN1(ecPub, challenge[:], sig) {
		t.Fatal("signature from conn 2 key does not verify with conn 1 pubkey")
	}
	t.Log("Sign+Verify across connections OK")

	// Verify HMAC consistency across connections
	loadH256.Write(testGUID[:])
	loadedHmac := loadH256.Sum(nil)
	if !bytes.Equal(loadedHmac, hmacBaseline) {
		t.Fatalf("HMAC mismatch across connections:\n  conn2: %x\n  conn1: %x", loadedHmac, hmacBaseline)
	}
	t.Log("HMAC matches across connections")

	t.Log("=== PASSED: Cross-connection persistence (DI on conn1 → Load on conn2) ===")
}

// TestTPMStore_ClearAndReprovision verifies that CleanupFDOState (the
// operation behind --tpm-clear) properly wipes all FDO state, and that
// a fresh DI can be performed afterward.
func TestTPMStore_ClearAndReprovision(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "cred.bin")

	t.Setenv("FDO_TPM_OWNER_HIERARCHY", "1")

	// =====================================================================
	// Phase 1: Initial DI + Save
	// =====================================================================
	store1, err := Open(credPath)
	if err != nil {
		t.Fatalf("Open (phase 1): %v", err)
	}

	_, _, _, err = store1.NewDI(protocol.Secp256r1KeyType)
	if err != nil {
		t.Fatalf("NewDI (phase 1): %v", err)
	}

	dc1 := fdo.DeviceCredential{
		Version:    101,
		DeviceInfo: "device-before-clear",
		GUID:       protocol.GUID{0x01, 0x02, 0x03},
		PublicKeyHash: protocol.Hash{
			Algorithm: protocol.Sha256Hash,
			Value:     make([]byte, 32),
		},
	}
	if err := store1.Save(dc1); err != nil {
		t.Fatalf("Save (phase 1): %v", err)
	}

	// Verify Load works
	if _, _, _, _, err := store1.Load(); err != nil {
		t.Fatalf("Load (phase 1): %v", err)
	}
	t.Log("Phase 1: DI + Save + Load OK")
	_ = store1.Close()

	// =====================================================================
	// Phase 2: Clear all FDO state (simulates --tpm-clear)
	// =====================================================================
	t.Log("Phase 2: Clearing FDO state...")
	tpmc, err := Open(credPath)
	if err != nil {
		t.Fatalf("Open for clear: %v", err)
	}
	// Access the underlying tpm transport to call CleanupFDOState
	ts := tpmc.(*tpmStore)
	tpm.CleanupFDOState(ts.tpmc)
	t.Log("CleanupFDOState completed")

	// Verify Load fails after clear
	_, _, _, _, err = tpmc.Load()
	if err == nil {
		t.Fatal("Load should fail after CleanupFDOState, but it succeeded")
	}
	t.Logf("Load after clear correctly failed: %v", err)
	_ = tpmc.Close()

	// =====================================================================
	// Phase 3: Reprovision (fresh DI after clear)
	// =====================================================================
	t.Log("Phase 3: Reprovisioning...")
	store3, err := Open(credPath)
	if err != nil {
		t.Fatalf("Open (phase 3): %v", err)
	}
	defer func() { _ = store3.Close() }()

	_, _, _, err = store3.NewDI(protocol.Secp256r1KeyType)
	if err != nil {
		t.Fatalf("NewDI (phase 3): %v", err)
	}

	dc3 := fdo.DeviceCredential{
		Version:    101,
		DeviceInfo: "device-after-clear",
		GUID:       protocol.GUID{0x0A, 0x0B, 0x0C},
		PublicKeyHash: protocol.Hash{
			Algorithm: protocol.Sha256Hash,
			Value:     make([]byte, 32),
		},
	}
	if err := store3.Save(dc3); err != nil {
		t.Fatalf("Save (phase 3): %v", err)
	}

	loadedDC, _, _, _, err := store3.Load()
	if err != nil {
		t.Fatalf("Load (phase 3): %v", err)
	}
	if loadedDC.DeviceInfo != dc3.DeviceInfo {
		t.Errorf("DeviceInfo: got %q, want %q", loadedDC.DeviceInfo, dc3.DeviceInfo)
	}
	if loadedDC.GUID != dc3.GUID {
		t.Errorf("GUID: got %x, want %x", loadedDC.GUID, dc3.GUID)
	}

	t.Log("=== PASSED: Clear + Reprovision (--tpm-clear → fresh DI) ===")
}
