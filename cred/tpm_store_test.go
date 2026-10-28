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
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"hash"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
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

// TestTPMStore_SaveInPlace checks the TO2 credential update path against the
// FDO TPM spec: DCTPM is defined once (512 bytes) and later saves write it in
// place with a single NV_Write; a save that fails leaves the previous
// credentials loadable; a DCTPM with the wrong magic is not loaded.
func TestTPMStore_SaveInPlace(t *testing.T) {
	t.Setenv("FDO_TPM_OWNER_HIERARCHY", "1")
	store, err := Open(filepath.Join(t.TempDir(), "cred.bin"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = store.Close() }()
	ts := store.(*tpmStore)

	if _, _, _, err := store.NewDI(protocol.Secp256r1KeyType); err != nil {
		t.Fatalf("NewDI: %v", err)
	}
	dctpmSize := func() uint16 {
		t.Helper()
		info, err := tpm.ReadNVCredentials(ts.tpmc)
		if err != nil {
			t.Fatal(err)
		}
		return info.DCTPMSize
	}
	cred := func(guid byte, rv int) fdo.DeviceCredential {
		dc := fdo.DeviceCredential{
			Version: 200, DeviceInfo: "in-place", GUID: protocol.GUID{guid},
			PublicKeyHash: protocol.Hash{Algorithm: protocol.Sha256Hash, Value: make([]byte, 32)},
		}
		for range rv {
			dc.RvInfo = append(dc.RvInfo, []protocol.RvInstruction{{Variable: protocol.RVDns, Value: []byte{0x6d, 'r', 'v', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'}}})
		}
		return dc
	}
	loadGUID := func() protocol.GUID {
		t.Helper()
		dc, _, _, _, err := store.Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		return dc.GUID
	}

	if err := store.Save(cred(1, 0)); err != nil {
		t.Fatalf("Save(DI): %v", err)
	}
	if got := dctpmSize(); got != tpm.DCTPMDefaultSize {
		t.Fatalf("DCTPM size after DI = %d, want %d", got, tpm.DCTPMDefaultSize)
	}

	// TO2 update with a longer RVInfo: same index, new contents.
	if err := store.Save(cred(2, 3)); err != nil {
		t.Fatalf("Save(TO2): %v", err)
	}
	if got := dctpmSize(); got != tpm.DCTPMDefaultSize {
		t.Fatalf("DCTPM size after TO2 = %d, want %d (index must not be redefined)", got, tpm.DCTPMDefaultSize)
	}
	if g := loadGUID(); g != (protocol.GUID{2}) {
		t.Fatalf("after TO2 update loaded GUID %x", g)
	}

	// A failed update (here: DCTPM write-locked) leaves the old credentials.
	rp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(tpm.DCTPMIndex)}.Execute(ts.tpmc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (tpm2.NVWriteLock{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(tpm.DCTPMIndex), Name: rp.NVName, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(tpm.DCTPMIndex), Name: rp.NVName},
	}).Execute(ts.tpmc); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(cred(3, 1)); err == nil {
		t.Fatal("Save succeeded on a write-locked DCTPM")
	}
	if g := loadGUID(); g != (protocol.GUID{2}) {
		t.Fatalf("failed update changed the credentials: loaded GUID %x", g)
	}

	// Wrong magic: readers SHALL treat it as no credentials.
	// (Undefining also clears the write lock; the keys stay.)
	if err := tpm.UndefineNVSpace(ts.tpmc, tpm.DCTPMIndex); err != nil {
		t.Fatal(err)
	}
	bad, err := cbor.Marshal(dctpmNVData{Magic: 0x12345678, Active: true, DeviceKeyHandle: tpm.DAKHandle, HMACKeyHandle: tpm.HMACKeyHandle})
	if err != nil {
		t.Fatal(err)
	}
	if err := tpm.WriteDCTPM(ts.tpmc, bad, false); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := store.Load(); err == nil {
		t.Fatal("Load accepted a DCTPM with the wrong magic")
	}
}

// TestTPMStore_MinFirmwareRev checks DCTPM.DCMinFirmwareRev (TPM spec): all
// eleven items are written; the value is seeded at DI from RVMinFirmwareRev,
// preserved when TO2 replaces RvInfo, never decreased, and a ten-item DCTPM
// written by older code loads (as 0).
func TestTPMStore_MinFirmwareRev(t *testing.T) {
	t.Setenv("FDO_TPM_OWNER_HIERARCHY", "1")
	store, err := Open(filepath.Join(t.TempDir(), "cred.bin"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = store.Close() }()
	ts := store.(*tpmStore)
	if _, _, _, err := store.NewDI(protocol.Secp256r1KeyType); err != nil {
		t.Fatalf("NewDI: %v", err)
	}

	rv := func(minRev uint64) [][]protocol.RvInstruction {
		dns, _ := cbor.Marshal("rv.example.com")
		dir := []protocol.RvInstruction{{Variable: protocol.RVDns, Value: dns}}
		if minRev > 0 {
			v, _ := cbor.Marshal(minRev)
			dir = append(dir, protocol.RvInstruction{Variable: protocol.RVMinFirmwareRev, Value: v})
		}
		return [][]protocol.RvInstruction{dir}
	}
	cred := func(guid byte, minRev uint64) fdo.DeviceCredential {
		return fdo.DeviceCredential{Version: 200, DeviceInfo: "minrev", GUID: protocol.GUID{guid}, RvInfo: rv(minRev),
			PublicKeyHash: protocol.Hash{Algorithm: protocol.Sha256Hash, Value: make([]byte, 32)}}
	}
	stored := func() (items int, minRev uint64) {
		t.Helper()
		info, err := tpm.ReadNVCredentials(ts.tpmc)
		if err != nil {
			t.Fatal(err)
		}
		var raw []cbor.RawBytes
		if err := tpm.DecodeDCTPM(info.RawDCTPM, &raw); err != nil {
			t.Fatal(err)
		}
		var d dctpmNVRead
		if err := tpm.DecodeDCTPM(info.RawDCTPM, &d); err != nil {
			t.Fatal(err)
		}
		return len(raw), d.MinFirmwareRev
	}

	if err := store.Save(cred(1, 7)); err != nil {
		t.Fatal(err)
	}
	if n, v := stored(); n != 11 || v != 7 {
		t.Fatalf("after DI: %d items, DCMinFirmwareRev %d; want 11, 7 (seeded from RVMinFirmwareRev)", n, v)
	}

	// TO2 replaces RvInfo (no tag 18): the stored minimum is preserved.
	if err := store.Save(cred(2, 0)); err != nil {
		t.Fatal(err)
	}
	if _, v := stored(); v != 7 {
		t.Fatalf("after TO2 without tag 18: DCMinFirmwareRev %d, want 7 (preserved)", v)
	}

	// Device ratchets to 9; a later save with a lower tag 18 must not lower it.
	info, _ := tpm.ReadNVCredentials(ts.tpmc)
	var d dctpmNVRead
	if err := tpm.DecodeDCTPM(info.RawDCTPM, &d); err != nil {
		t.Fatal(err)
	}
	d.MinFirmwareRev = 9
	raised, _ := cbor.Marshal(dctpmNVData(d))
	if err := tpm.WriteDCTPM(ts.tpmc, raised, false); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(cred(3, 3)); err != nil {
		t.Fatal(err)
	}
	if _, v := stored(); v != 9 {
		t.Fatalf("after ratchet to 9 and save with tag 18 = 3: DCMinFirmwareRev %d, want 9", v)
	}

	// Ten-item DCTPM from older code: loads, and reads as 0.
	type tenItems struct {
		Magic           uint32                     `cbor:"0,keyasint"`
		Active          bool                       `cbor:"1,keyasint"`
		Version         uint16                     `cbor:"2,keyasint"`
		DeviceInfo      string                     `cbor:"3,keyasint"`
		GUID            protocol.GUID              `cbor:"4,keyasint"`
		RvInfo          [][]protocol.RvInstruction `cbor:"5,keyasint"`
		PublicKeyHash   protocol.Hash              `cbor:"6,keyasint"`
		DeviceKeyType   uint8                      `cbor:"7,keyasint"`
		DeviceKeyHandle uint32                     `cbor:"8,keyasint"`
		HMACKeyHandle   uint32                     `cbor:"9,keyasint"`
	}
	old, _ := cbor.Marshal(tenItems{Magic: tpm.DCTPMMagic, Active: true, Version: 200, GUID: protocol.GUID{4},
		PublicKeyHash:   protocol.Hash{Algorithm: protocol.Sha256Hash, Value: make([]byte, 32)},
		DeviceKeyHandle: tpm.DAKHandle, HMACKeyHandle: tpm.HMACKeyHandle})
	if err := tpm.WriteDCTPM(ts.tpmc, old, false); err != nil {
		t.Fatal(err)
	}
	if n, v := stored(); n != 10 || v != 0 {
		t.Fatalf("ten-item DCTPM: %d items, DCMinFirmwareRev %d", n, v)
	}
	if dc, _, _, _, err := store.Load(); err != nil || dc.GUID != (protocol.GUID{4}) {
		t.Fatalf("Load of ten-item DCTPM: %v", err)
	}
}

// TestTPMStore_P384PersistedHMAC: a P-384 device gets a persisted HMAC key
// fixed to SHA-384 (TPM spec Table 10). Its HMAC-SHA384 is the same after
// Load and is computed by the persisted key at HMACKeyHandle (not the old
// template-re-derived key), and HMAC-SHA256 is refused.
func TestTPMStore_P384PersistedHMAC(t *testing.T) {
	t.Setenv("FDO_TPM_OWNER_HIERARCHY", "1")
	store, err := Open(filepath.Join(t.TempDir(), "cred.bin"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = store.Close() }()
	ts := store.(*tpmStore)
	h256, h384, _, err := store.NewDI(protocol.Secp384r1KeyType)
	if err != nil {
		t.Fatalf("NewDI: %v", err)
	}
	msg := []byte("voucher header")
	mac := func(h hash.Hash) ([]byte, error) {
		h.Reset()
		_, _ = h.Write(msg)
		s := h.Sum(nil)
		if f, ok := h.(interface{ Err() error }); ok && f.Err() != nil {
			return nil, f.Err()
		}
		return s, nil
	}
	atDI, err := mac(h384)
	if err != nil || len(atDI) != 48 {
		t.Fatalf("HMAC-SHA384 at DI: len %d, %v", len(atDI), err)
	}
	if _, err := mac(h256); err == nil {
		t.Error("HMAC-SHA256 succeeded on a P-384 device's SHA-384 HMAC key; expected the TPM to refuse")
	}

	dc := fdo.DeviceCredential{Version: 200, DeviceInfo: "p384", GUID: protocol.GUID{3},
		PublicKeyHash: protocol.Hash{Algorithm: protocol.Sha384Hash, Value: make([]byte, 48)}}
	if err := store.Save(dc); err != nil {
		t.Fatalf("Save: %v", err)
	}
	_, _, h384b, _, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	afterLoad, err := mac(h384b)
	if err != nil || !bytes.Equal(afterLoad, atDI) {
		t.Fatalf("HMAC-SHA384 after Load = %x (%v), want %x", afterLoad, err, atDI)
	}

	persisted, err := tpm.NewSpecHmac(ts.tpmc, crypto.SHA384, tpm.HMACKeyHandle)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = persisted.Close() }()
	if want, err := mac(persisted); err != nil || !bytes.Equal(want, atDI) {
		t.Errorf("store HMAC-SHA384 %x is not the persisted key's %x (%v)", atDI, want, err)
	}
}
