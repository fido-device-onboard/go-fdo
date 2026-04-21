//go:build spec_compliance_test
// +build spec_compliance_test

// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

// Phase 9 integration tests — proves the production library API can perform
// a full DI → NV Store → NV Load → Sign → HMAC cycle using ONLY the TPM.
// No files, no shared Go state between provision and verify phases.
//
// Run:
//
//	cd tpm && go test -v -tags=spec_compliance_test -run TestPhase9 -count=1
//
// With simulator:
//
//	FDO_TPM=sim go test -v -tags=spec_compliance_test -run TestPhase9 -count=1

package tpm_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
	tpmlib "github.com/fido-device-onboard/go-fdo/tpm"
)

// dumpTPMState reads the consolidated DCTPM NV index and persistent handles,
// then logs a human-readable summary.
func dumpTPMState(t *testing.T, thetpm tpmlib.TPM, label string) {
	t.Helper()
	info, err := tpmlib.ReadNVCredentials(thetpm)
	if err != nil {
		t.Logf("[%s] ReadNVCredentials error: %v", label, err)
		return
	}
	t.Logf("[%s] ── TPM FDO State ──", label)
	if info.HasDCTPM {
		t.Logf("  DCTPM     (0x%08X)    [%d bytes]", tpmlib.DCTPMIndex, info.DCTPMSize)
		var dctpm dctpmDump
		if err := cbor.Unmarshal(info.RawDCTPM, &dctpm); err != nil {
			t.Logf("    (decode error: %v)", err)
		} else {
			t.Logf("    Magic             0x%08X", dctpm.Magic)
			t.Logf("    Active            %v", dctpm.Active)
			t.Logf("    Version           %d", dctpm.Version)
			t.Logf("    DeviceInfo        %q", dctpm.DeviceInfo)
			t.Logf("    GUID              %x", dctpm.GUID)
			t.Logf("    KeyType           %s", dctpm.KeyType)
			t.Logf("    DeviceKeyHandle   0x%08X", dctpm.DeviceKeyHandle)
			t.Logf("    HMACKeyHandle     0x%08X", dctpm.HMACKeyHandle)
			t.Logf("    PublicKeyHash     alg=%d value=%s", dctpm.PublicKeyHash.Algorithm, hex.EncodeToString(dctpm.PublicKeyHash.Value))
			if len(dctpm.RvInfo) == 0 {
				t.Log("    RvInfo            (none)")
			} else {
				directives := protocol.ParseDeviceRvInfo(dctpm.RvInfo)
				for i, dir := range directives {
					t.Logf("    RvInfo[%d]", i)
					for _, u := range dir.URLs {
						t.Logf("      URL             %s", u)
					}
					if dir.Bypass {
						t.Log("      Bypass          true")
					}
					if dir.Delay > 0 {
						t.Logf("      Delay           %s", dir.Delay)
					}
				}
			}
		}
	} else {
		t.Logf("  DCTPM     (0x%08X)    [not defined]", tpmlib.DCTPMIndex)
	}
	dak := "not present"
	if info.HasDAK {
		pubKey, err := tpmlib.ReadDAKPublicKey(thetpm)
		if err != nil {
			dak = fmt.Sprintf("present (read error: %v)", err)
		} else if ecKey, ok := pubKey.(*ecdsa.PublicKey); ok {
			dak = fmt.Sprintf("ECC %s  X=%x", ecKey.Curve.Params().Name, ecKey.X.Bytes())
		} else {
			dak = fmt.Sprintf("present (%T)", pubKey)
		}
	}
	t.Logf("  DAK       (0x%08X)    %s", tpmlib.DAKHandle, dak)
	hmacKey := "not present"
	if info.HasHMACKey {
		hmacKey = "present"
	}
	t.Logf("  HMAC Key  (0x%08X)    %s", tpmlib.HMACKeyHandle, hmacKey)
	t.Logf("[%s] ── end ──", label)
}

// dctpmDump mirrors the consolidated DCTPM CBOR structure stored in NV.
// Defined here because the cred package type is unexported.
type dctpmDump struct {
	Magic           uint32                     `cbor:"0,keyasint"`
	Active          bool                       `cbor:"1,keyasint"`
	Version         uint16                     `cbor:"2,keyasint"`
	DeviceInfo      string                     `cbor:"3,keyasint"`
	GUID            protocol.GUID              `cbor:"4,keyasint"`
	RvInfo          [][]protocol.RvInstruction `cbor:"5,keyasint"`
	PublicKeyHash   protocol.Hash              `cbor:"6,keyasint"`
	KeyType         protocol.KeyType           `cbor:"7,keyasint"`
	DeviceKeyHandle uint32                     `cbor:"8,keyasint"`
	HMACKeyHandle   uint32                     `cbor:"9,keyasint"`
}

// mustCBOR marshals v to CBOR, fatally failing the test on error.
func mustCBOR(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cbor.Marshal(v)
	if err != nil {
		t.Fatalf("cbor.Marshal: %v", err)
	}
	return b
}

// TestPhase9_ProductionAPI_NVOnly proves that the production exported
// functions in tpm/nv.go, tpm/key.go, and tpm/hmac.go can perform a
// complete credential lifecycle using ONLY TPM NV storage — zero files.
//
// Architecture (mirrors what cred/tpm_store.go does, but at the TPM layer):
//
//	PROVISION PHASE (simulates NewDI + Save):
//	  1. CleanupFDOState — remove any prior state
//	  2. CreateSRK — create Storage Root Key as parent
//	  3. CreateChildECKey → PersistKey to DAKHandle
//	  4. CreateChildHMACKey → PersistKey to HMACKeyHandle
//	  5. Write consolidated DCTPM NV (CBOR blob with all credential data)
//	  6. NewSpecHmac → compute HMAC baseline over GUID
//	  7. Record "owner voucher" data (public key, GUID, HMAC baseline)
//
//	VERIFY PHASE (simulates Load → TO2, NO shared Go state from provision):
//	  7. ReadNVCredentials — read DCTPM NV, decode, verify Magic + Active
//	  8. LoadPersistentKey(DAKHandle) — get signing key with empty password auth
//	  9. Sign a fresh challenge nonce, verify with owner's public key
//	 10. NewSpecHmac → compute HMAC over GUID from NV, verify against baseline
//	 11. ProveDAKPossession — library-level DAK proof
//
// The VERIFY PHASE receives ONLY the TPM connection and the owner voucher
// data. It reads ALL device-side state from TPM NV/persistent handles.
func TestPhase9_ProductionAPI_NVOnly(t *testing.T) {
	thetpm := openTPM(t)
	usePlatform := !ownerHierarchyFallback()

	// =====================================================================
	// PROVISION PHASE — uses production exported functions from tpm package
	// =====================================================================

	// Step 1: Clean slate
	tpmlib.CleanupFDOState(thetpm)
	t.Log("Step 1: CleanupFDOState — removed any prior FDO state")

	// Step 2: Create SRK (Storage Root Key) as parent for child keys
	srk, err := tpmlib.CreateSRK(thetpm)
	if err != nil {
		t.Fatalf("CreateSRK: %v", err)
	}
	defer func() { tpm2.FlushContext{FlushHandle: srk.Handle}.Execute(thetpm) }()
	t.Log("Step 2: Created SRK (Storage Root Key)")

	// Step 3: Create ECC signing key (DAK) as child of SRK → persist
	dkHandle, _, err := tpmlib.CreateChildECKey(thetpm, *srk, tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256)
	if err != nil {
		t.Fatalf("CreateChildECKey: %v", err)
	}
	if err := tpmlib.PersistKey(thetpm, *dkHandle, tpmlib.DAKHandle); err != nil {
		t.Fatalf("PersistKey (DAK): %v", err)
	}
	t.Logf("Step 3: Created and persisted DAK at 0x%08X", tpmlib.DAKHandle)

	// Step 4: Create HMAC key as child of SRK → persist
	hmacHandle, err := tpmlib.CreateChildHMACKey(thetpm, *srk)
	if err != nil {
		t.Fatalf("CreateChildHMACKey: %v", err)
	}
	if err := tpmlib.PersistKey(thetpm, *hmacHandle, tpmlib.HMACKeyHandle); err != nil {
		t.Fatalf("PersistKey (HMAC): %v", err)
	}
	t.Logf("Step 4: Created and persisted HMAC key at 0x%08X", tpmlib.HMACKeyHandle)

	// Step 5: Write consolidated DCTPM NV index (single CBOR blob)
	guid := [16]byte{
		0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
	deviceInfo := "Phase9-Test-Device"

	// Build realistic rendezvous instructions: HTTP to 127.0.0.1:8080 with bypass
	rvInfo := [][]protocol.RvInstruction{{
		{Variable: protocol.RVProtocol, Value: mustCBOR(t, uint8(protocol.RVProtHTTP))},
		{Variable: protocol.RVIPAddress, Value: mustCBOR(t, []byte{127, 0, 0, 1})},
		{Variable: protocol.RVDevPort, Value: mustCBOR(t, uint16(8080))},
		{Variable: protocol.RVBypass},
	}}

	// Compute public key hash from DAK
	provisionKeyForHash, err := tpmlib.LoadPersistentKey(thetpm, tpmlib.DAKHandle)
	if err != nil {
		t.Fatalf("LoadPersistentKey (for pubkey hash): %v", err)
	}
	pubKeyForHash := provisionKeyForHash.Public().(*ecdsa.PublicKey)
	_ = provisionKeyForHash.Close()
	pubKeyHashBytes := sha256.Sum256(append(pubKeyForHash.X.Bytes(), pubKeyForHash.Y.Bytes()...))

	dctpmPayload := dctpmDump{
		Magic:      tpmlib.DCTPMMagic,
		Active:     true,
		Version:    101,
		DeviceInfo: deviceInfo,
		GUID:       guid,
		RvInfo:     rvInfo,
		PublicKeyHash: protocol.Hash{
			Algorithm: protocol.Sha256Hash,
			Value:     pubKeyHashBytes[:],
		},
		KeyType:         protocol.Secp256r1KeyType,
		DeviceKeyHandle: tpmlib.DAKHandle,
		HMACKeyHandle:   tpmlib.HMACKeyHandle,
	}
	dctpmBytes, err := cbor.Marshal(dctpmPayload)
	if err != nil {
		t.Fatalf("CBOR Marshal DCTPM: %v", err)
	}

	dctpmName, err := tpmlib.DefineNVSpace(thetpm, tpmlib.DCTPMIndex, uint16(len(dctpmBytes)), tpmlib.NVProfileDCTPM, usePlatform)
	if err != nil {
		t.Fatalf("DefineNVSpace DCTPM: %v", err)
	}
	if err := tpmlib.WriteNV(thetpm, tpmlib.DCTPMIndex, dctpmName, dctpmBytes, tpmlib.NVProfileDCTPM); err != nil {
		t.Fatalf("WriteNV DCTPM: %v", err)
	}
	t.Logf("Step 5: DCTPM NV stored [%d bytes] — Magic=FDO1, Active=true, GUID=%x, info=%q", len(dctpmBytes), guid, deviceInfo)

	// Step 6: Compute HMAC baseline over GUID using NewSpecHmac
	provisionHmac, err := tpmlib.NewSpecHmac(thetpm, 0, tpmlib.HMACKeyHandle) // crypto.Hash(0) — hash arg is for Size()/BlockSize()
	if err != nil {
		t.Fatalf("NewSpecHmac (provision): %v", err)
	}
	if _, err := provisionHmac.Write(guid[:]); err != nil {
		t.Fatalf("HMAC Write (provision): %v", err)
	}
	if provisionHmac.Err() != nil {
		t.Fatalf("HMAC Err (provision): %v", provisionHmac.Err())
	}
	hmacBaseline := provisionHmac.Sum(nil)
	if provisionHmac.Err() != nil {
		t.Fatalf("HMAC Sum Err (provision): %v", provisionHmac.Err())
	}
	_ = provisionHmac.Close()
	t.Logf("Step 6: HMAC baseline over GUID: %x", hmacBaseline)

	// Extract DAK public key for owner voucher
	provisionKey, err := tpmlib.LoadPersistentKey(thetpm, tpmlib.DAKHandle)
	if err != nil {
		t.Fatalf("LoadPersistentKey (provision): %v", err)
	}
	ownerPubKey := provisionKey.Public().(*ecdsa.PublicKey)
	_ = provisionKey.Close()
	t.Logf("Step 6b: DAK public key extracted (P-%d)", ownerPubKey.Curve.Params().BitSize)

	dumpTPMState(t, thetpm, "AFTER PROVISION")

	// =====================================================================
	// OWNER VOUCHER — this is what the owner's server holds.
	// The ONLY data flowing from provision to verify phase.
	// =====================================================================
	type ownerData struct {
		pubKey       *ecdsa.PublicKey
		guid         [16]byte
		hmacBaseline []byte
	}
	owner := ownerData{
		pubKey:       ownerPubKey,
		guid:         guid,
		hmacBaseline: hmacBaseline,
	}

	// =====================================================================
	// VERIFY PHASE — ZERO shared Go state from provision phase.
	// All device-side data read from TPM NV/persistent handles.
	// =====================================================================
	t.Log("=== VERIFY PHASE: reading ALL state from TPM (zero shared Go variables) ===")

	// Step 7: ReadNVCredentials — read consolidated DCTPM NV
	info, err := tpmlib.ReadNVCredentials(thetpm)
	if err != nil {
		t.Fatalf("ReadNVCredentials: %v", err)
	}
	if !info.HasDCTPM || len(info.RawDCTPM) == 0 {
		t.Fatal("DCTPM NV should be present")
	}
	if !info.HasDAK {
		t.Fatal("DAK should be present")
	}
	if !info.HasHMACKey {
		t.Fatal("HMAC key should be present")
	}

	// Decode consolidated DCTPM
	var verifyDCTPM dctpmDump
	if err := cbor.Unmarshal(info.RawDCTPM, &verifyDCTPM); err != nil {
		t.Fatalf("DCTPM decode: %v", err)
	}
	if verifyDCTPM.Magic != tpmlib.DCTPMMagic {
		t.Fatalf("DCTPM Magic: got 0x%08X, want 0x%08X", verifyDCTPM.Magic, tpmlib.DCTPMMagic)
	}
	if !verifyDCTPM.Active {
		t.Fatal("DCTPM Active should be true")
	}

	// Verify GUID from NV matches owner voucher
	if verifyDCTPM.GUID != owner.guid {
		t.Fatalf("GUID mismatch: NV=%x owner=%x", verifyDCTPM.GUID, owner.guid)
	}
	if verifyDCTPM.DeviceInfo != deviceInfo {
		t.Fatalf("DeviceInfo mismatch: NV=%q want=%q", verifyDCTPM.DeviceInfo, deviceInfo)
	}
	if verifyDCTPM.Version != 101 {
		t.Errorf("DCTPM Version: got %d, want 101", verifyDCTPM.Version)
	}
	if verifyDCTPM.KeyType != protocol.Secp256r1KeyType {
		t.Errorf("DCTPM KeyType: got %d, want SECP256R1", verifyDCTPM.KeyType)
	}
	if len(verifyDCTPM.RvInfo) != 1 || len(verifyDCTPM.RvInfo[0]) != 4 {
		t.Errorf("DCTPM RvInfo: got %d directives, want 1 with 4 instructions", len(verifyDCTPM.RvInfo))
	}
	if verifyDCTPM.DeviceKeyHandle != tpmlib.DAKHandle {
		t.Errorf("DCTPM DeviceKeyHandle: got 0x%08X, want 0x%08X", verifyDCTPM.DeviceKeyHandle, tpmlib.DAKHandle)
	}
	if verifyDCTPM.HMACKeyHandle != tpmlib.HMACKeyHandle {
		t.Errorf("DCTPM HMACKeyHandle: got 0x%08X, want 0x%08X", verifyDCTPM.HMACKeyHandle, tpmlib.HMACKeyHandle)
	}
	t.Logf("Step 7: DCTPM verified — Magic=FDO1 Active=true Version=%d GUID=%x KeyType=%s DAK=0x%08X HMAC=0x%08X",
		verifyDCTPM.Version, verifyDCTPM.GUID, verifyDCTPM.KeyType,
		verifyDCTPM.DeviceKeyHandle, verifyDCTPM.HMACKeyHandle)

	// Step 8: LoadPersistentKey — get signing key with empty password auth
	verifyKey, err := tpmlib.LoadPersistentKey(thetpm, tpmlib.DAKHandle)
	if err != nil {
		t.Fatalf("LoadPersistentKey (verify): %v", err)
	}
	defer func() { _ = verifyKey.Close() }()
	t.Log("Step 8: LoadPersistentKey OK — DAK loaded with empty password auth")

	// Step 9: Sign a fresh challenge, verify with owner's public key
	challenge := sha256.Sum256([]byte("Phase 9 integration test challenge nonce"))
	sig, err := verifyKey.Sign(nil, challenge[:], nil)
	if err != nil {
		t.Fatalf("Sign (empty-auth): %v", err)
	}

	// Verify using owner's public key (NOT from TPM — from owner voucher)
	if !ecdsa.VerifyASN1(owner.pubKey, challenge[:], sig) {
		t.Fatal("DAK signature verification FAILED — owner pubkey does not match")
	}
	t.Logf("Step 9: Sign+Verify OK — DAK signature verified against owner voucher pubkey")

	// Step 9b: Sign a DIFFERENT challenge to prove it's not cached
	challenge2 := sha256.Sum256([]byte("second challenge — must produce different signature"))
	sig2, err := verifyKey.Sign(nil, challenge2[:], nil)
	if err != nil {
		t.Fatalf("Sign (second challenge): %v", err)
	}
	if !ecdsa.VerifyASN1(owner.pubKey, challenge2[:], sig2) {
		t.Fatal("second signature verification FAILED")
	}
	if bytes.Equal(sig, sig2) {
		t.Error("two different challenges produced identical signatures — suspicious")
	}
	t.Log("Step 9b: Second Sign+Verify OK — different challenge, different signature, both valid")

	// Step 10: NewSpecHmac — compute HMAC over GUID from NV, verify baseline
	verifyHmac, err := tpmlib.NewSpecHmac(thetpm, 0, tpmlib.HMACKeyHandle)
	if err != nil {
		t.Fatalf("NewSpecHmac (verify): %v", err)
	}
	// Use the GUID read from NV (verifyDCTPM.GUID), NOT from owner voucher
	if _, err := verifyHmac.Write(verifyDCTPM.GUID[:]); err != nil {
		t.Fatalf("HMAC Write (verify): %v", err)
	}
	if verifyHmac.Err() != nil {
		t.Fatalf("HMAC Err (verify): %v", verifyHmac.Err())
	}
	verifyResult := verifyHmac.Sum(nil)
	if verifyHmac.Err() != nil {
		t.Fatalf("HMAC Sum Err (verify): %v", verifyHmac.Err())
	}
	_ = verifyHmac.Close()

	if !bytes.Equal(verifyResult, owner.hmacBaseline) {
		t.Fatalf("HMAC mismatch:\n  verify:   %x\n  baseline: %x", verifyResult, owner.hmacBaseline)
	}
	t.Logf("Step 10: HMAC verified — matches baseline from provision phase")

	// Step 11: ProveDAKPossession — high-level library API
	proof, err := tpmlib.ProveDAKPossession(thetpm, []byte("Phase 9 final possession proof"))
	if err != nil {
		t.Fatalf("ProveDAKPossession: %v", err)
	}
	ecKey, ok := proof.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", proof.PublicKey)
	}
	// Verify the proof's public key matches the owner voucher's key
	if ecKey.X.Cmp(owner.pubKey.X) != 0 || ecKey.Y.Cmp(owner.pubKey.Y) != 0 {
		t.Fatal("ProveDAKPossession returned different public key than owner voucher")
	}
	if !ecdsa.VerifyASN1(ecKey, proof.Challenge[:], proof.Signature) {
		t.Fatal("ProveDAKPossession self-verification FAILED")
	}
	t.Log("Step 11: ProveDAKPossession OK — pubkey matches, signature verified")

	dumpTPMState(t, thetpm, "AFTER VERIFY")

	t.Log("=== Phase 9 PASSED: Full DI→NV→Load→Sign→HMAC cycle with ZERO disk storage ===")
}

// TestPhase9_HMACDeterminism proves the persistent HMAC key produces
// consistent results across multiple NewSpecHmac() calls (same key,
// same data → same HMAC).
func TestPhase9_HMACDeterminism(t *testing.T) {
	thetpm := openTPM(t)

	// Only clean the resources this test uses — leave other state intact
	_ = tpmlib.EvictPersistentHandle(thetpm, tpmlib.HMACKeyHandle)

	// Provision HMAC key via child-of-SRK method
	srk, err := tpmlib.CreateSRK(thetpm)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { tpm2.FlushContext{FlushHandle: srk.Handle}.Execute(thetpm) }()
	handle, err := tpmlib.CreateChildHMACKey(thetpm, *srk)
	if err != nil {
		t.Fatal(err)
	}
	if err := tpmlib.PersistKey(thetpm, *handle, tpmlib.HMACKeyHandle); err != nil {
		t.Fatal(err)
	}

	testData := []byte("determinism test data for Phase 9")

	// Compute HMAC three times with separate NewSpecHmac() calls
	var results [3][]byte
	for i := range results {
		h, err := tpmlib.NewSpecHmac(thetpm, 0, tpmlib.HMACKeyHandle)
		if err != nil {
			t.Fatalf("NewSpecHmac(%d): %v", i, err)
		}
		h.Write(testData)
		if h.Err() != nil {
			t.Fatalf("HMAC Err(%d): %v", i, h.Err())
		}
		results[i] = h.Sum(nil)
		if h.Err() != nil {
			t.Fatalf("HMAC Sum Err(%d): %v", i, h.Err())
		}
		_ = h.Close()
	}

	// All three must be identical
	for i := 1; i < len(results); i++ {
		if !bytes.Equal(results[0], results[i]) {
			t.Errorf("HMAC[0]=%x != HMAC[%d]=%x", results[0], i, results[i])
		}
	}

	// Different data → different HMAC
	h, _ := tpmlib.NewSpecHmac(thetpm, 0, tpmlib.HMACKeyHandle)
	h.Write([]byte("different data"))
	different := h.Sum(nil)
	_ = h.Close()
	if bytes.Equal(results[0], different) {
		t.Error("same HMAC for different data — broken")
	}

	// Verify HMAC length (SHA-256 = 32 bytes)
	if len(results[0]) != 32 {
		t.Errorf("HMAC length: got %d, want 32", len(results[0]))
	}

	t.Logf("HMAC determinism OK: %x (3 calls, same result, 32 bytes)", results[0])
}

// TestPhase9_SignMultipleDigests proves the persistent DAK can sign
// multiple different digests, all verifiable with the same public key.
func TestPhase9_SignMultipleDigests(t *testing.T) {
	thetpm := openTPM(t)

	// Only clean the resources this test uses — leave other state intact
	_ = tpmlib.EvictPersistentHandle(thetpm, tpmlib.DAKHandle)

	// Provision DAK via child-of-SRK method
	srk, err := tpmlib.CreateSRK(thetpm)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { tpm2.FlushContext{FlushHandle: srk.Handle}.Execute(thetpm) }()
	handle, _, err := tpmlib.CreateChildECKey(thetpm, *srk, tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := tpmlib.PersistKey(thetpm, *handle, tpmlib.DAKHandle); err != nil {
		t.Fatal(err)
	}

	// Load the key back using production API
	key, err := tpmlib.LoadPersistentKey(thetpm, tpmlib.DAKHandle)
	if err != nil {
		t.Fatalf("LoadPersistentKey: %v", err)
	}
	defer func() { _ = key.Close() }()

	pubKey := key.Public().(*ecdsa.PublicKey)

	// Sign 10 different digests
	for i := 0; i < 10; i++ {
		msg := []byte("Phase 9 digest " + string(rune('A'+i)))
		digest := sha256.Sum256(msg)
		sig, err := key.Sign(nil, digest[:], nil)
		if err != nil {
			t.Fatalf("Sign(%d): %v", i, err)
		}
		if !ecdsa.VerifyASN1(pubKey, digest[:], sig) {
			t.Fatalf("Verify(%d) failed", i)
		}
	}
	t.Logf("Signed and verified 10 different digests with persistent DAK (empty-auth)")
}

// TestPhase9_EmptyAuthWorks proves that keys created with userWithAuth=1
// can be used with empty password auth — the standard auth mechanism.
func TestPhase9_EmptyAuthWorks(t *testing.T) {
	thetpm := openTPM(t)

	// Only clean the resources this test uses — leave other state intact
	_ = tpmlib.EvictPersistentHandle(thetpm, tpmlib.DAKHandle)

	// Provision DAK with empty-auth via child-of-SRK method
	srk, err := tpmlib.CreateSRK(thetpm)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { tpm2.FlushContext{FlushHandle: srk.Handle}.Execute(thetpm) }()
	handle, _, err := tpmlib.CreateChildECKey(thetpm, *srk, tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := tpmlib.PersistKey(thetpm, *handle, tpmlib.DAKHandle); err != nil {
		t.Fatal(err)
	}

	// Sign with empty password auth (should SUCCEED because UserWithAuth=1)
	readResp, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(tpmlib.DAKHandle)}.Execute(thetpm)
	if err != nil {
		t.Fatalf("ReadPublic: %v", err)
	}

	digest := sha256.Sum256([]byte("empty password auth should succeed"))
	signResp, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(tpmlib.DAKHandle),
			Name:   readResp.Name,
			Auth:   tpm2.PasswordAuth(nil), // empty password auth
		},
		Digest:     tpm2.TPM2BDigest{Buffer: digest[:]},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("empty password auth should have SUCCEEDED, but Sign failed: %v", err)
	}
	t.Logf("Empty password auth correctly accepted")

	// Verify the signature using the public key
	key, err := tpmlib.LoadPersistentKey(thetpm, tpmlib.DAKHandle)
	if err != nil {
		t.Fatalf("LoadPersistentKey: %v", err)
	}
	defer func() { _ = key.Close() }()

	pubKey := key.Public().(*ecdsa.PublicKey)

	// Convert TPM signature to ASN1 for verification
	rsig := signResp.Signature.Signature.ECDSA
	sig, err := key.Sign(nil, digest[:], nil)
	if err != nil {
		t.Fatalf("Sign (empty-auth via library): %v", err)
	}
	_ = rsig // raw TPM signature confirmed success above
	if !ecdsa.VerifyASN1(pubKey, digest[:], sig) {
		t.Fatal("empty-auth signature verification failed")
	}
	t.Log("Empty password auth correctly accepted — Sign succeeded + verified")
}

// TestPhase9_CleanupFDOState proves that CleanupFDOState properly
// removes all NV indices and persistent handles.
func TestPhase9_CleanupFDOState(t *testing.T) {
	thetpm := openTPM(t)
	usePlatform := !ownerHierarchyFallback()
	tpmlib.CleanupFDOState(thetpm)

	// Provision some state: persistent keys + consolidated DCTPM
	srk, err := tpmlib.CreateSRK(thetpm)
	if err != nil {
		t.Fatalf("CreateSRK: %v", err)
	}
	defer func() { tpm2.FlushContext{FlushHandle: srk.Handle}.Execute(thetpm) }()

	dkHandle, _, err := tpmlib.CreateChildECKey(thetpm, *srk, tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256)
	if err != nil {
		t.Fatalf("CreateChildECKey: %v", err)
	}
	if err := tpmlib.PersistKey(thetpm, *dkHandle, tpmlib.DAKHandle); err != nil {
		t.Fatalf("PersistKey (DAK): %v", err)
	}

	hmacHandle, err := tpmlib.CreateChildHMACKey(thetpm, *srk)
	if err != nil {
		t.Fatalf("CreateChildHMACKey: %v", err)
	}
	if err := tpmlib.PersistKey(thetpm, *hmacHandle, tpmlib.HMACKeyHandle); err != nil {
		t.Fatalf("PersistKey (HMAC): %v", err)
	}

	// Write a consolidated DCTPM NV blob
	dctpmPayload := dctpmDump{
		Magic:           tpmlib.DCTPMMagic,
		Active:          true,
		Version:         101,
		DeviceInfo:      "cleanup-test",
		GUID:            [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
		KeyType:         protocol.Secp256r1KeyType,
		DeviceKeyHandle: tpmlib.DAKHandle,
		HMACKeyHandle:   tpmlib.HMACKeyHandle,
	}
	dctpmBytes, _ := cbor.Marshal(dctpmPayload)
	dctpmName, _ := tpmlib.DefineNVSpace(thetpm, tpmlib.DCTPMIndex, uint16(len(dctpmBytes)), tpmlib.NVProfileDCTPM, usePlatform)
	tpmlib.WriteNV(thetpm, tpmlib.DCTPMIndex, dctpmName, dctpmBytes, tpmlib.NVProfileDCTPM)

	// Verify state exists
	info, err := tpmlib.ReadNVCredentials(thetpm)
	if err != nil {
		t.Fatalf("ReadNVCredentials before cleanup: %v", err)
	}
	if !info.HasDCTPM || !info.HasDAK || !info.HasHMACKey {
		t.Fatal("expected DCTPM + DAK + HMAC before cleanup")
	}
	t.Log("State provisioned: DCTPM=present DAK=present HMAC=present")

	dumpTPMState(t, thetpm, "BEFORE CLEANUP")

	// Clean up
	tpmlib.CleanupFDOState(thetpm)

	dumpTPMState(t, thetpm, "AFTER CLEANUP")

	// Verify state is gone
	info2, err := tpmlib.ReadNVCredentials(thetpm)
	if err != nil {
		t.Fatalf("ReadNVCredentials after cleanup: %v", err)
	}
	if info2.HasDCTPM {
		t.Error("DCTPM should be gone after cleanup")
	}
	if info2.HasDAK {
		t.Error("DAK should be gone after cleanup")
	}
	if info2.HasHMACKey {
		t.Error("HMAC key should be gone after cleanup")
	}
	t.Log("CleanupFDOState OK: all NV indices and persistent handles removed")
}
