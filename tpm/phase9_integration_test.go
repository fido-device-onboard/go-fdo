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
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/google/go-tpm/tpm2"

	tpmlib "github.com/fido-device-onboard/go-fdo/tpm"
)

// TestPhase9_ProductionAPI_NVOnly proves that the production exported
// functions in tpm/nv.go, tpm/key.go, and tpm/hmac.go can perform a
// complete credential lifecycle using ONLY TPM NV storage — zero files.
//
// Architecture (mirrors what cred/tpm_store.go does, but at the TPM layer):
//
//	PROVISION PHASE (simulates NewDI + Save):
//	  1. CleanupFDOState — remove any prior state
//	  2. Generate random Unique Strings
//	  3. DefineNVSpace + WriteNV for DeviceKey_US, HMAC_US, DCActive, DCTPM
//	  4. ComputeFDOAuthPolicy for each US NV
//	  5. GenerateSpecECKey → PersistKey to DAKHandle
//	  6. GenerateSpecHMACKey → PersistKey to HMACKeyHandle
//	  7. NewSpecHmac → compute HMAC baseline over GUID
//	  8. Record "owner voucher" data (public key, GUID, HMAC baseline)
//
//	VERIFY PHASE (simulates Load → TO2, NO shared Go state from provision):
//	  9. ReadNVCredentials — read all NV indices, verify Active=true
//	 10. LoadPersistentKey(DAKHandle) — get signing key with policy auth
//	 11. Sign a fresh challenge nonce, verify with owner's public key
//	 12. NewSpecHmac → compute HMAC over GUID from NV, verify against baseline
//	 13. ProveDAKPossession — library-level DAK proof
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

	// Step 2: Generate random Unique Strings (production uses crypto/rand)
	deviceKeyUS := make([]byte, 64)
	if _, err := rand.Read(deviceKeyUS); err != nil {
		t.Fatalf("generate device key US: %v", err)
	}
	hmacUS := make([]byte, 32)
	if _, err := rand.Read(hmacUS); err != nil {
		t.Fatalf("generate HMAC US: %v", err)
	}
	t.Log("Step 2: Generated random Unique Strings (64 bytes device key, 32 bytes HMAC)")

	// Step 3: Define and write Unique String NV indices
	dkUSName, err := tpmlib.DefineNVSpace(thetpm, tpmlib.DeviceKeyUSIndex, 64, tpmlib.NVProfileB, usePlatform)
	if err != nil {
		t.Fatalf("DefineNVSpace DeviceKey_US: %v", err)
	}
	if err := tpmlib.WriteNV(thetpm, tpmlib.DeviceKeyUSIndex, dkUSName, deviceKeyUS, tpmlib.NVProfileB); err != nil {
		t.Fatalf("WriteNV DeviceKey_US: %v", err)
	}

	hmacUSName, err := tpmlib.DefineNVSpace(thetpm, tpmlib.HMACUSIndex, 32, tpmlib.NVProfileB, usePlatform)
	if err != nil {
		t.Fatalf("DefineNVSpace HMAC_US: %v", err)
	}
	if err := tpmlib.WriteNV(thetpm, tpmlib.HMACUSIndex, hmacUSName, hmacUS, tpmlib.NVProfileB); err != nil {
		t.Fatalf("WriteNV HMAC_US: %v", err)
	}
	t.Log("Step 3: Defined and wrote DeviceKey_US + HMAC_US NV indices")

	// Step 4: Compute auth policies
	dkPolicy, err := tpmlib.ComputeFDOAuthPolicy(thetpm, tpmlib.DeviceKeyUSIndex, dkUSName)
	if err != nil {
		t.Fatalf("ComputeFDOAuthPolicy (device key): %v", err)
	}
	hmacPolicy, err := tpmlib.ComputeFDOAuthPolicy(thetpm, tpmlib.HMACUSIndex, hmacUSName)
	if err != nil {
		t.Fatalf("ComputeFDOAuthPolicy (HMAC): %v", err)
	}
	t.Log("Step 4: Computed auth policies (PolicyNV + PolicySecret) for both keys")

	// Step 5: Create ECC signing key (DAK) → persist
	dkHandle, _, err := tpmlib.GenerateSpecECKey(thetpm, tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256, deviceKeyUS, dkPolicy)
	if err != nil {
		t.Fatalf("GenerateSpecECKey: %v", err)
	}
	if err := tpmlib.PersistKey(thetpm, *dkHandle, tpmlib.DAKHandle); err != nil {
		t.Fatalf("PersistKey (DAK): %v", err)
	}
	t.Logf("Step 5: Created and persisted DAK at 0x%08X", tpmlib.DAKHandle)

	// Step 6: Create HMAC key → persist
	hmacHandle, err := tpmlib.GenerateSpecHMACKey(thetpm, hmacUS, hmacPolicy)
	if err != nil {
		t.Fatalf("GenerateSpecHMACKey: %v", err)
	}
	if err := tpmlib.PersistKey(thetpm, *hmacHandle, tpmlib.HMACKeyHandle); err != nil {
		t.Fatalf("PersistKey (HMAC): %v", err)
	}
	t.Logf("Step 6: Created and persisted HMAC key at 0x%08X", tpmlib.HMACKeyHandle)

	// Step 7: Write DCActive + DCTPM NV indices
	guid := [16]byte{
		0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
	deviceInfo := "Phase9-Test-Device"
	dctpmData := make([]byte, 0, 16+len(deviceInfo))
	dctpmData = append(dctpmData, guid[:]...)
	dctpmData = append(dctpmData, []byte(deviceInfo)...)

	dcActiveName, err := tpmlib.DefineNVSpace(thetpm, tpmlib.DCActiveIndex, 1, tpmlib.NVProfileA, usePlatform)
	if err != nil {
		t.Fatalf("DefineNVSpace DCActive: %v", err)
	}
	if err := tpmlib.WriteNV(thetpm, tpmlib.DCActiveIndex, dcActiveName, []byte{0x01}, tpmlib.NVProfileA); err != nil {
		t.Fatalf("WriteNV DCActive: %v", err)
	}

	dctpmName, err := tpmlib.DefineNVSpace(thetpm, tpmlib.DCTPMIndex, uint16(len(dctpmData)), tpmlib.NVProfileB, usePlatform)
	if err != nil {
		t.Fatalf("DefineNVSpace DCTPM: %v", err)
	}
	if err := tpmlib.WriteNV(thetpm, tpmlib.DCTPMIndex, dctpmName, dctpmData, tpmlib.NVProfileB); err != nil {
		t.Fatalf("WriteNV DCTPM: %v", err)
	}
	t.Logf("Step 7: DCActive=0x01, DCTPM stored GUID=%x info=%q", guid, deviceInfo)

	// Step 8: Compute HMAC baseline over GUID using NewSpecHmac
	provisionHmac, err := tpmlib.NewSpecHmac(thetpm, 0) // crypto.Hash(0) — hash arg is for Size()/BlockSize()
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
	t.Logf("Step 8: HMAC baseline over GUID: %x", hmacBaseline)

	// Extract DAK public key for owner voucher
	provisionKey, err := tpmlib.LoadPersistentKey(thetpm, tpmlib.DAKHandle, tpmlib.DeviceKeyUSIndex)
	if err != nil {
		t.Fatalf("LoadPersistentKey (provision): %v", err)
	}
	ownerPubKey := provisionKey.Public().(*ecdsa.PublicKey)
	_ = provisionKey.Close()
	t.Logf("Step 8b: DAK public key extracted (P-%d)", ownerPubKey.Curve.Params().BitSize)

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

	// Step 9: ReadNVCredentials — read all NV indices
	info, err := tpmlib.ReadNVCredentials(thetpm)
	if err != nil {
		t.Fatalf("ReadNVCredentials: %v", err)
	}
	if !info.Active {
		t.Fatal("DCActive should be true (0x01)")
	}
	if !info.HasDAK {
		t.Fatal("DAK should be present")
	}
	if !info.HasHMACKey {
		t.Fatal("HMAC key should be present")
	}

	// Verify GUID from NV matches owner voucher
	if info.GUID != owner.guid {
		t.Fatalf("GUID mismatch: NV=%x owner=%x", info.GUID, owner.guid)
	}
	if info.DeviceInfo != deviceInfo {
		t.Fatalf("DeviceInfo mismatch: NV=%q want=%q", info.DeviceInfo, deviceInfo)
	}
	t.Logf("Step 9: ReadNVCredentials OK — Active=true GUID=%x DAK=present HMAC=present", info.GUID)

	// Step 10: LoadPersistentKey — get signing key with policy session auth
	verifyKey, err := tpmlib.LoadPersistentKey(thetpm, tpmlib.DAKHandle, tpmlib.DeviceKeyUSIndex)
	if err != nil {
		t.Fatalf("LoadPersistentKey (verify): %v", err)
	}
	defer func() { _ = verifyKey.Close() }()
	t.Log("Step 10: LoadPersistentKey OK — DAK loaded with policy session auth")

	// Step 11: Sign a fresh challenge, verify with owner's public key
	challenge := sha256.Sum256([]byte("Phase 9 integration test challenge nonce"))
	sig, err := verifyKey.Sign(nil, challenge[:], nil)
	if err != nil {
		t.Fatalf("Sign (policy auth): %v", err)
	}

	// Verify using owner's public key (NOT from TPM — from owner voucher)
	if !ecdsa.VerifyASN1(owner.pubKey, challenge[:], sig) {
		t.Fatal("DAK signature verification FAILED — owner pubkey does not match")
	}
	t.Logf("Step 11: Sign+Verify OK — DAK signature verified against owner voucher pubkey")

	// Step 11b: Sign a DIFFERENT challenge to prove it's not cached
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
	t.Log("Step 11b: Second Sign+Verify OK — different challenge, different signature, both valid")

	// Step 12: NewSpecHmac — compute HMAC over GUID from NV, verify baseline
	verifyHmac, err := tpmlib.NewSpecHmac(thetpm, 0)
	if err != nil {
		t.Fatalf("NewSpecHmac (verify): %v", err)
	}
	// Use the GUID read from NV (info.GUID), NOT from owner voucher
	if _, err := verifyHmac.Write(info.GUID[:]); err != nil {
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
	t.Logf("Step 12: HMAC verified — matches baseline from provision phase")

	// Step 13: ProveDAKPossession — high-level library API
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
	t.Log("Step 13: ProveDAKPossession OK — pubkey matches, signature verified")

	t.Log("=== Phase 9 PASSED: Full DI→NV→Load→Sign→HMAC cycle with ZERO disk storage ===")
}

// TestPhase9_HMACDeterminism proves the persistent HMAC key produces
// consistent results across multiple NewSpecHmac() calls (same key,
// same data → same HMAC).
func TestPhase9_HMACDeterminism(t *testing.T) {
	thetpm := openTPM(t)
	usePlatform := !ownerHierarchyFallback()
	tpmlib.CleanupFDOState(thetpm)

	// Provision HMAC key
	hmacUS := make([]byte, 32)
	if _, err := rand.Read(hmacUS); err != nil {
		t.Fatal(err)
	}
	hmacUSName, err := tpmlib.DefineNVSpace(thetpm, tpmlib.HMACUSIndex, 32, tpmlib.NVProfileB, usePlatform)
	if err != nil {
		t.Fatal(err)
	}
	if err := tpmlib.WriteNV(thetpm, tpmlib.HMACUSIndex, hmacUSName, hmacUS, tpmlib.NVProfileB); err != nil {
		t.Fatal(err)
	}
	policy, err := tpmlib.ComputeFDOAuthPolicy(thetpm, tpmlib.HMACUSIndex, hmacUSName)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := tpmlib.GenerateSpecHMACKey(thetpm, hmacUS, policy)
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
		h, err := tpmlib.NewSpecHmac(thetpm, 0)
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
	h, _ := tpmlib.NewSpecHmac(thetpm, 0)
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
	usePlatform := !ownerHierarchyFallback()
	tpmlib.CleanupFDOState(thetpm)

	// Provision DAK
	dkUS := make([]byte, 64)
	if _, err := rand.Read(dkUS); err != nil {
		t.Fatal(err)
	}
	dkUSName, err := tpmlib.DefineNVSpace(thetpm, tpmlib.DeviceKeyUSIndex, 64, tpmlib.NVProfileB, usePlatform)
	if err != nil {
		t.Fatal(err)
	}
	if err := tpmlib.WriteNV(thetpm, tpmlib.DeviceKeyUSIndex, dkUSName, dkUS, tpmlib.NVProfileB); err != nil {
		t.Fatal(err)
	}
	policy, err := tpmlib.ComputeFDOAuthPolicy(thetpm, tpmlib.DeviceKeyUSIndex, dkUSName)
	if err != nil {
		t.Fatal(err)
	}
	handle, _, err := tpmlib.GenerateSpecECKey(thetpm, tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256, dkUS, policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := tpmlib.PersistKey(thetpm, *handle, tpmlib.DAKHandle); err != nil {
		t.Fatal(err)
	}

	// Load the key back using production API
	key, err := tpmlib.LoadPersistentKey(thetpm, tpmlib.DAKHandle, tpmlib.DeviceKeyUSIndex)
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
	t.Logf("Signed and verified 10 different digests with persistent DAK (policy session auth)")
}

// TestPhase9_PasswordAuthRejected proves that policy-protected keys
// CANNOT be used with simple password auth — only policy session works.
func TestPhase9_PasswordAuthRejected(t *testing.T) {
	thetpm := openTPM(t)
	usePlatform := !ownerHierarchyFallback()
	tpmlib.CleanupFDOState(thetpm)

	// Provision DAK with AuthPolicy
	dkUS := make([]byte, 64)
	if _, err := rand.Read(dkUS); err != nil {
		t.Fatal(err)
	}
	dkUSName, err := tpmlib.DefineNVSpace(thetpm, tpmlib.DeviceKeyUSIndex, 64, tpmlib.NVProfileB, usePlatform)
	if err != nil {
		t.Fatal(err)
	}
	if err := tpmlib.WriteNV(thetpm, tpmlib.DeviceKeyUSIndex, dkUSName, dkUS, tpmlib.NVProfileB); err != nil {
		t.Fatal(err)
	}
	policy, err := tpmlib.ComputeFDOAuthPolicy(thetpm, tpmlib.DeviceKeyUSIndex, dkUSName)
	if err != nil {
		t.Fatal(err)
	}
	handle, _, err := tpmlib.GenerateSpecECKey(thetpm, tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256, dkUS, policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := tpmlib.PersistKey(thetpm, *handle, tpmlib.DAKHandle); err != nil {
		t.Fatal(err)
	}

	// Try to sign with simple password auth (should FAIL because UserWithAuth=false)
	readResp, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(tpmlib.DAKHandle)}.Execute(thetpm)
	if err != nil {
		t.Fatalf("ReadPublic: %v", err)
	}

	digest := sha256.Sum256([]byte("password auth should fail"))
	_, err = tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(tpmlib.DAKHandle),
			Name:   readResp.Name,
			Auth:   tpm2.PasswordAuth(nil), // password auth, NOT policy session
		},
		Digest:     tpm2.TPM2BDigest{Buffer: digest[:]},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}.Execute(thetpm)
	if err == nil {
		t.Fatal("password auth should have been REJECTED for policy-protected key, but Sign succeeded")
	}
	t.Logf("Password auth correctly rejected: %v", err)

	// Now sign with proper policy session auth (should succeed)
	key, err := tpmlib.LoadPersistentKey(thetpm, tpmlib.DAKHandle, tpmlib.DeviceKeyUSIndex)
	if err != nil {
		t.Fatalf("LoadPersistentKey: %v", err)
	}
	defer func() { _ = key.Close() }()

	sig, err := key.Sign(nil, digest[:], nil)
	if err != nil {
		t.Fatalf("Sign (policy auth): %v", err)
	}
	pubKey := key.Public().(*ecdsa.PublicKey)
	if !ecdsa.VerifyASN1(pubKey, digest[:], sig) {
		t.Fatal("policy auth signature verification failed")
	}
	t.Log("Policy session auth correctly accepted — Sign succeeded + verified")
}

// TestPhase9_CleanupFDOState proves that CleanupFDOState properly
// removes all NV indices and persistent handles.
func TestPhase9_CleanupFDOState(t *testing.T) {
	thetpm := openTPM(t)
	usePlatform := !ownerHierarchyFallback()
	tpmlib.CleanupFDOState(thetpm)

	// Provision some state
	dkUS := make([]byte, 64)
	rand.Read(dkUS)
	dkUSName, _ := tpmlib.DefineNVSpace(thetpm, tpmlib.DeviceKeyUSIndex, 64, tpmlib.NVProfileB, usePlatform)
	tpmlib.WriteNV(thetpm, tpmlib.DeviceKeyUSIndex, dkUSName, dkUS, tpmlib.NVProfileB)

	hmacUS := make([]byte, 32)
	rand.Read(hmacUS)
	hmacUSName, _ := tpmlib.DefineNVSpace(thetpm, tpmlib.HMACUSIndex, 32, tpmlib.NVProfileB, usePlatform)
	tpmlib.WriteNV(thetpm, tpmlib.HMACUSIndex, hmacUSName, hmacUS, tpmlib.NVProfileB)

	dcActiveName, _ := tpmlib.DefineNVSpace(thetpm, tpmlib.DCActiveIndex, 1, tpmlib.NVProfileA, usePlatform)
	tpmlib.WriteNV(thetpm, tpmlib.DCActiveIndex, dcActiveName, []byte{0x01}, tpmlib.NVProfileA)

	dkPolicy, _ := tpmlib.ComputeFDOAuthPolicy(thetpm, tpmlib.DeviceKeyUSIndex, dkUSName)
	dkHandle, _, _ := tpmlib.GenerateSpecECKey(thetpm, tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256, dkUS, dkPolicy)
	tpmlib.PersistKey(thetpm, *dkHandle, tpmlib.DAKHandle)

	hmacPolicy, _ := tpmlib.ComputeFDOAuthPolicy(thetpm, tpmlib.HMACUSIndex, hmacUSName)
	hmacHandle, _ := tpmlib.GenerateSpecHMACKey(thetpm, hmacUS, hmacPolicy)
	tpmlib.PersistKey(thetpm, *hmacHandle, tpmlib.HMACKeyHandle)

	// Verify state exists
	info, err := tpmlib.ReadNVCredentials(thetpm)
	if err != nil {
		t.Fatalf("ReadNVCredentials before cleanup: %v", err)
	}
	if !info.Active || !info.HasDAK || !info.HasHMACKey {
		t.Fatal("expected Active + DAK + HMAC before cleanup")
	}
	t.Log("State provisioned: Active=true DAK=present HMAC=present")

	// Clean up
	tpmlib.CleanupFDOState(thetpm)

	// Verify state is gone
	info2, err := tpmlib.ReadNVCredentials(thetpm)
	if err != nil {
		t.Fatalf("ReadNVCredentials after cleanup: %v", err)
	}
	if info2.Active {
		t.Error("DCActive should be false after cleanup")
	}
	if info2.HasDAK {
		t.Error("DAK should be gone after cleanup")
	}
	if info2.HasHMACKey {
		t.Error("HMAC key should be gone after cleanup")
	}
	t.Log("CleanupFDOState OK: all NV indices and persistent handles removed")
}
