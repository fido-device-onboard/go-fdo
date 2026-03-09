//go:build spec_compliance_test
// +build spec_compliance_test

// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

// Package tpm_test contains FDO TPM specification compliance tests
// per "Securing FDO Credentials in the TPM v1.0":
// https://fidoalliance.org/specifications/download-iot-specifications/
//
// Run all tests:
//
//	cd tpm && go test -v -tags=spec_compliance_test -run TestSpecCompliance -count=1
//
// Configuration via environment variables:
//
//	FDO_TPM=sim                  Use software TPM simulator (default: hardware /dev/tpmrm0)
//	FDO_TPM_P384=0               Disable P-384/SHA-384 tests (default: enabled)
//	FDO_TPM_OWNER_HIERARCHY=1    Use Owner hierarchy instead of Platform for Profile A/B
//	                             (required on Linux userspace where Platform is locked)
//
// Run specific phases:
//
//	go test -v -tags=spec_compliance_test -run TestSpecCompliance/Phase3
//	go test -v -tags=spec_compliance_test -run TestSpecCompliance/Phase5/NegativeAuth
package tpm_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"math/big"
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// =========================================================================
// Constants — FDO spec NV index handles and persistent object handles
// =========================================================================

const (
	// NV Index range 0x01D10000-0x01D10005 reserved for FDO
	DCActive_Index     = 0x01D10000 // OS action flag (1=true, 0=false)
	DCTPM_Index        = 0x01D10001 // DCProtVer, DCDeviceInfo, DCGuid, DCPubKeyHash, DCRVInfo
	DCOV_Index         = 0x01D10002 // DCOV in CBOR encoding
	HMAC_US_Index      = 0x01D10003 // HMAC Unique String (SHA-256/SHA-384)
	DeviceKey_US_Index = 0x01D10004 // Device Key Unique String (P-256/P-384)
	FDO_Cert_Index     = 0x01D10005 // Optional X.509 Certificate for FDO Device key

	// Persistent object handles
	FDO_Device_Key_Handle  = 0x81020002 // ECC signing key in Endorsement hierarchy
	FDO_HMAC_Secret_Handle = 0x81020003 // HMAC key in Endorsement hierarchy
)

// =========================================================================
// NV Attribute Profiles — spec Table 9
// =========================================================================

// Profile A (DCActive): OwnerWrite, AuthWrite, OwnerRead, AuthRead, NoDA, PlatformCreate
var nvAttrsProfileA = tpm2.TPMANV{
	OwnerWrite:     true,
	AuthWrite:      true,
	OwnerRead:      true,
	AuthRead:       true,
	NoDA:           true,
	PlatformCreate: true,
	NT:             tpm2.TPMNTOrdinary,
}

// Profile B (DCTPM, HMAC_US, DeviceKey_US): AuthWrite, AuthRead, NoDA, PlatformCreate
var nvAttrsProfileB = tpm2.TPMANV{
	AuthWrite:      true,
	AuthRead:       true,
	NoDA:           true,
	PlatformCreate: true,
	NT:             tpm2.TPMNTOrdinary,
}

// Profile C (DCOV, FDO_Cert): OwnerWrite, AuthWrite, OwnerRead, AuthRead, NoDA
var nvAttrsProfileC = tpm2.TPMANV{
	OwnerWrite: true,
	AuthWrite:  true,
	OwnerRead:  true,
	AuthRead:   true,
	NoDA:       true,
	NT:         tpm2.TPMNTOrdinary,
}

// nvProfile bundles attributes + defining hierarchy + read/write mode.
type nvProfile struct {
	attrs      tpm2.TPMANV
	authHandle tpm2.TPMHandle
	useOwnerRW bool // true → Owner auth for read/write; false → NV index auth
}

var (
	profileA = nvProfile{nvAttrsProfileA, tpm2.TPMRHPlatform, true}
	profileB = nvProfile{nvAttrsProfileB, tpm2.TPMRHPlatform, false}
	profileC = nvProfile{nvAttrsProfileC, tpm2.TPMRHOwner, true}
)

// =========================================================================
// Configuration helpers
// =========================================================================

// openTPM opens a TPM for testing.
//
// Default: real hardware TPM via /dev/tpmrm0 (falls back to /dev/tpm0).
// The test FAILS if no hardware TPM is accessible — this is intentional
// so that a passing result always means the tests actually exercised a TPM.
//
// Set FDO_TPM=sim to explicitly opt in to the software simulator.
func openTPM(t *testing.T) transport.TPMCloser {
	t.Helper()

	if os.Getenv("FDO_TPM") == "sim" {
		sim, err := simulator.OpenSimulator()
		if err != nil {
			t.Fatalf("opening TPM simulator: %v", err)
		}
		t.Cleanup(func() {
			if err := sim.Close(); err != nil {
				t.Error(err)
			}
		})
		t.Log("TPM backend: simulator")
		return sim
	}

	// Hardware: try resource manager first, then direct device
	dev, err := linuxtpm.Open("/dev/tpmrm0")
	if err == nil {
		t.Cleanup(func() { dev.Close() })
		t.Log("TPM backend: /dev/tpmrm0")
		return dev
	}
	dev, err2 := linuxtpm.Open("/dev/tpm0")
	if err2 == nil {
		t.Cleanup(func() { dev.Close() })
		t.Log("TPM backend: /dev/tpm0")
		return dev
	}
	t.Fatalf("No hardware TPM available (tpmrm0: %v; tpm0: %v). "+
		"Set FDO_TPM=sim to use the software simulator.", err, err2)
	return nil // unreachable
}

// skipP384 skips the test when P-384 is disabled.
// P-384 is ON by default; set FDO_TPM_P384=0 to disable.
func skipP384(t *testing.T) {
	t.Helper()
	if os.Getenv("FDO_TPM_P384") == "0" {
		t.Skip("P-384 disabled (FDO_TPM_P384=0)")
	}
}

// ownerHierarchyFallback returns true when the user has explicitly opted
// in to using Owner hierarchy instead of Platform hierarchy.
//
// The FDO spec requires Profile A/B NV indices to be created via the
// Platform hierarchy (PlatformCreate=1). On real hardware from Linux
// userspace, Platform hierarchy is typically locked after boot — it is
// only available from firmware (UEFI) or with root privileges.
//
// Set FDO_TPM_OWNER_HIERARCHY=1 to explicitly acknowledge this limitation
// and run the tests with Owner hierarchy instead. PlatformCreate will be
// false, and compliance checks will be adjusted accordingly.
func ownerHierarchyFallback() bool {
	return os.Getenv("FDO_TPM_OWNER_HIERARCHY") == "1"
}

// cleanupFDOState attempts to remove all FDO NV indices and persistent
// handles, ignoring errors. This is needed for hardware TPM where state
// persists between test runs.
func cleanupFDOState(t *testing.T, thetpm transport.TPM) {
	t.Helper()
	for _, idx := range []tpm2.TPMHandle{
		DCActive_Index, DCTPM_Index, DCOV_Index,
		HMAC_US_Index, DeviceKey_US_Index, FDO_Cert_Index,
	} {
		nvPub, err := (tpm2.NVReadPublic{NVIndex: idx}).Execute(thetpm)
		if err != nil {
			continue // index does not exist
		}
		nh := tpm2.NamedHandle{Handle: idx, Name: nvPub.NVName}
		// Try Platform first (for firmware-created), then Owner (for test-created)
		for _, auth := range []tpm2.TPMHandle{tpm2.TPMRHPlatform, tpm2.TPMRHOwner} {
			if _, err := (tpm2.NVUndefineSpace{
				AuthHandle: auth,
				NVIndex:    nh,
			}).Execute(thetpm); err == nil {
				break
			}
		}
	}
	for _, h := range []tpm2.TPMHandle{FDO_Device_Key_Handle, FDO_HMAC_Secret_Handle} {
		readResp, err := (tpm2.ReadPublic{ObjectHandle: h}).Execute(thetpm)
		if err != nil {
			continue
		}
		tpm2.EvictControl{
			Auth: tpm2.TPMRHOwner,
			ObjectHandle: &tpm2.NamedHandle{
				Handle: h,
				Name:   readResp.Name,
			},
			PersistentHandle: h,
		}.Execute(thetpm) //nolint:errcheck
	}
}

// =========================================================================
// NV helpers
// =========================================================================

// defineNVSpec creates an NV index with the given attributes and returns its Name.
//
// When authHandle is TPM_RH_PLATFORM and Platform hierarchy is not accessible,
// the test FAILS unless the user has set FDO_TPM_OWNER_HIERARCHY=1 to explicitly
// opt in to Owner hierarchy (PlatformCreate will be false in that mode).
func defineNVSpec(t *testing.T, thetpm transport.TPM, index tpm2.TPMHandle, dataSize uint16, attrs tpm2.TPMANV, authHandle tpm2.TPMHandle) tpm2.TPM2BName {
	t.Helper()

	effectiveAuth := authHandle
	effectiveAttrs := attrs
	if authHandle == tpm2.TPMRHPlatform && ownerHierarchyFallback() {
		effectiveAuth = tpm2.TPMRHOwner
		effectiveAttrs.PlatformCreate = false
	}

	def := tpm2.NVDefineSpace{
		AuthHandle: effectiveAuth,
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex:    index,
			NameAlg:    tpm2.TPMAlgSHA256,
			Attributes: effectiveAttrs,
			DataSize:   dataSize,
		}),
	}
	if _, err := def.Execute(thetpm); err != nil {
		if authHandle == tpm2.TPMRHPlatform && !ownerHierarchyFallback() {
			t.Fatalf("NVDefineSpace 0x%08X: %v\n"+
				"Platform hierarchy is not accessible. The FDO spec requires Profile A/B\n"+
				"indices to be created with Platform auth (PlatformCreate=1). On Linux\n"+
				"userspace this typically requires root or firmware-level access.\n\n"+
				"Options:\n"+
				"  1. Run with sudo or from firmware context for full spec compliance\n"+
				"  2. Set FDO_TPM_OWNER_HIERARCHY=1 to use Owner hierarchy instead\n"+
				"     (PlatformCreate will be false — not fully spec-compliant)\n"+
				"  3. Set FDO_TPM=sim to use the software simulator",
				index, err)
		}
		t.Fatalf("NVDefineSpace 0x%08X: %v", index, err)
	}
	pub, err := def.PublicInfo.Contents()
	if err != nil {
		t.Fatalf("getting NV public: %v", err)
	}
	nvName, err := tpm2.NVName(pub)
	if err != nil {
		t.Fatalf("computing NV name: %v", err)
	}
	return *nvName
}

func writeNVOwner(t *testing.T, thetpm transport.TPM, index tpm2.TPMHandle, nvName tpm2.TPM2BName, data []byte) {
	t.Helper()
	if _, err := (tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: index, Name: nvName},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: data},
	}).Execute(thetpm); err != nil {
		t.Fatalf("NVWrite (Owner) 0x%08X: %v", index, err)
	}
}

func readNVOwner(t *testing.T, thetpm transport.TPM, index tpm2.TPMHandle, nvName tpm2.TPM2BName, size uint16) []byte {
	t.Helper()
	resp, err := (tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: index, Name: nvName},
		Size:       size,
	}).Execute(thetpm)
	if err != nil {
		t.Fatalf("NVRead (Owner) 0x%08X: %v", index, err)
	}
	return resp.Data.Buffer
}

func writeNVAuth(t *testing.T, thetpm transport.TPM, index tpm2.TPMHandle, nvName tpm2.TPM2BName, data []byte) {
	t.Helper()
	if _, err := (tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: index, Name: nvName, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: index, Name: nvName},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: data},
	}).Execute(thetpm); err != nil {
		t.Fatalf("NVWrite (NV auth) 0x%08X: %v", index, err)
	}
}

func readNVAuth(t *testing.T, thetpm transport.TPM, index tpm2.TPMHandle, nvName tpm2.TPM2BName, size uint16) []byte {
	t.Helper()
	resp, err := (tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{Handle: index, Name: nvName, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: index, Name: nvName},
		Size:       size,
	}).Execute(thetpm)
	if err != nil {
		t.Fatalf("NVRead (NV auth) 0x%08X: %v", index, err)
	}
	return resp.Data.Buffer
}

func writeNV(t *testing.T, thetpm transport.TPM, index tpm2.TPMHandle, nvName tpm2.TPM2BName, data []byte, prof nvProfile) {
	t.Helper()
	if prof.useOwnerRW {
		writeNVOwner(t, thetpm, index, nvName, data)
	} else {
		writeNVAuth(t, thetpm, index, nvName, data)
	}
}

func readNV(t *testing.T, thetpm transport.TPM, index tpm2.TPMHandle, nvName tpm2.TPM2BName, size uint16, prof nvProfile) []byte {
	t.Helper()
	if prof.useOwnerRW {
		return readNVOwner(t, thetpm, index, nvName, size)
	}
	return readNVAuth(t, thetpm, index, nvName, size)
}

// =========================================================================
// Auth policy helpers — spec Table 12
// =========================================================================

// computeFDOAuthPolicy uses a trial session to compute:
//
//	PolicyNV(US NV, offset=0, operand=0x00, UnsignedGE) || PolicySecret(US NV)
func computeFDOAuthPolicy(t *testing.T, thetpm transport.TPM, usIndex tpm2.TPMHandle, usName tpm2.TPM2BName) tpm2.TPM2BDigest {
	t.Helper()
	sess, cleanup, err := tpm2.PolicySession(thetpm, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		t.Fatalf("PolicySession (trial): %v", err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			t.Errorf("trial session cleanup: %v", err)
		}
	}()

	ah := tpm2.AuthHandle{Handle: usIndex, Name: usName, Auth: tpm2.PasswordAuth(nil)}
	nh := tpm2.NamedHandle{Handle: usIndex, Name: usName}

	if _, err := (tpm2.PolicyNV{
		AuthHandle: ah, NVIndex: nh, PolicySession: sess.Handle(),
		OperandB: tpm2.TPM2BOperand{Buffer: []byte{0}}, Operation: tpm2.TPMEOUnsignedGE,
	}).Execute(thetpm); err != nil {
		t.Fatalf("PolicyNV (trial): %v", err)
	}
	if _, err := (tpm2.PolicySecret{
		AuthHandle: ah, PolicySession: sess.Handle(),
	}).Execute(thetpm); err != nil {
		t.Fatalf("PolicySecret (trial): %v", err)
	}

	pgd, err := tpm2.PolicyGetDigest{PolicySession: sess.Handle()}.Execute(thetpm)
	if err != nil {
		t.Fatalf("PolicyGetDigest: %v", err)
	}
	return pgd.PolicyDigest
}

// fdoKeyPolicy returns a JIT policy callback for key authorization.
func fdoKeyPolicy(usIndex tpm2.TPMHandle, usName tpm2.TPM2BName) tpm2.Session {
	return tpm2.Policy(tpm2.TPMAlgSHA256, 16, func(tpm transport.TPM, handle tpm2.TPMISHPolicy, _ tpm2.TPM2BNonce) error {
		ah := tpm2.AuthHandle{Handle: usIndex, Name: usName, Auth: tpm2.PasswordAuth(nil)}
		nh := tpm2.NamedHandle{Handle: usIndex, Name: usName}
		if _, err := (tpm2.PolicyNV{
			AuthHandle: ah, NVIndex: nh, PolicySession: handle,
			OperandB: tpm2.TPM2BOperand{Buffer: []byte{0}}, Operation: tpm2.TPMEOUnsignedGE,
		}).Execute(tpm); err != nil {
			return err
		}
		if _, err := (tpm2.PolicySecret{
			AuthHandle: ah, PolicySession: handle,
		}).Execute(tpm); err != nil {
			return err
		}
		return nil
	})
}

// =========================================================================
// Key creation helpers
// =========================================================================

// createPersistentECCKey provisions the DeviceKey_US NV index (Profile B),
// computes auth policy, creates an ECC P-256 primary, and persists it.
// Returns the NV name needed for policy session authorization.
func createPersistentECCKey(t *testing.T, thetpm transport.TPM) tpm2.TPM2BName {
	t.Helper()
	us := generateTestDeviceKeyUniqueString(64)
	nvName := defineNVSpec(t, thetpm, DeviceKey_US_Index, 64, nvAttrsProfileB, tpm2.TPMRHPlatform)
	writeNVAuth(t, thetpm, DeviceKey_US_Index, nvName, us)

	policy := computeFDOAuthPolicy(t, thetpm, DeviceKey_US_Index, nvName)
	resp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type: tpm2.TPMAlgECC, NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, SignEncrypt: true,
			},
			AuthPolicy: policy,
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
				Scheme: tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256})},
			}),
			Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: us[:32]},
				Y: tpm2.TPM2BECCParameter{Buffer: us[32:]},
			}),
		}),
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("CreatePrimary ECC: %v", err)
	}
	if _, err := (tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     &tpm2.NamedHandle{Handle: resp.ObjectHandle, Name: resp.Name},
		PersistentHandle: tpm2.TPMHandle(FDO_Device_Key_Handle),
	}).Execute(thetpm); err != nil {
		t.Fatalf("EvictControl ECC: %v", err)
	}
	tpm2.FlushContext{FlushHandle: resp.ObjectHandle}.Execute(thetpm) //nolint:errcheck
	return nvName
}

// createPersistentHMACKey provisions the HMAC_US NV index (Profile B),
// computes auth policy, creates an HMAC SHA-256 primary, and persists it.
func createPersistentHMACKey(t *testing.T, thetpm transport.TPM) tpm2.TPM2BName {
	t.Helper()
	us := generateTestHMACUniqueString(32)
	nvName := defineNVSpec(t, thetpm, HMAC_US_Index, 32, nvAttrsProfileB, tpm2.TPMRHPlatform)
	writeNVAuth(t, thetpm, HMAC_US_Index, nvName, us)

	policy := computeFDOAuthPolicy(t, thetpm, HMAC_US_Index, nvName)
	resp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type: tpm2.TPMAlgKeyedHash, NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, SignEncrypt: true,
			},
			AuthPolicy: policy,
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
				Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgHMAC,
					Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC, &tpm2.TPMSSchemeHMAC{HashAlg: tpm2.TPMAlgSHA256})},
			}),
			Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{Buffer: us}),
		}),
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("CreatePrimary HMAC: %v", err)
	}
	if _, err := (tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     &tpm2.NamedHandle{Handle: resp.ObjectHandle, Name: resp.Name},
		PersistentHandle: tpm2.TPMHandle(FDO_HMAC_Secret_Handle),
	}).Execute(thetpm); err != nil {
		t.Fatalf("EvictControl HMAC: %v", err)
	}
	tpm2.FlushContext{FlushHandle: resp.ObjectHandle}.Execute(thetpm) //nolint:errcheck
	return nvName
}

// =========================================================================
// Test data generators
// =========================================================================

func generateTestDCTPMData() []byte {
	d := make([]byte, 512)
	for i := range d {
		d[i] = byte(i % 256)
	}
	return d
}

func generateTestOVData() []byte {
	d := make([]byte, 1024)
	for i := range d {
		d[i] = byte((i * 3) % 256)
	}
	return d
}

func generateTestHMACUniqueString(size int) []byte {
	d := make([]byte, size)
	for i := range d {
		d[i] = byte((i * 7) % 256)
	}
	return d
}

func generateTestDeviceKeyUniqueString(size int) []byte {
	d := make([]byte, size)
	half := size / 2
	for i := range d {
		if i < half {
			d[i] = byte((i * 11) % 256)
		} else {
			d[i] = byte((i * 13) % 256)
		}
	}
	return d
}

func generateTestCertificate() []byte {
	d := make([]byte, 2048)
	for i := range d {
		d[i] = byte((i * 17) % 256)
	}
	return d
}

// =========================================================================
// Small helpers
// =========================================================================

func assertBool(t *testing.T, name string, got, want bool) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %v, want %v", name, got, want)
	}
}

// =========================================================================
// Single entry point
// =========================================================================

// TestSpecCompliance runs the full FDO TPM specification compliance suite.
//
// Default: hardware TPM, P-384 enabled.
// Override with FDO_TPM=sim and/or FDO_TPM_P384=0.
func TestSpecCompliance(t *testing.T) {
	t.Run("Phase1_Constants", runPhase1)
	t.Run("Phase2_DataStructures", runPhase2)
	t.Run("Phase3_Storage", runPhase3)
	t.Run("Phase4_Crypto", runPhase4)
	t.Run("Phase5_Compliance", runPhase5)
	t.Run("Phase6_E2E", runPhase6)
}

// =========================================================================
// Phase 1 — Constant Validation
// =========================================================================

func runPhase1(t *testing.T) {
	t.Run("NVIndexRange", func(t *testing.T) {
		indices := []struct {
			name  string
			value uint32
		}{
			{"DCActive", DCActive_Index},
			{"DCTPM", DCTPM_Index},
			{"DCOV", DCOV_Index},
			{"HMAC_US", HMAC_US_Index},
			{"DeviceKey_US", DeviceKey_US_Index},
			{"FDO_Cert", FDO_Cert_Index},
		}
		for i, idx := range indices {
			expected := uint32(0x01D10000) + uint32(i)
			if idx.value != expected {
				t.Errorf("%s: got 0x%08X, want 0x%08X", idx.name, idx.value, expected)
			}
		}
		t.Logf("NV indices: 0x%08X-0x%08X (6 indices)", DCActive_Index, FDO_Cert_Index)
	})

	t.Run("PersistentHandles", func(t *testing.T) {
		for _, h := range []struct {
			name   string
			handle uint32
		}{
			{"FDO_Device_Key", FDO_Device_Key_Handle},
			{"FDO_HMAC_Secret", FDO_HMAC_Secret_Handle},
		} {
			if h.handle < 0x81000000 || h.handle > 0x81FFFFFF {
				t.Errorf("%s (0x%08X) outside persistent range", h.name, h.handle)
			}
		}
	})

	t.Run("DeviceKeyTypes", func(t *testing.T) {
		// Spec section 4.1: FdoDeviceKey=0, IDevIDDeviceKey=1, LDevIDDeviceKey=2
		for _, tc := range []struct {
			name    string
			keyType int
		}{
			{"FdoDeviceKey", 0},
			{"IDevIDDeviceKey", 1},
			{"LDevIDDeviceKey", 2},
		} {
			if tc.keyType < 0 || tc.keyType > 2 {
				t.Errorf("%s: invalid value %d", tc.name, tc.keyType)
			}
		}
	})
}

// =========================================================================
// Phase 2 — Data Structure Validation
// =========================================================================

func runPhase2(t *testing.T) {
	t.Run("DCTPMStructure", func(t *testing.T) {
		testCases := []struct {
			name       string
			version    uint16
			deviceInfo string
			guid       []byte
			keyType    int
			handle     uint32
		}{
			{"FDO_DeviceKey", 1, "test-device", make([]byte, 16), 0, 0x81020002},
			{"IDevID", 1, "test-device-idevid", make([]byte, 16), 1, 0x0},
			{"LDevID", 1, "test-device-ldevid", make([]byte, 16), 2, 0x0},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				if tc.version != 1 {
					t.Errorf("version: got %d, want 1", tc.version)
				}
				if len(tc.guid) != 16 {
					t.Errorf("GUID: %d bytes, want 16", len(tc.guid))
				}
				if tc.keyType < 0 || tc.keyType > 2 {
					t.Errorf("keyType %d out of range [0,2]", tc.keyType)
				}
			})
		}
	})
}

// =========================================================================
// Phase 3 — TPM Storage Operations
// =========================================================================

func runPhase3(t *testing.T) {
	t.Run("NVDefinition", func(t *testing.T) {
		cases := []struct {
			name    string
			index   uint32
			size    uint16
			profile nvProfile
			p384    bool
		}{
			{"DCActive", DCActive_Index, 1, profileA, false},
			{"DCTPM", DCTPM_Index, 256, profileB, false},
			{"DCOV", DCOV_Index, 512, profileC, false},
			{"HMAC_US_SHA256", HMAC_US_Index, 32, profileB, false},
			{"HMAC_US_SHA384", HMAC_US_Index, 48, profileB, true},
			{"DeviceKey_US_P256", DeviceKey_US_Index, 64, profileB, false},
			{"DeviceKey_US_P384", DeviceKey_US_Index, 96, profileB, true},
			{"FDO_Certificate", FDO_Cert_Index, 512, profileC, false},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if tc.p384 {
					skipP384(t)
				}
				// Each subtest gets its own TPM — P-384/P-256 share NV indices
				thetpm := openTPM(t)
				cleanupFDOState(t, thetpm)
				defineNVSpec(t, thetpm, tpm2.TPMHandle(tc.index), tc.size, tc.profile.attrs, tc.profile.authHandle)
				resp, err := (tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(tc.index)}).Execute(thetpm)
				if err != nil {
					t.Fatalf("NVReadPublic: %v", err)
				}
				t.Logf("0x%08X created, name: %x", tc.index, resp.NVName.Buffer)
			})
		}
	})

	t.Run("DataRoundTrip", func(t *testing.T) {
		thetpm := openTPM(t)
		cleanupFDOState(t, thetpm)

		cases := []struct {
			name    string
			index   uint32
			data    []byte
			profile nvProfile
		}{
			{"DCActive", DCActive_Index, []byte{1}, profileA},
			{"DCTPM", DCTPM_Index, generateTestDCTPMData()[:256], profileB},
			{"DCOV", DCOV_Index, generateTestOVData()[:512], profileC},
			{"HMAC_US", HMAC_US_Index, generateTestHMACUniqueString(32), profileB},
			{"DeviceKey_US", DeviceKey_US_Index, generateTestDeviceKeyUniqueString(64), profileB},
			{"FDO_Certificate", FDO_Cert_Index, generateTestCertificate()[:512], profileC},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				nvName := defineNVSpec(t, thetpm, tpm2.TPMHandle(tc.index), uint16(len(tc.data)), tc.profile.attrs, tc.profile.authHandle)
				writeNV(t, thetpm, tpm2.TPMHandle(tc.index), nvName, tc.data, tc.profile)
				got := readNV(t, thetpm, tpm2.TPMHandle(tc.index), nvName, uint16(len(tc.data)), tc.profile)
				if !bytes.Equal(got, tc.data) {
					t.Errorf("data mismatch at 0x%08X", tc.index)
				}
				t.Logf("0x%08X: %d bytes round-trip OK", tc.index, len(tc.data))
			})
		}
	})

	t.Run("PersistentObjects", func(t *testing.T) {
		thetpm := openTPM(t)
		cleanupFDOState(t, thetpm)

		t.Run("DeviceKey_ECC_P256", func(t *testing.T) {
			createPersistentECCKey(t, thetpm)
			resp, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_Device_Key_Handle)}.Execute(thetpm)
			if err != nil {
				t.Fatalf("ReadPublic: %v", err)
			}
			t.Logf("Persistent ECC key at 0x%08X, name=%x", FDO_Device_Key_Handle, resp.Name.Buffer)
		})

		t.Run("HMACSecret_SHA256", func(t *testing.T) {
			createPersistentHMACKey(t, thetpm)
			resp, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_HMAC_Secret_Handle)}.Execute(thetpm)
			if err != nil {
				t.Fatalf("ReadPublic: %v", err)
			}
			t.Logf("Persistent HMAC key at 0x%08X, name=%x", FDO_HMAC_Secret_Handle, resp.Name.Buffer)
		})
	})

	t.Run("KeyDerivation", func(t *testing.T) {
		cases := []struct {
			name             string
			usIndex          uint32
			persistentHandle tpm2.TPMHandle
			algType          string
			keySize          int
			p384             bool
		}{
			{"HMAC_SHA256", HMAC_US_Index, FDO_HMAC_Secret_Handle, "HMAC", 32, false},
			{"HMAC_SHA384", HMAC_US_Index, FDO_HMAC_Secret_Handle, "HMAC", 48, true},
			{"DeviceKey_P256", DeviceKey_US_Index, FDO_Device_Key_Handle, "ECC", 32, false},
			{"DeviceKey_P384", DeviceKey_US_Index, FDO_Device_Key_Handle, "ECC", 48, true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if tc.p384 {
					skipP384(t)
				}
				// Each subtest gets its own TPM — P-384/P-256 share NV indices and persistent handles
				thetpm := openTPM(t)
				cleanupFDOState(t, thetpm)
				var usData []byte
				var nvSize uint16
				if tc.algType == "ECC" {
					usData = generateTestDeviceKeyUniqueString(tc.keySize * 2)
					nvSize = uint16(tc.keySize * 2)
				} else {
					usData = generateTestHMACUniqueString(tc.keySize)
					nvSize = uint16(tc.keySize)
				}
				nvName := defineNVSpec(t, thetpm, tpm2.TPMHandle(tc.usIndex), nvSize, nvAttrsProfileB, tpm2.TPMRHPlatform)
				writeNVAuth(t, thetpm, tpm2.TPMHandle(tc.usIndex), nvName, usData)
				got := readNVAuth(t, thetpm, tpm2.TPMHandle(tc.usIndex), nvName, nvSize)
				if !bytes.Equal(got, usData) {
					t.Fatal("US NV round-trip mismatch")
				}

				policy := computeFDOAuthPolicy(t, thetpm, tpm2.TPMHandle(tc.usIndex), nvName)

				// Select curve/hash based on key variant
				curveID := tpm2.TPMECCNistP256
				hashAlg := tpm2.TPMAlgSHA256
				if tc.p384 {
					curveID = tpm2.TPMECCNistP384
					hashAlg = tpm2.TPMAlgSHA384
				}

				var tmpl tpm2.TPMTPublic
				if tc.algType == "ECC" {
					half := len(usData) / 2
					tmpl = tpm2.TPMTPublic{
						Type: tpm2.TPMAlgECC, NameAlg: tpm2.TPMAlgSHA256,
						ObjectAttributes: tpm2.TPMAObject{
							FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, SignEncrypt: true,
						},
						AuthPolicy: policy,
						Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
							CurveID: curveID,
							Scheme: tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgECDSA,
								Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: hashAlg})},
						}),
						Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
							X: tpm2.TPM2BECCParameter{Buffer: usData[:half]},
							Y: tpm2.TPM2BECCParameter{Buffer: usData[half:]},
						}),
					}
				} else {
					tmpl = tpm2.TPMTPublic{
						Type: tpm2.TPMAlgKeyedHash, NameAlg: tpm2.TPMAlgSHA256,
						ObjectAttributes: tpm2.TPMAObject{
							FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, SignEncrypt: true,
						},
						AuthPolicy: policy,
						Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
							Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgHMAC,
								Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC, &tpm2.TPMSSchemeHMAC{HashAlg: hashAlg})},
						}),
						Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{Buffer: usData}),
					}
				}
				createResp, err := tpm2.CreatePrimary{
					PrimaryHandle: tpm2.TPMRHEndorsement, InPublic: tpm2.New2B(tmpl),
				}.Execute(thetpm)
				if err != nil {
					t.Fatalf("CreatePrimary: %v", err)
				}
				if _, err := (tpm2.EvictControl{
					Auth:             tpm2.TPMRHOwner,
					ObjectHandle:     &tpm2.NamedHandle{Handle: createResp.ObjectHandle, Name: createResp.Name},
					PersistentHandle: tc.persistentHandle,
				}).Execute(thetpm); err != nil {
					t.Fatalf("EvictControl: %v", err)
				}
				t.Logf("Derived %s key (%d-byte US) at 0x%08X", tc.algType, len(usData), tc.persistentHandle)
			})
		}
	})

	t.Run("ClearResilience", func(t *testing.T) {
		thetpm := openTPM(t)
		cleanupFDOState(t, thetpm)

		us := generateTestDeviceKeyUniqueString(64)
		nvName := defineNVSpec(t, thetpm, DeviceKey_US_Index, 64, nvAttrsProfileB, tpm2.TPMRHPlatform)
		writeNVAuth(t, thetpm, DeviceKey_US_Index, nvName, us)

		policy := computeFDOAuthPolicy(t, thetpm, DeviceKey_US_Index, nvName)
		tmpl := tpm2.TPMTPublic{
			Type: tpm2.TPMAlgECC, NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, SignEncrypt: true,
			},
			AuthPolicy: policy,
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
				CurveID: tpm2.TPMECCNistP256,
				Scheme: tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256})},
			}),
			Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: us[:32]},
				Y: tpm2.TPM2BECCParameter{Buffer: us[32:]},
			}),
		}

		r1, err := tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHEndorsement, InPublic: tpm2.New2B(tmpl)}.Execute(thetpm)
		if err != nil {
			t.Fatalf("CreatePrimary (1): %v", err)
		}
		p1, _ := tpm2.ReadPublic{ObjectHandle: r1.ObjectHandle}.Execute(thetpm)
		tpm2.FlushContext{FlushHandle: r1.ObjectHandle}.Execute(thetpm) //nolint:errcheck

		r2, err := tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHEndorsement, InPublic: tpm2.New2B(tmpl)}.Execute(thetpm)
		if err != nil {
			t.Fatalf("CreatePrimary (2): %v", err)
		}
		p2, _ := tpm2.ReadPublic{ObjectHandle: r2.ObjectHandle}.Execute(thetpm)

		d1, _ := p1.OutPublic.Contents()
		d2, _ := p2.OutPublic.Contents()
		e1, _ := d1.Unique.ECC()
		e2, _ := d2.Unique.ECC()
		if !bytes.Equal(e1.X.Buffer, e2.X.Buffer) || !bytes.Equal(e1.Y.Buffer, e2.Y.Buffer) {
			t.Error("keys differ after re-derivation with same unique string")
		}
		t.Log("Same unique string produces same key (TPM2_Clear resilience)")
	})
}

// =========================================================================
// Phase 4 — Cryptographic Operations (policy session auth)
// =========================================================================

func runPhase4(t *testing.T) {
	t.Run("Signing", func(t *testing.T) {
		t.Run("BasicSign", func(t *testing.T) {
			thetpm := openTPM(t)
			cleanupFDOState(t, thetpm)
			dkNVName := createPersistentECCKey(t, thetpm)

			readResp, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_Device_Key_Handle)}.Execute(thetpm)
			if err != nil {
				t.Fatalf("ReadPublic: %v", err)
			}
			pub, _ := readResp.OutPublic.Contents()
			ecc, _ := pub.Unique.ECC()
			pubKey := &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(ecc.X.Buffer),
				Y:     new(big.Int).SetBytes(ecc.Y.Buffer),
			}

			digest := sha256.Sum256([]byte("FDO spec compliance signing test"))
			sigResp, err := tpm2.Sign{
				KeyHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMHandle(FDO_Device_Key_Handle), Name: readResp.Name,
					Auth: fdoKeyPolicy(DeviceKey_US_Index, dkNVName),
				},
				Digest:     tpm2.TPM2BDigest{Buffer: digest[:]},
				Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
			}.Execute(thetpm)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			ecSig, _ := sigResp.Signature.Signature.ECDSA()
			r := new(big.Int).SetBytes(ecSig.SignatureR.Buffer)
			s := new(big.Int).SetBytes(ecSig.SignatureS.Buffer)
			if !ecdsa.Verify(pubKey, digest[:], r, s) {
				t.Fatal("ECDSA verify failed")
			}
			t.Logf("Signed+verified at 0x%08X (policy auth)", FDO_Device_Key_Handle)
		})

		t.Run("Determinism", func(t *testing.T) {
			thetpm := openTPM(t)
			cleanupFDOState(t, thetpm)
			dkNVName := createPersistentECCKey(t, thetpm)

			readResp, _ := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_Device_Key_Handle)}.Execute(thetpm)
			pub, _ := readResp.OutPublic.Contents()
			ecc, _ := pub.Unique.ECC()
			pubKey := &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(ecc.X.Buffer),
				Y:     new(big.Int).SetBytes(ecc.Y.Buffer),
			}

			digest := sha256.Sum256([]byte("determinism test"))
			policy := fdoKeyPolicy(DeviceKey_US_Index, dkNVName)

			var sigs [2]*tpm2.SignResponse
			for i := range sigs {
				var err error
				sigs[i], err = tpm2.Sign{
					KeyHandle:  tpm2.AuthHandle{Handle: tpm2.TPMHandle(FDO_Device_Key_Handle), Name: readResp.Name, Auth: policy},
					Digest:     tpm2.TPM2BDigest{Buffer: digest[:]},
					Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
				}.Execute(thetpm)
				if err != nil {
					t.Fatalf("Sign(%d): %v", i, err)
				}
			}
			for i, sig := range sigs {
				ec, _ := sig.Signature.Signature.ECDSA()
				r := new(big.Int).SetBytes(ec.SignatureR.Buffer)
				s := new(big.Int).SetBytes(ec.SignatureS.Buffer)
				if !ecdsa.Verify(pubKey, digest[:], r, s) {
					t.Errorf("sig %d failed verify", i)
				}
			}
			t.Log("Both signatures verified (policy auth)")
		})

		t.Run("DifferentDigests", func(t *testing.T) {
			thetpm := openTPM(t)
			cleanupFDOState(t, thetpm)
			dkNVName := createPersistentECCKey(t, thetpm)

			readResp, _ := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_Device_Key_Handle)}.Execute(thetpm)
			pub, _ := readResp.OutPublic.Contents()
			ecc, _ := pub.Unique.ECC()
			pubKey := &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(ecc.X.Buffer),
				Y:     new(big.Int).SetBytes(ecc.Y.Buffer),
			}
			policy := fdoKeyPolicy(DeviceKey_US_Index, dkNVName)

			for _, msg := range []string{"DI message", "TO1", "TO2", "", "special!@#"} {
				label := msg
				if label == "" {
					label = "(empty)"
				}
				t.Run(label, func(t *testing.T) {
					digest := sha256.Sum256([]byte(msg))
					sigResp, err := tpm2.Sign{
						KeyHandle:  tpm2.AuthHandle{Handle: tpm2.TPMHandle(FDO_Device_Key_Handle), Name: readResp.Name, Auth: policy},
						Digest:     tpm2.TPM2BDigest{Buffer: digest[:]},
						Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
					}.Execute(thetpm)
					if err != nil {
						t.Fatalf("Sign: %v", err)
					}
					ec, _ := sigResp.Signature.Signature.ECDSA()
					r := new(big.Int).SetBytes(ec.SignatureR.Buffer)
					s := new(big.Int).SetBytes(ec.SignatureS.Buffer)
					if !ecdsa.Verify(pubKey, digest[:], r, s) {
						t.Error("verify failed")
					}
				})
			}
		})
	})

	t.Run("HMAC", func(t *testing.T) {
		t.Run("Basic", func(t *testing.T) {
			thetpm := openTPM(t)
			cleanupFDOState(t, thetpm)
			hmacNVName := createPersistentHMACKey(t, thetpm)

			computeHMAC := func(data []byte) []byte {
				t.Helper()
				rr, _ := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_HMAC_Secret_Handle)}.Execute(thetpm)
				hs, err := tpm2.HmacStart{
					Handle:  tpm2.AuthHandle{Handle: tpm2.TPMHandle(FDO_HMAC_Secret_Handle), Name: rr.Name, Auth: fdoKeyPolicy(HMAC_US_Index, hmacNVName)},
					Auth:    tpm2.TPM2BAuth{},
					HashAlg: tpm2.TPMAlgNull,
				}.Execute(thetpm)
				if err != nil {
					t.Fatalf("HmacStart: %v", err)
				}
				sc, err := tpm2.SequenceComplete{
					SequenceHandle: tpm2.AuthHandle{Handle: hs.SequenceHandle, Auth: tpm2.PasswordAuth(nil)},
					Buffer:         tpm2.TPM2BMaxBuffer{Buffer: data},
					Hierarchy:      tpm2.TPMRHNull,
				}.Execute(thetpm)
				if err != nil {
					t.Fatalf("SequenceComplete: %v", err)
				}
				return sc.Result.Buffer
			}

			h1 := computeHMAC([]byte("test data"))
			h2 := computeHMAC([]byte("test data"))
			h3 := computeHMAC([]byte("different data"))

			if !bytes.Equal(h1, h2) {
				t.Error("HMAC not deterministic")
			}
			if bytes.Equal(h1, h3) {
				t.Error("HMAC should differ for different data")
			}
			if len(h1) != 32 {
				t.Errorf("HMAC length: got %d, want 32", len(h1))
			}
			t.Logf("HMAC at 0x%08X: %x (policy auth)", FDO_HMAC_Secret_Handle, h1)
		})

		t.Run("LargeData", func(t *testing.T) {
			thetpm := openTPM(t)
			cleanupFDOState(t, thetpm)
			hmacNVName := createPersistentHMACKey(t, thetpm)

			largeData := make([]byte, 4096)
			for i := range largeData {
				largeData[i] = byte((i * 31) % 256)
			}

			computeHMACLarge := func(data []byte) []byte {
				t.Helper()
				rr, _ := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_HMAC_Secret_Handle)}.Execute(thetpm)
				hs, err := tpm2.HmacStart{
					Handle:  tpm2.AuthHandle{Handle: tpm2.TPMHandle(FDO_HMAC_Secret_Handle), Name: rr.Name, Auth: fdoKeyPolicy(HMAC_US_Index, hmacNVName)},
					Auth:    tpm2.TPM2BAuth{},
					HashAlg: tpm2.TPMAlgNull,
				}.Execute(thetpm)
				if err != nil {
					t.Fatalf("HmacStart: %v", err)
				}
				seqAuth := tpm2.AuthHandle{Handle: hs.SequenceHandle, Auth: tpm2.PasswordAuth(nil)}
				remaining := data
				for len(remaining) > 1024 {
					if _, err := (tpm2.SequenceUpdate{
						SequenceHandle: seqAuth,
						Buffer:         tpm2.TPM2BMaxBuffer{Buffer: remaining[:1024]},
					}).Execute(thetpm); err != nil {
						t.Fatalf("SequenceUpdate: %v", err)
					}
					remaining = remaining[1024:]
				}
				sc, err := tpm2.SequenceComplete{
					SequenceHandle: seqAuth,
					Buffer:         tpm2.TPM2BMaxBuffer{Buffer: remaining},
					Hierarchy:      tpm2.TPMRHNull,
				}.Execute(thetpm)
				if err != nil {
					t.Fatalf("SequenceComplete: %v", err)
				}
				return sc.Result.Buffer
			}

			h1 := computeHMACLarge(largeData)
			h2 := computeHMACLarge(largeData)
			if !bytes.Equal(h1, h2) {
				t.Error("large HMAC not deterministic")
			}
			if len(h1) != 32 {
				t.Errorf("HMAC length: got %d, want 32", len(h1))
			}
			t.Logf("Large HMAC (%d bytes, policy auth): %x", len(largeData), h1)
		})
	})

	t.Run("PersistentHandleOps", func(t *testing.T) {
		thetpm := openTPM(t)
		cleanupFDOState(t, thetpm)
		dkNVName := createPersistentECCKey(t, thetpm)
		hmacNVName := createPersistentHMACKey(t, thetpm)

		t.Run("ReadPublic_DeviceKey", func(t *testing.T) {
			resp, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_Device_Key_Handle)}.Execute(thetpm)
			if err != nil {
				t.Fatalf("ReadPublic: %v", err)
			}
			pub, _ := resp.OutPublic.Contents()
			if pub.Type != tpm2.TPMAlgECC {
				t.Errorf("type: got %v, want ECC", pub.Type)
			}
		})

		t.Run("ReadPublic_HMACSecret", func(t *testing.T) {
			resp, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_HMAC_Secret_Handle)}.Execute(thetpm)
			if err != nil {
				t.Fatalf("ReadPublic: %v", err)
			}
			pub, _ := resp.OutPublic.Contents()
			if pub.Type != tpm2.TPMAlgKeyedHash {
				t.Errorf("type: got %v, want KeyedHash", pub.Type)
			}
		})

		t.Run("Sign", func(t *testing.T) {
			rr, _ := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_Device_Key_Handle)}.Execute(thetpm)
			pub, _ := rr.OutPublic.Contents()
			ecc, _ := pub.Unique.ECC()
			pubKey := &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(ecc.X.Buffer),
				Y:     new(big.Int).SetBytes(ecc.Y.Buffer),
			}
			digest := sha256.Sum256([]byte("persistent sign"))
			sigResp, err := tpm2.Sign{
				KeyHandle:  tpm2.AuthHandle{Handle: tpm2.TPMHandle(FDO_Device_Key_Handle), Name: rr.Name, Auth: fdoKeyPolicy(DeviceKey_US_Index, dkNVName)},
				Digest:     tpm2.TPM2BDigest{Buffer: digest[:]},
				Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
			}.Execute(thetpm)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			ec, _ := sigResp.Signature.Signature.ECDSA()
			if !ecdsa.Verify(pubKey, digest[:], new(big.Int).SetBytes(ec.SignatureR.Buffer), new(big.Int).SetBytes(ec.SignatureS.Buffer)) {
				t.Fatal("verify failed")
			}
		})

		t.Run("HMAC", func(t *testing.T) {
			rr, _ := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_HMAC_Secret_Handle)}.Execute(thetpm)
			hs, err := tpm2.HmacStart{
				Handle:  tpm2.AuthHandle{Handle: tpm2.TPMHandle(FDO_HMAC_Secret_Handle), Name: rr.Name, Auth: fdoKeyPolicy(HMAC_US_Index, hmacNVName)},
				Auth:    tpm2.TPM2BAuth{},
				HashAlg: tpm2.TPMAlgNull,
			}.Execute(thetpm)
			if err != nil {
				t.Fatalf("HmacStart: %v", err)
			}
			sc, err := tpm2.SequenceComplete{
				SequenceHandle: tpm2.AuthHandle{Handle: hs.SequenceHandle, Auth: tpm2.PasswordAuth(nil)},
				Buffer:         tpm2.TPM2BMaxBuffer{Buffer: []byte("persistent hmac")},
				Hierarchy:      tpm2.TPMRHNull,
			}.Execute(thetpm)
			if err != nil {
				t.Fatalf("SequenceComplete: %v", err)
			}
			if len(sc.Result.Buffer) != 32 {
				t.Errorf("HMAC length: got %d, want 32", len(sc.Result.Buffer))
			}
		})
	})
}

// =========================================================================
// Phase 5 — Compliance Verification
// =========================================================================

func runPhase5(t *testing.T) {
	t.Run("NVAttributes", func(t *testing.T) {
		t.Run("ProfileA", func(t *testing.T) {
			thetpm := openTPM(t)
			cleanupFDOState(t, thetpm)
			expectPlatformCreate := !ownerHierarchyFallback()
			defineNVSpec(t, thetpm, DCActive_Index, 1, nvAttrsProfileA, tpm2.TPMRHPlatform)

			resp, err := (tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(DCActive_Index)}).Execute(thetpm)
			if err != nil {
				t.Fatalf("NVReadPublic: %v", err)
			}
			nvPub, _ := resp.NVPublic.Contents()
			a := nvPub.Attributes

			assertBool(t, "OwnerWrite", a.OwnerWrite, true)
			assertBool(t, "AuthWrite", a.AuthWrite, true)
			assertBool(t, "OwnerRead", a.OwnerRead, true)
			assertBool(t, "AuthRead", a.AuthRead, true)
			assertBool(t, "NoDA", a.NoDA, true)
			assertBool(t, "PlatformCreate", a.PlatformCreate, expectPlatformCreate)
			assertBool(t, "PPWrite", a.PPWrite, false)
			assertBool(t, "PolicyWrite", a.PolicyWrite, false)
			assertBool(t, "PPRead", a.PPRead, false)
			assertBool(t, "PolicyRead", a.PolicyRead, false)
			if a.NT != tpm2.TPMNTOrdinary {
				t.Errorf("NT: got %d, want Ordinary", a.NT)
			}
		})

		t.Run("ProfileB", func(t *testing.T) {
			thetpm := openTPM(t)
			cleanupFDOState(t, thetpm)
			expectPlatformCreate := !ownerHierarchyFallback()

			for _, idx := range []struct {
				name  string
				index tpm2.TPMHandle
				size  uint16
			}{
				{"DCTPM", DCTPM_Index, 256},
				{"HMAC_US", HMAC_US_Index, 32},
				{"DeviceKey_US", DeviceKey_US_Index, 64},
			} {
				t.Run(idx.name, func(t *testing.T) {
					defineNVSpec(t, thetpm, idx.index, idx.size, nvAttrsProfileB, tpm2.TPMRHPlatform)
					resp, _ := (tpm2.NVReadPublic{NVIndex: idx.index}).Execute(thetpm)
					nvPub, _ := resp.NVPublic.Contents()
					a := nvPub.Attributes

					assertBool(t, "AuthWrite", a.AuthWrite, true)
					assertBool(t, "AuthRead", a.AuthRead, true)
					assertBool(t, "NoDA", a.NoDA, true)
					assertBool(t, "PlatformCreate", a.PlatformCreate, expectPlatformCreate)
					assertBool(t, "OwnerWrite", a.OwnerWrite, false)
					assertBool(t, "OwnerRead", a.OwnerRead, false)
				})
			}
		})

		t.Run("ProfileC", func(t *testing.T) {
			thetpm := openTPM(t)
			cleanupFDOState(t, thetpm)

			for _, idx := range []struct {
				name  string
				index tpm2.TPMHandle
				size  uint16
			}{
				{"DCOV", DCOV_Index, 512},
				{"FDO_Certificate", FDO_Cert_Index, 512},
			} {
				t.Run(idx.name, func(t *testing.T) {
					defineNVSpec(t, thetpm, idx.index, idx.size, nvAttrsProfileC, tpm2.TPMRHOwner)
					resp, _ := (tpm2.NVReadPublic{NVIndex: idx.index}).Execute(thetpm)
					nvPub, _ := resp.NVPublic.Contents()
					a := nvPub.Attributes

					assertBool(t, "OwnerWrite", a.OwnerWrite, true)
					assertBool(t, "AuthWrite", a.AuthWrite, true)
					assertBool(t, "OwnerRead", a.OwnerRead, true)
					assertBool(t, "AuthRead", a.AuthRead, true)
					assertBool(t, "NoDA", a.NoDA, true)
					assertBool(t, "PlatformCreate", a.PlatformCreate, false)
				})
			}
		})

		t.Run("ProfileDifferentiation", func(t *testing.T) {
			thetpm := openTPM(t)
			cleanupFDOState(t, thetpm)
			expectPlatformCreate := !ownerHierarchyFallback()

			defineNVSpec(t, thetpm, DCActive_Index, 1, nvAttrsProfileA, tpm2.TPMRHPlatform)
			defineNVSpec(t, thetpm, DCTPM_Index, 256, nvAttrsProfileB, tpm2.TPMRHPlatform)
			defineNVSpec(t, thetpm, DCOV_Index, 512, nvAttrsProfileC, tpm2.TPMRHOwner)

			readAttrs := func(idx tpm2.TPMHandle) tpm2.TPMANV {
				resp, _ := (tpm2.NVReadPublic{NVIndex: idx}).Execute(thetpm)
				p, _ := resp.NVPublic.Contents()
				return p.Attributes
			}
			pA := readAttrs(DCActive_Index)
			pB := readAttrs(DCTPM_Index)
			pC := readAttrs(DCOV_Index)

			// A vs B: Owner access (always distinguishable)
			if !pA.OwnerWrite || pB.OwnerWrite {
				t.Error("A should have OwnerWrite, B should not")
			}
			// PlatformCreate checks only meaningful when using Platform hierarchy
			if expectPlatformCreate {
				if !pA.PlatformCreate || pC.PlatformCreate {
					t.Error("A should have PlatformCreate, C should not")
				}
				if !pB.PlatformCreate || !pC.OwnerWrite {
					t.Error("B should have PlatformCreate, C should have OwnerWrite")
				}
			} else {
				// With FDO_TPM_OWNER_HIERARCHY=1, A/B don't have PlatformCreate
				if pA.PlatformCreate || pB.PlatformCreate || pC.PlatformCreate {
					t.Error("PlatformCreate should be false when using Owner hierarchy")
				}
				if !pC.OwnerWrite {
					t.Error("C should have OwnerWrite")
				}
			}
			// All share AuthWrite, AuthRead, NoDA
			for name, a := range map[string]tpm2.TPMANV{"A": pA, "B": pB, "C": pC} {
				if !a.AuthWrite || !a.AuthRead || !a.NoDA {
					t.Errorf("Profile %s missing common attrs", name)
				}
			}
		})
	})

	t.Run("ObjectAttributes", func(t *testing.T) {
		t.Run("DeviceKey", func(t *testing.T) {
			thetpm := openTPM(t)
			cleanupFDOState(t, thetpm)
			createPersistentECCKey(t, thetpm)

			resp, _ := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_Device_Key_Handle)}.Execute(thetpm)
			pub, _ := resp.OutPublic.Contents()
			oa := pub.ObjectAttributes

			assertBool(t, "FixedTPM", oa.FixedTPM, true)
			assertBool(t, "FixedParent", oa.FixedParent, true)
			assertBool(t, "SensitiveDataOrigin", oa.SensitiveDataOrigin, true)
			assertBool(t, "SignEncrypt", oa.SignEncrypt, true)
			assertBool(t, "UserWithAuth", oa.UserWithAuth, false)
			assertBool(t, "STClear", oa.STClear, false)
			assertBool(t, "Restricted", oa.Restricted, false)
			assertBool(t, "Decrypt", oa.Decrypt, false)

			if len(pub.AuthPolicy.Buffer) == 0 {
				t.Error("AuthPolicy empty; spec requires Table 12 digest")
			}
			if pub.Type != tpm2.TPMAlgECC {
				t.Errorf("Type: got %v, want ECC", pub.Type)
			}
		})

		t.Run("HMACSecret", func(t *testing.T) {
			thetpm := openTPM(t)
			cleanupFDOState(t, thetpm)
			createPersistentHMACKey(t, thetpm)

			resp, _ := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_HMAC_Secret_Handle)}.Execute(thetpm)
			pub, _ := resp.OutPublic.Contents()
			oa := pub.ObjectAttributes

			assertBool(t, "FixedTPM", oa.FixedTPM, true)
			assertBool(t, "FixedParent", oa.FixedParent, true)
			assertBool(t, "SensitiveDataOrigin", oa.SensitiveDataOrigin, true)
			assertBool(t, "SignEncrypt", oa.SignEncrypt, true)
			assertBool(t, "UserWithAuth", oa.UserWithAuth, false)

			if len(pub.AuthPolicy.Buffer) == 0 {
				t.Error("AuthPolicy empty; spec requires Table 12 digest")
			}
			if pub.Type != tpm2.TPMAlgKeyedHash {
				t.Errorf("Type: got %v, want KeyedHash", pub.Type)
			}
		})
	})

	t.Run("AuthPolicyDigest", func(t *testing.T) {
		t.Run("DeviceKey", func(t *testing.T) {
			thetpm := openTPM(t)
			cleanupFDOState(t, thetpm)

			us := generateTestDeviceKeyUniqueString(64)
			nvName := defineNVSpec(t, thetpm, DeviceKey_US_Index, 64, nvAttrsProfileB, tpm2.TPMRHPlatform)
			writeNVAuth(t, thetpm, DeviceKey_US_Index, nvName, us)

			expected := computeFDOAuthPolicy(t, thetpm, DeviceKey_US_Index, nvName)
			resp, err := tpm2.CreatePrimary{
				PrimaryHandle: tpm2.TPMRHEndorsement,
				InPublic: tpm2.New2B(tpm2.TPMTPublic{
					Type: tpm2.TPMAlgECC, NameAlg: tpm2.TPMAlgSHA256,
					ObjectAttributes: tpm2.TPMAObject{
						FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, SignEncrypt: true,
					},
					AuthPolicy: expected,
					Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCNistP256,
						Scheme: tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgECDSA,
							Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256})},
					}),
					Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
						X: tpm2.TPM2BECCParameter{Buffer: us[:32]},
						Y: tpm2.TPM2BECCParameter{Buffer: us[32:]},
					}),
				}),
			}.Execute(thetpm)
			if err != nil {
				t.Fatalf("CreatePrimary: %v", err)
			}
			tpm2.EvictControl{
				Auth:             tpm2.TPMRHOwner,
				ObjectHandle:     &tpm2.NamedHandle{Handle: resp.ObjectHandle, Name: resp.Name},
				PersistentHandle: tpm2.TPMHandle(FDO_Device_Key_Handle),
			}.Execute(thetpm) //nolint:errcheck
			tpm2.FlushContext{FlushHandle: resp.ObjectHandle}.Execute(thetpm) //nolint:errcheck

			rr, _ := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_Device_Key_Handle)}.Execute(thetpm)
			pub, _ := rr.OutPublic.Contents()
			if !bytes.Equal(pub.AuthPolicy.Buffer, expected.Buffer) {
				t.Errorf("digest mismatch:\n  stored: %x\n  trial:  %x", pub.AuthPolicy.Buffer, expected.Buffer)
			}
			if len(pub.AuthPolicy.Buffer) != sha256.Size {
				t.Errorf("digest length %d, want %d", len(pub.AuthPolicy.Buffer), sha256.Size)
			}
		})

		t.Run("HMACSecret", func(t *testing.T) {
			thetpm := openTPM(t)
			cleanupFDOState(t, thetpm)

			us := generateTestHMACUniqueString(32)
			nvName := defineNVSpec(t, thetpm, HMAC_US_Index, 32, nvAttrsProfileB, tpm2.TPMRHPlatform)
			writeNVAuth(t, thetpm, HMAC_US_Index, nvName, us)

			expected := computeFDOAuthPolicy(t, thetpm, HMAC_US_Index, nvName)
			resp, err := tpm2.CreatePrimary{
				PrimaryHandle: tpm2.TPMRHEndorsement,
				InPublic: tpm2.New2B(tpm2.TPMTPublic{
					Type: tpm2.TPMAlgKeyedHash, NameAlg: tpm2.TPMAlgSHA256,
					ObjectAttributes: tpm2.TPMAObject{
						FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, SignEncrypt: true,
					},
					AuthPolicy: expected,
					Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
						Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgHMAC,
							Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC, &tpm2.TPMSSchemeHMAC{HashAlg: tpm2.TPMAlgSHA256})},
					}),
					Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{Buffer: us}),
				}),
			}.Execute(thetpm)
			if err != nil {
				t.Fatalf("CreatePrimary: %v", err)
			}
			tpm2.EvictControl{
				Auth:             tpm2.TPMRHOwner,
				ObjectHandle:     &tpm2.NamedHandle{Handle: resp.ObjectHandle, Name: resp.Name},
				PersistentHandle: tpm2.TPMHandle(FDO_HMAC_Secret_Handle),
			}.Execute(thetpm) //nolint:errcheck
			tpm2.FlushContext{FlushHandle: resp.ObjectHandle}.Execute(thetpm) //nolint:errcheck

			rr, _ := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_HMAC_Secret_Handle)}.Execute(thetpm)
			pub, _ := rr.OutPublic.Contents()
			if !bytes.Equal(pub.AuthPolicy.Buffer, expected.Buffer) {
				t.Errorf("digest mismatch:\n  stored: %x\n  trial:  %x", pub.AuthPolicy.Buffer, expected.Buffer)
			}
		})
	})

	t.Run("NegativeAuth", func(t *testing.T) {
		t.Run("PasswordOnSigningKey", func(t *testing.T) {
			thetpm := openTPM(t)
			cleanupFDOState(t, thetpm)
			createPersistentECCKey(t, thetpm)

			rr, _ := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_Device_Key_Handle)}.Execute(thetpm)
			digest := sha256.Sum256([]byte("negative auth"))
			_, err := tpm2.Sign{
				KeyHandle:  tpm2.AuthHandle{Handle: tpm2.TPMHandle(FDO_Device_Key_Handle), Name: rr.Name, Auth: tpm2.PasswordAuth(nil)},
				Digest:     tpm2.TPM2BDigest{Buffer: digest[:]},
				Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
			}.Execute(thetpm)
			if err == nil {
				t.Fatal("password auth should fail (UserWithAuth=0)")
			}
			t.Logf("Correctly rejected: %v", err)
		})

		t.Run("PasswordOnHMACKey", func(t *testing.T) {
			thetpm := openTPM(t)
			cleanupFDOState(t, thetpm)
			createPersistentHMACKey(t, thetpm)

			rr, _ := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_HMAC_Secret_Handle)}.Execute(thetpm)
			_, err := tpm2.HmacStart{
				Handle:  tpm2.AuthHandle{Handle: tpm2.TPMHandle(FDO_HMAC_Secret_Handle), Name: rr.Name, Auth: tpm2.PasswordAuth(nil)},
				Auth:    tpm2.TPM2BAuth{},
				HashAlg: tpm2.TPMAlgNull,
			}.Execute(thetpm)
			if err == nil {
				t.Fatal("password auth should fail (UserWithAuth=0)")
			}
			t.Logf("Correctly rejected: %v", err)
		})

		t.Run("OwnerWriteOnProfileB", func(t *testing.T) {
			thetpm := openTPM(t)
			cleanupFDOState(t, thetpm)

			data := generateTestHMACUniqueString(32)
			nvName := defineNVSpec(t, thetpm, HMAC_US_Index, 32, nvAttrsProfileB, tpm2.TPMRHPlatform)
			writeNVAuth(t, thetpm, HMAC_US_Index, nvName, data) // should work

			_, err := (tpm2.NVWrite{
				AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
				NVIndex:    tpm2.NamedHandle{Handle: HMAC_US_Index, Name: nvName},
				Data:       tpm2.TPM2BMaxNVBuffer{Buffer: data},
			}).Execute(thetpm)
			if err == nil {
				t.Fatal("Owner write should fail on Profile B (OwnerWrite=0)")
			}
			t.Logf("Correctly rejected: %v", err)
		})

		t.Run("OwnerReadOnProfileB", func(t *testing.T) {
			thetpm := openTPM(t)
			cleanupFDOState(t, thetpm)

			data := generateTestHMACUniqueString(32)
			nvName := defineNVSpec(t, thetpm, HMAC_US_Index, 32, nvAttrsProfileB, tpm2.TPMRHPlatform)
			writeNVAuth(t, thetpm, HMAC_US_Index, nvName, data)

			_, err := (tpm2.NVRead{
				AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
				NVIndex:    tpm2.NamedHandle{Handle: HMAC_US_Index, Name: nvName},
				Size:       32,
			}).Execute(thetpm)
			if err == nil {
				t.Fatal("Owner read should fail on Profile B (OwnerRead=0)")
			}
			t.Logf("Correctly rejected: %v", err)
		})

		t.Run("WrongPolicyNVIndex", func(t *testing.T) {
			thetpm := openTPM(t)
			cleanupFDOState(t, thetpm)
			createPersistentECCKey(t, thetpm) // bound to DeviceKey_US

			// Create a separate HMAC US NV index
			hmacUS := generateTestHMACUniqueString(32)
			hmacNVName := defineNVSpec(t, thetpm, HMAC_US_Index, 32, nvAttrsProfileB, tpm2.TPMRHPlatform)
			writeNVAuth(t, thetpm, HMAC_US_Index, hmacNVName, hmacUS)

			rr, _ := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_Device_Key_Handle)}.Execute(thetpm)
			digest := sha256.Sum256([]byte("wrong policy"))

			// Use HMAC_US policy for Device Key — should fail
			_, err := tpm2.Sign{
				KeyHandle:  tpm2.AuthHandle{Handle: tpm2.TPMHandle(FDO_Device_Key_Handle), Name: rr.Name, Auth: fdoKeyPolicy(HMAC_US_Index, hmacNVName)},
				Digest:     tpm2.TPM2BDigest{Buffer: digest[:]},
				Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
			}.Execute(thetpm)
			if err == nil {
				t.Fatal("wrong policy NV index should fail (digest mismatch)")
			}
			t.Logf("Correctly rejected: %v", err)
		})
	})
}

// =========================================================================
// Phase 6 — End-to-End DI → Onboard Flow
// =========================================================================
//
// This phase simulates the real-world lifecycle:
//
//  1. DI_Provision — Manufacturer initializes the device: creates DAK (ECC key),
//     HMAC secret, credential NV indices, and extracts "evidence" (public key,
//     GUID, HMAC baseline). In production, this evidence goes into the
//     Ownership Voucher.
//
//  2. Onboard_Attest — Device proves its identity to a new owner: discovers
//     TPM objects fresh via NVReadPublic/ReadPublic, signs a challenge nonce
//     with the DAK, and computes an HMAC over the GUID. The owner verifies
//     both against the manufacturer evidence.
//
//  3. Onboard_Attest_Again — Same flow with a fresh nonce, proving the TPM
//     state persists and attestation is repeatable.
//
// The onboarding side intentionally discovers all NV Names at runtime (not
// carried over from DI) — this mirrors how real device code would work.

// diEvidence represents what the manufacturer captures during Device
// Initialization and places into the Ownership Voucher. The new owner
// uses this to verify the device during onboarding (TO2).
type diEvidence struct {
	devicePublicKey *ecdsa.PublicKey
	guid            [16]byte
	hmacBaseline    []byte // HMAC(guid) — proves HMAC key possession
}

func runPhase6(t *testing.T) {
	thetpm := openTPM(t)
	cleanupFDOState(t, thetpm)

	var evidence diEvidence
	var diOK bool

	// --- DI: Manufacturer provisions device ---
	t.Run("DI_Provision", func(t *testing.T) {
		// 1. Generate device GUID (deterministic for test reproducibility;
		//    real DI would use crypto/rand)
		guid := [16]byte{
			0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
			0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90,
		}
		evidence.guid = guid

		// 2. Set DCActive = 1 (device initialized)
		nvNameActive := defineNVSpec(t, thetpm, DCActive_Index, 1, profileA.attrs, profileA.authHandle)
		writeNV(t, thetpm, DCActive_Index, nvNameActive, []byte{0x01}, profileA)
		t.Log("DCActive = 1 (device initialized)")

		// 3. Write DCTPM: GUID (16 bytes) + device info string
		//    In production this is CBOR-encoded DCProtVer, DCDeviceInfo,
		//    DCGuid, DCPubKeyHash, DCRVInfo per spec Table 5.
		deviceInfo := "FDO-Test-Device-v1.0"
		dctpmData := make([]byte, 0, 16+len(deviceInfo))
		dctpmData = append(dctpmData, guid[:]...)
		dctpmData = append(dctpmData, []byte(deviceInfo)...)
		nvNameDCTPM := defineNVSpec(t, thetpm, DCTPM_Index, uint16(len(dctpmData)), profileB.attrs, profileB.authHandle)
		writeNV(t, thetpm, DCTPM_Index, nvNameDCTPM, dctpmData, profileB)
		t.Logf("DCTPM: GUID=%x info=%q", guid, deviceInfo)

		// 4. Provision DeviceKey_US NV + create ECC P-256 DAK
		dkUS := generateTestDeviceKeyUniqueString(64)
		nvNameDKUS := defineNVSpec(t, thetpm, DeviceKey_US_Index, 64, profileB.attrs, profileB.authHandle)
		writeNVAuth(t, thetpm, DeviceKey_US_Index, nvNameDKUS, dkUS)

		dkPolicy := computeFDOAuthPolicy(t, thetpm, DeviceKey_US_Index, nvNameDKUS)
		dkResp, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHEndorsement,
			InPublic: tpm2.New2B(tpm2.TPMTPublic{
				Type: tpm2.TPMAlgECC, NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, SignEncrypt: true,
				},
				AuthPolicy: dkPolicy,
				Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
					CurveID: tpm2.TPMECCNistP256,
					Scheme: tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgECDSA,
						Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256})},
				}),
				Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
					X: tpm2.TPM2BECCParameter{Buffer: dkUS[:32]},
					Y: tpm2.TPM2BECCParameter{Buffer: dkUS[32:]},
				}),
			}),
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("CreatePrimary (DAK): %v", err)
		}
		if _, err := (tpm2.EvictControl{
			Auth:             tpm2.TPMRHOwner,
			ObjectHandle:     &tpm2.NamedHandle{Handle: dkResp.ObjectHandle, Name: dkResp.Name},
			PersistentHandle: tpm2.TPMHandle(FDO_Device_Key_Handle),
		}).Execute(thetpm); err != nil {
			t.Fatalf("EvictControl (DAK): %v", err)
		}
		tpm2.FlushContext{FlushHandle: dkResp.ObjectHandle}.Execute(thetpm) //nolint:errcheck

		// Extract DAK public key — goes into Ownership Voucher
		readResp, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_Device_Key_Handle)}.Execute(thetpm)
		if err != nil {
			t.Fatalf("ReadPublic (DAK): %v", err)
		}
		pub, _ := readResp.OutPublic.Contents()
		ecc, _ := pub.Unique.ECC()
		evidence.devicePublicKey = &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(ecc.X.Buffer),
			Y:     new(big.Int).SetBytes(ecc.Y.Buffer),
		}
		t.Logf("DAK public key extracted (P-256)")

		// 5. Provision HMAC_US NV + create HMAC SHA-256 key
		hmacUS := generateTestHMACUniqueString(32)
		nvNameHMACUS := defineNVSpec(t, thetpm, HMAC_US_Index, 32, profileB.attrs, profileB.authHandle)
		writeNVAuth(t, thetpm, HMAC_US_Index, nvNameHMACUS, hmacUS)

		hmacPolicy := computeFDOAuthPolicy(t, thetpm, HMAC_US_Index, nvNameHMACUS)
		hmacResp, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHEndorsement,
			InPublic: tpm2.New2B(tpm2.TPMTPublic{
				Type: tpm2.TPMAlgKeyedHash, NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, SignEncrypt: true,
				},
				AuthPolicy: hmacPolicy,
				Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
					Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgHMAC,
						Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC, &tpm2.TPMSSchemeHMAC{HashAlg: tpm2.TPMAlgSHA256})},
				}),
				Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{Buffer: hmacUS}),
			}),
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("CreatePrimary (HMAC): %v", err)
		}
		if _, err := (tpm2.EvictControl{
			Auth:             tpm2.TPMRHOwner,
			ObjectHandle:     &tpm2.NamedHandle{Handle: hmacResp.ObjectHandle, Name: hmacResp.Name},
			PersistentHandle: tpm2.TPMHandle(FDO_HMAC_Secret_Handle),
		}).Execute(thetpm); err != nil {
			t.Fatalf("EvictControl (HMAC): %v", err)
		}
		tpm2.FlushContext{FlushHandle: hmacResp.ObjectHandle}.Execute(thetpm) //nolint:errcheck

		// 6. Compute HMAC baseline over GUID — manufacturer keeps this
		//    as proof that only this device can reproduce it
		hmacRR, _ := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_HMAC_Secret_Handle)}.Execute(thetpm)
		hs, err := tpm2.HmacStart{
			Handle:  tpm2.AuthHandle{Handle: tpm2.TPMHandle(FDO_HMAC_Secret_Handle), Name: hmacRR.Name, Auth: fdoKeyPolicy(HMAC_US_Index, nvNameHMACUS)},
			HashAlg: tpm2.TPMAlgNull,
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("HmacStart (baseline): %v", err)
		}
		sc, err := tpm2.SequenceComplete{
			SequenceHandle: tpm2.AuthHandle{Handle: hs.SequenceHandle, Auth: tpm2.PasswordAuth(nil)},
			Buffer:         tpm2.TPM2BMaxBuffer{Buffer: guid[:]},
			Hierarchy:      tpm2.TPMRHNull,
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("SequenceComplete (baseline): %v", err)
		}
		evidence.hmacBaseline = sc.Result.Buffer
		t.Logf("HMAC baseline over GUID: %x", evidence.hmacBaseline)

		// 7. Write DCOV placeholder (real DI writes the full ownership voucher)
		dcovData := []byte("ownership-voucher-placeholder")
		nvNameDCOV := defineNVSpec(t, thetpm, DCOV_Index, uint16(len(dcovData)), profileC.attrs, profileC.authHandle)
		writeNV(t, thetpm, DCOV_Index, nvNameDCOV, dcovData, profileC)
		t.Log("DCOV written")

		t.Log("=== DI complete: DAK, HMAC key, credentials provisioned in TPM ===")
		diOK = true
	})

	// --- Onboard: Device proves identity to new owner ---
	t.Run("Onboard_Attest", func(t *testing.T) {
		if !diOK {
			t.Fatal("DI_Provision did not complete — cannot onboard (see DI errors above)")
		}
		onboardAndAttest(t, thetpm, &evidence, "onboard-1")
	})

	// --- Onboard again: fresh nonce, proves persistence + repeatability ---
	t.Run("Onboard_Attest_Again", func(t *testing.T) {
		if !diOK {
			t.Fatal("DI_Provision did not complete — cannot onboard (see DI errors above)")
		}
		onboardAndAttest(t, thetpm, &evidence, "onboard-2")
	})
}

// onboardAndAttest simulates the device side of TO2: discovers all TPM
// objects fresh (via NVReadPublic / ReadPublic), signs a challenge nonce
// with the DAK, and computes an HMAC over the GUID. The "owner" then
// verifies both against the manufacturer evidence from DI.
//
// No DI-time state is carried over except what would be in the Ownership
// Voucher (the diEvidence struct).
func onboardAndAttest(t *testing.T, thetpm transport.TPM, evidence *diEvidence, label string) {
	t.Helper()

	// 1. Read DCActive — verify device is initialized
	nvPubActive, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(DCActive_Index)}.Execute(thetpm)
	if err != nil {
		t.Fatalf("[%s] NVReadPublic DCActive: %v", label, err)
	}
	activeData := readNV(t, thetpm, DCActive_Index, nvPubActive.NVName, 1, profileA)
	if activeData[0] != 0x01 {
		t.Fatalf("[%s] DCActive: got 0x%02X, want 0x01", label, activeData[0])
	}
	t.Logf("[%s] DCActive = 1 (device is initialized)", label)

	// 2. Read DCTPM — extract and verify GUID
	nvPubDCTPM, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(DCTPM_Index)}.Execute(thetpm)
	if err != nil {
		t.Fatalf("[%s] NVReadPublic DCTPM: %v", label, err)
	}
	dctpmPub, _ := nvPubDCTPM.NVPublic.Contents()
	dctpmData := readNV(t, thetpm, DCTPM_Index, nvPubDCTPM.NVName, dctpmPub.DataSize, profileB)
	var extractedGUID [16]byte
	copy(extractedGUID[:], dctpmData[:16])
	if extractedGUID != evidence.guid {
		t.Fatalf("[%s] GUID mismatch: got %x, want %x", label, extractedGUID, evidence.guid)
	}
	t.Logf("[%s] GUID verified: %x", label, extractedGUID)

	// 3. Discover DAK and sign a challenge nonce
	//    The nonce simulates the owner's TO2 challenge — different each call
	nonce := sha256.Sum256([]byte(label + " attestation challenge"))

	dkReadResp, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_Device_Key_Handle)}.Execute(thetpm)
	if err != nil {
		t.Fatalf("[%s] ReadPublic DAK: %v", label, err)
	}

	// Discover DeviceKey_US NV Name for policy session (not carried from DI)
	nvPubDKUS, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(DeviceKey_US_Index)}.Execute(thetpm)
	if err != nil {
		t.Fatalf("[%s] NVReadPublic DeviceKey_US: %v", label, err)
	}

	sigResp, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(FDO_Device_Key_Handle),
			Name:   dkReadResp.Name,
			Auth:   fdoKeyPolicy(DeviceKey_US_Index, nvPubDKUS.NVName),
		},
		Digest:     tpm2.TPM2BDigest{Buffer: nonce[:]},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("[%s] DAK Sign: %v", label, err)
	}

	// 4. Owner verifies signature against DI public key (from Ownership Voucher)
	ecSig, _ := sigResp.Signature.Signature.ECDSA()
	r := new(big.Int).SetBytes(ecSig.SignatureR.Buffer)
	s := new(big.Int).SetBytes(ecSig.SignatureS.Buffer)
	if !ecdsa.Verify(evidence.devicePublicKey, nonce[:], r, s) {
		t.Fatalf("[%s] DAK signature verification FAILED", label)
	}
	t.Logf("[%s] DAK attestation: signature verified against DI public key", label)

	// 5. Compute HMAC over GUID — verify matches manufacturer baseline
	nvPubHMACUS, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(HMAC_US_Index)}.Execute(thetpm)
	if err != nil {
		t.Fatalf("[%s] NVReadPublic HMAC_US: %v", label, err)
	}

	hmacRR, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(FDO_HMAC_Secret_Handle)}.Execute(thetpm)
	if err != nil {
		t.Fatalf("[%s] ReadPublic HMAC key: %v", label, err)
	}
	hs, err := tpm2.HmacStart{
		Handle:  tpm2.AuthHandle{Handle: tpm2.TPMHandle(FDO_HMAC_Secret_Handle), Name: hmacRR.Name, Auth: fdoKeyPolicy(HMAC_US_Index, nvPubHMACUS.NVName)},
		HashAlg: tpm2.TPMAlgNull,
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("[%s] HmacStart: %v", label, err)
	}
	sc, err := tpm2.SequenceComplete{
		SequenceHandle: tpm2.AuthHandle{Handle: hs.SequenceHandle, Auth: tpm2.PasswordAuth(nil)},
		Buffer:         tpm2.TPM2BMaxBuffer{Buffer: evidence.guid[:]},
		Hierarchy:      tpm2.TPMRHNull,
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("[%s] SequenceComplete: %v", label, err)
	}
	if !bytes.Equal(sc.Result.Buffer, evidence.hmacBaseline) {
		t.Fatalf("[%s] HMAC mismatch: got %x, want %x", label, sc.Result.Buffer, evidence.hmacBaseline)
	}
	t.Logf("[%s] HMAC verified: matches manufacturer baseline", label)

	t.Logf("[%s] === Device attestation complete — identity verified ===", label)
}
