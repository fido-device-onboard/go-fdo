//go:build spec_compliance_test
// +build spec_compliance_test

// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

// Package tpm_test contains FDO TPM specification compliance tests per
// "Securing FDO Credentials in the TPM" (securing-fdo-in-tpm.bs): one DCTPM
// NV index (0x01D10001) holding a CBOR structure, plus a persistent Device
// key and HMAC key whose handles DCTPM records.
//
// The tests drive the library functions the credential store
// (cred/tpm_store.go) uses for DI, load and TO2 updates — not local copies
// of templates — and check the results against the spec tables.
//
// Run (hardware TPM, Linux userspace):
//
//	cd tpm && go test -v -tags=spec_compliance_test -run TestSpecCompliance -count=1
//
// Configuration via environment variables:
//
//	FDO_TPM=sim                     Use the software simulator (default: /dev/tpmrm0)
//	FDO_TPM_DEVICE=<path>           TPM device or swtpm Unix socket (e.g. swtpm socket --server type=unixio,...)
//	FDO_TPM_P384=0                  Skip P-384/SHA-384 cases
//	FDO_TPM_PLATFORM_HIERARCHY=1    Create DCTPM under the Platform hierarchy
//	                                (PLATFORMCREATE; falls back to Owner if locked)
//	FDO_TPM_OWNER_HIERARCHY=1       Used by the Phase 9 tests (phase9_integration_test.go)
//
// WARNING: on a hardware TPM these tests remove any existing FDO state
// (DCTPM index and the FDO persistent handles) first.
package tpm_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/simulator"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
	tpmlib "github.com/fido-device-onboard/go-fdo/tpm"
)

// =========================================================================
// Configuration helpers (also used by phase9_integration_test.go)
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

	// FDO_TPM_DEVICE: a TPM character device or a swtpm Unix socket, opened
	// the way the library does it (tpm.DefaultOpen).
	if path := os.Getenv("FDO_TPM_DEVICE"); path != "" {
		dev, err := tpmlib.DefaultOpen()
		if err != nil {
			t.Fatalf("opening FDO_TPM_DEVICE=%s: %v", path, err)
		}
		t.Cleanup(func() { _ = dev.Close() })
		t.Logf("TPM backend: %s", path)
		return dev
	}

	dev, err := linuxtpm.Open("/dev/tpmrm0")
	if err == nil {
		t.Cleanup(func() { _ = dev.Close() })
		t.Log("TPM backend: /dev/tpmrm0")
		return dev
	}
	dev, err2 := linuxtpm.Open("/dev/tpm0")
	if err2 == nil {
		t.Cleanup(func() { _ = dev.Close() })
		t.Log("TPM backend: /dev/tpm0")
		return dev
	}
	t.Fatalf("No hardware TPM available (tpmrm0: %v; tpm0: %v). "+
		"Set FDO_TPM=sim to use the software simulator.", err, err2)
	return nil // unreachable
}

// ownerHierarchyFallback is used by the Phase 9 tests.
func ownerHierarchyFallback() bool {
	return os.Getenv("FDO_TPM_OWNER_HIERARCHY") == "1"
}

// usePlatformDCTPM mirrors cred/tpm_store.go: DCTPM is created under the
// Owner hierarchy unless FDO_TPM_PLATFORM_HIERARCHY=1.
func usePlatformDCTPM() bool {
	return os.Getenv("FDO_TPM_PLATFORM_HIERARCHY") == "1"
}

// =========================================================================
// DCTPM structure (spec CDDL) — same encoding as cred/tpm_store.go
// =========================================================================

type specDCTPM struct {
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
	MinFirmwareRev  uint64                     `cbor:"10,keyasint"`
}

func mustRvInfo(t *testing.T, host string) [][]protocol.RvInstruction {
	t.Helper()
	dns, err := cbor.Marshal(host)
	if err != nil {
		t.Fatal(err)
	}
	return [][]protocol.RvInstruction{{{Variable: protocol.RVDns, Value: dns}}}
}

// =========================================================================
// Device key / HMAC key cases (spec Tables 10-12)
// =========================================================================

type keyCase struct {
	name    string
	curve   tpm2.TPMECCCurve
	nameAlg tpm2.TPMAlgID
	hash    crypto.Hash
	keyType protocol.KeyType
	child   bool // true: child of the deterministic SRK; false: primary with unique string
}

// supportsP384 reports whether the TPM lists NIST P-384 (TPM_CAP_ECC_CURVES).
func supportsP384(t *testing.T, thetpm transport.TPM) bool {
	t.Helper()
	resp, err := tpm2.GetCapability{
		Capability: tpm2.TPMCapECCCurves, Property: 0, PropertyCount: 64,
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("GetCapability(ECC_CURVES): %v", err)
	}
	curves, err := resp.CapabilityData.Data.ECCCurves()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range curves.ECCCurves {
		if c == tpm2.TPMECCNistP384 {
			return true
		}
	}
	return false
}

func keyCases(t *testing.T, thetpm transport.TPM) []keyCase {
	cases := []keyCase{
		{"P256_Child", tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256, crypto.SHA256, protocol.Secp256r1KeyType, true},
		{"P256_Primary", tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256, crypto.SHA256, protocol.Secp256r1KeyType, false},
	}
	switch {
	case os.Getenv("FDO_TPM_P384") == "0":
		t.Log("P-384 cases skipped (FDO_TPM_P384=0)")
	case !supportsP384(t, thetpm):
		t.Log("P-384 cases skipped: TPM does not list NIST P-384")
	default:
		cases = append(cases,
			keyCase{"P384_Child", tpm2.TPMECCNistP384, tpm2.TPMAlgSHA384, crypto.SHA384, protocol.Secp384r1KeyType, true},
			keyCase{"P384_Primary", tpm2.TPMECCNistP384, tpm2.TPMAlgSHA384, crypto.SHA384, protocol.Secp384r1KeyType, false},
		)
	}
	return cases
}

// provisionKeys creates and persists the Device key and HMAC key the way
// cred/tpm_store.go NewDI does, after removing any previous FDO state.
func provisionKeys(t *testing.T, thetpm transport.TPM, kc keyCase) crypto.PublicKey {
	t.Helper()
	tpmlib.CleanupFDOState(thetpm)
	t.Cleanup(func() { tpmlib.CleanupFDOState(thetpm) })

	var (
		dak, hk *tpm2.NamedHandle
		pub     crypto.PublicKey
		err     error
	)
	if kc.child {
		srk, err := tpmlib.CreateSRK(thetpm)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = (tpm2.FlushContext{FlushHandle: srk.Handle}).Execute(thetpm) }()
		if dak, pub, err = tpmlib.CreateChildECKey(thetpm, *srk, kc.curve, kc.nameAlg); err != nil {
			t.Fatalf("CreateChildECKey: %v", err)
		}
		if err := tpmlib.PersistKey(thetpm, *dak, tpmlib.DAKHandle); err != nil {
			t.Fatal(err)
		}
		if hk, err = tpmlib.CreateChildHMACKey(thetpm, *srk, kc.nameAlg); err != nil {
			t.Fatalf("CreateChildHMACKey: %v", err)
		}
	} else {
		coord := 32
		if kc.curve == tpm2.TPMECCNistP384 {
			coord = 48
		}
		dkUS := make([]byte, 2*coord)
		hmacUS := make([]byte, coord)
		_, _ = rand.Read(dkUS)
		_, _ = rand.Read(hmacUS)
		if dak, pub, err = tpmlib.GenerateSpecECKey(thetpm, kc.curve, kc.nameAlg, dkUS); err != nil {
			t.Fatalf("GenerateSpecECKey: %v", err)
		}
		if err := tpmlib.PersistKey(thetpm, *dak, tpmlib.DAKHandle); err != nil {
			t.Fatal(err)
		}
		if hk, err = tpmlib.GenerateSpecHMACKey(thetpm, kc.nameAlg, hmacUS); err != nil {
			t.Fatalf("GenerateSpecHMACKey: %v", err)
		}
	}
	if err := tpmlib.PersistKey(thetpm, *hk, tpmlib.HMACKeyHandle); err != nil {
		t.Fatal(err)
	}
	return pub
}

func persistentPublic(t *testing.T, thetpm transport.TPM, handle uint32) (*tpm2.TPMTPublic, tpm2.TPM2BName) {
	t.Helper()
	rp, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(handle)}.Execute(thetpm)
	if err != nil {
		t.Fatalf("ReadPublic 0x%08X: %v", handle, err)
	}
	pub, err := rp.OutPublic.Contents()
	if err != nil {
		t.Fatal(err)
	}
	return pub, rp.Name
}

// assertKeyAttrs checks spec Table 11.
func assertKeyAttrs(t *testing.T, which string, a tpm2.TPMAObject) {
	t.Helper()
	for _, c := range []struct {
		name      string
		got, want bool
	}{
		{"fixedTPM", a.FixedTPM, true},
		{"fixedParent", a.FixedParent, true},
		{"sensitiveDataOrigin", a.SensitiveDataOrigin, true},
		{"userWithAuth", a.UserWithAuth, true},
		{"adminWithPolicy", a.AdminWithPolicy, true},
		{"noDA", a.NoDA, true},
		{"sign", a.SignEncrypt, true},
		{"restricted", a.Restricted, false},
		{"decrypt", a.Decrypt, false},
	} {
		if c.got != c.want {
			t.Errorf("%s %s = %v, want %v (spec Table 11)", which, c.name, c.got, c.want)
		}
	}
}

// =========================================================================
// TestSpecCompliance
// =========================================================================

func TestSpecCompliance(t *testing.T) {
	t.Run("Constants", testConstants)
	t.Run("DCTPM_Index", testDCTPMIndex)
	t.Run("Keys", testKeys)
	t.Run("Lifecycle", testLifecycle)
}

// testConstants: spec Tables 5 and 6, and the DCTPM magic.
func testConstants(t *testing.T) {
	if tpmlib.DCTPMIndex != 0x01D10001 {
		t.Errorf("DCTPMIndex = 0x%08X, want 0x01D10001", tpmlib.DCTPMIndex)
	}
	if tpmlib.DCTPMMagic != 0x46444F31 {
		t.Errorf("DCTPMMagic = 0x%08X, want 0x46444F31 (\"FDO1\")", tpmlib.DCTPMMagic)
	}
	if tpmlib.DAKHandle != 0x81020002 || tpmlib.HMACKeyHandle != 0x81020003 {
		t.Errorf("default handles DAK 0x%08X HMAC 0x%08X, want 0x81020002 / 0x81020003",
			tpmlib.DAKHandle, tpmlib.HMACKeyHandle)
	}
	if tpmlib.DCTPMDefaultSize < 384 {
		t.Errorf("DCTPMDefaultSize %d below the spec minimum of 384", tpmlib.DCTPMDefaultSize)
	}
}

// testDCTPMIndex: spec Table 9 attributes, sizing, single-item decoding with
// trailing bytes, and in-place updates.
func testDCTPMIndex(t *testing.T) {
	thetpm := openTPM(t)
	tpmlib.CleanupFDOState(thetpm)
	t.Cleanup(func() { tpmlib.CleanupFDOState(thetpm) })

	first, err := cbor.Marshal(specDCTPM{Magic: tpmlib.DCTPMMagic, Active: true, Version: 200, DeviceInfo: "spec-test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tpmlib.WriteDCTPM(thetpm, first, usePlatformDCTPM()); err != nil {
		t.Fatalf("WriteDCTPM: %v", err)
	}

	rp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(tpmlib.DCTPMIndex)}.Execute(thetpm)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := rp.NVPublic.Contents()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Attributes", func(t *testing.T) {
		a := pub.Attributes
		for _, c := range []struct {
			name      string
			got, want bool
		}{
			{"OWNERWRITE", a.OwnerWrite, true},
			{"AUTHWRITE", a.AuthWrite, true},
			{"OWNERREAD", a.OwnerRead, true},
			{"AUTHREAD", a.AuthRead, true},
			{"NO_DA", a.NoDA, true},
			{"WRITE_STCLEAR", a.WriteSTClear, true},
			{"POLICYWRITE", a.PolicyWrite, false},
			{"POLICYREAD", a.PolicyRead, false},
			{"PPWRITE", a.PPWrite, false},
			{"PPREAD", a.PPRead, false},
			{"WRITEDEFINE", a.WriteDefine, false},
			{"GLOBALLOCK", a.GlobalLock, false},
			{"READ_STCLEAR", a.ReadSTClear, false},
		} {
			if c.got != c.want {
				t.Errorf("DCTPM %s = %v, want %v (spec Table 9)", c.name, c.got, c.want)
			}
		}
		if a.NT != tpm2.TPMNTOrdinary {
			t.Errorf("DCTPM TPM_NT = %v, want ordinary", a.NT)
		}
		if !usePlatformDCTPM() && a.PlatformCreate {
			t.Error("DCTPM has PLATFORMCREATE without FDO_TPM_PLATFORM_HIERARCHY=1")
		}
		t.Logf("PLATFORMCREATE=%v (requested %v; falls back to Owner if Platform is locked)",
			a.PlatformCreate, usePlatformDCTPM())
	})

	t.Run("Size", func(t *testing.T) {
		if pub.DataSize < 384 || pub.DataSize != tpmlib.DCTPMDefaultSize {
			t.Errorf("DCTPM size %d, want %d (spec: minimum 384, 512 RECOMMENDED)", pub.DataSize, tpmlib.DCTPMDefaultSize)
		}
		bufMax, err := tpmlib.NVBufferMax(thetpm)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("TPM_PT_NV_BUFFER_MAX = %d", bufMax)
		if int(pub.DataSize) > bufMax {
			t.Logf("note: index larger than one NV_Write; updates write the structure only, without zero padding")
		}
	})

	t.Run("FirstItemOnly", func(t *testing.T) {
		info, err := tpmlib.ReadNVCredentials(thetpm)
		if err != nil {
			t.Fatal(err)
		}
		if len(info.RawDCTPM) != int(pub.DataSize) || len(info.RawDCTPM) <= len(first) {
			t.Fatalf("raw DCTPM %d bytes, index %d, structure %d: expected trailing bytes", len(info.RawDCTPM), pub.DataSize, len(first))
		}
		var got specDCTPM
		if err := tpmlib.DecodeDCTPM(info.RawDCTPM, &got); err != nil {
			t.Fatalf("DecodeDCTPM: %v", err)
		}
		if got.Magic != tpmlib.DCTPMMagic || got.DeviceInfo != "spec-test" {
			t.Fatalf("decoded %+v", got)
		}
		if !bytes.Equal(info.RawDCTPM[:len(first)], first) {
			t.Error("DCTPM structure does not start at offset 0")
		}
		if bytes.ContainsFunc(info.RawDCTPM[len(first):], func(r rune) bool { return r != 0 }) {
			t.Log("note: trailing bytes are not zero (index larger than one NV_Write)")
		}
	})

	t.Run("InPlaceUpdate", func(t *testing.T) {
		longer, err := cbor.Marshal(specDCTPM{Magic: tpmlib.DCTPMMagic, Active: true, Version: 200,
			DeviceInfo: "spec-test", RvInfo: mustRvInfo(t, "rvserver.example.com")})
		if err != nil {
			t.Fatal(err)
		}
		if err := tpmlib.WriteDCTPM(thetpm, longer, usePlatformDCTPM()); err != nil {
			t.Fatalf("WriteDCTPM (update): %v", err)
		}
		rp2, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(tpmlib.DCTPMIndex)}.Execute(thetpm)
		if err != nil {
			t.Fatal(err)
		}
		pub2, _ := rp2.NVPublic.Contents()
		if pub2.DataSize != pub.DataSize || pub2.Attributes.PlatformCreate != pub.Attributes.PlatformCreate {
			t.Errorf("index changed on update: size %d -> %d", pub.DataSize, pub2.DataSize)
		}
		info, err := tpmlib.ReadNVCredentials(thetpm)
		if err != nil {
			t.Fatal(err)
		}
		var got specDCTPM
		if err := tpmlib.DecodeDCTPM(info.RawDCTPM, &got); err != nil {
			t.Fatal(err)
		}
		if len(got.RvInfo) != 1 {
			t.Fatalf("update not visible: %+v", got)
		}
	})

	// Last: the lock lasts until the next TPM2_Startup(CLEAR); cleanup
	// undefines the index (UndefineSpace is not blocked by the write lock).
	t.Run("WriteLock", func(t *testing.T) {
		rp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(tpmlib.DCTPMIndex)}.Execute(thetpm)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := (tpm2.NVWriteLock{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(tpmlib.DCTPMIndex), Name: rp.NVName, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(tpmlib.DCTPMIndex), Name: rp.NVName},
		}).Execute(thetpm); err != nil {
			t.Fatalf("TPM2_NV_WriteLock (empty authValue): %v", err)
		}
		if err := tpmlib.WriteDCTPM(thetpm, first, usePlatformDCTPM()); err == nil {
			t.Fatal("DCTPM update succeeded while write-locked (index replaced instead of written in place)")
		}
	})
}

// testKeys: spec Tables 10-12 for every creation method and curve.
func testKeys(t *testing.T) {
	thetpm := openTPM(t)
	for _, kc := range keyCases(t, thetpm) {
		t.Run(kc.name, func(t *testing.T) {
			provisionKeys(t, thetpm, kc)

			dakPub, dakName := persistentPublic(t, thetpm, tpmlib.DAKHandle)
			hkPub, hkName := persistentPublic(t, thetpm, tpmlib.HMACKeyHandle)

			t.Run("DeviceKey_Template", func(t *testing.T) {
				assertKeyAttrs(t, "Device key", dakPub.ObjectAttributes)
				if dakPub.Type != tpm2.TPMAlgECC || dakPub.NameAlg != kc.nameAlg {
					t.Errorf("Device key type 0x%x nameAlg 0x%x", uint16(dakPub.Type), uint16(dakPub.NameAlg))
				}
				want, _ := tpmlib.DeviceKeyAuthPolicy(kc.nameAlg)
				if !bytes.Equal(dakPub.AuthPolicy.Buffer, want.Buffer) {
					t.Errorf("Device key authPolicy %x, want %x (spec Table 12)", dakPub.AuthPolicy.Buffer, want.Buffer)
				}
				if hex.EncodeToString(want.Buffer) != specDeviceKeyPolicy[kc.nameAlg] {
					t.Error("library policy digest differs from spec Table 12 constant")
				}
			})

			t.Run("HMACKey_Template", func(t *testing.T) {
				assertKeyAttrs(t, "HMAC key", hkPub.ObjectAttributes)
				if hkPub.Type != tpm2.TPMAlgKeyedHash {
					t.Errorf("HMAC key type 0x%x", uint16(hkPub.Type))
				}
				if len(hkPub.AuthPolicy.Buffer) != 0 {
					t.Errorf("HMAC key authPolicy %x, want empty (spec Table 12)", hkPub.AuthPolicy.Buffer)
				}
				if hkPub.NameAlg != kc.nameAlg {
					t.Errorf("HMAC key nameAlg 0x%x, want 0x%x (matches the Device key, Table 10)", uint16(hkPub.NameAlg), uint16(kc.nameAlg))
				}
				kh, err := hkPub.Parameters.KeyedHashDetail()
				if err != nil || kh.Scheme.Scheme != tpm2.TPMAlgHMAC {
					t.Fatalf("HMAC key scheme not TPM_ALG_HMAC (Table 10): %+v %v", kh, err)
				}
				if d, err := kh.Scheme.Details.HMAC(); err != nil || d.HashAlg != kc.nameAlg {
					t.Errorf("HMAC key scheme hash %+v, want 0x%x (matches the Device key, Table 10)", d, uint16(kc.nameAlg))
				}
			})

			t.Run("HMAC_DeviceKeyHash", func(t *testing.T) {
				own := crypto.SHA256
				if kc.nameAlg == tpm2.TPMAlgSHA384 {
					own = crypto.SHA384
				}
				h, err := tpmlib.NewSpecHmac(thetpm, own, tpmlib.HMACKeyHandle)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = h.Write([]byte("fdo"))
				if s := h.Sum(nil); h.Err() != nil || len(s) != own.Size() {
					t.Errorf("HMAC-%v with the persisted key: len %d, %v", own, len(s), h.Err())
				}
				_ = h.Close()
			})

			t.Run("Sign_EmptyAuth", func(t *testing.T) {
				proof, err := tpmlib.ProveDAKPossession(thetpm, nil)
				if err != nil {
					t.Fatalf("ProveDAKPossession: %v", err)
				}
				ec, ok := proof.PublicKey.(*ecdsa.PublicKey)
				if !ok || !ecdsa.VerifyASN1(ec, proof.Challenge[:], proof.Signature) {
					t.Fatal("DAK signature does not verify")
				}
			})

			t.Run("HMAC_EmptyAuth", func(t *testing.T) {
				h1, err := tpmlib.NewSpecHmac(thetpm, crypto.SHA256, tpmlib.HMACKeyHandle)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = h1.Write([]byte("fdo"))
				h2, err := tpmlib.NewSpecHmac(thetpm, crypto.SHA256, tpmlib.HMACKeyHandle)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = h2.Write([]byte("fdo"))
				a, b := h1.Sum(nil), h2.Sum(nil)
				if len(a) != sha256.Size || !bytes.Equal(a, b) {
					t.Fatalf("HMAC not deterministic or wrong size: %x / %x", a, b)
				}
			})

			t.Run("Admin_CertifyOnly", func(t *testing.T) {
				// TPM2_Certify needs a restricted signing key; use a fresh AK.
				srk, err := tpmlib.CreateSRK(thetpm)
				if err != nil {
					t.Fatal(err)
				}
				defer flush(thetpm, srk.Handle)
				ak := createAK(t, thetpm, *srk)
				defer flush(thetpm, ak.Handle)

				certify := func(auth tpm2.Session) error {
					_, err := tpm2.Certify{
						ObjectHandle:   tpm2.AuthHandle{Handle: tpm2.TPMHandle(tpmlib.DAKHandle), Name: dakName, Auth: auth},
						SignHandle:     tpm2.AuthHandle{Handle: ak.Handle, Name: ak.Name, Auth: tpm2.PasswordAuth(nil)},
						QualifyingData: tpm2.TPM2BData{Buffer: []byte("owner-nonce")},
						InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
					}.Execute(thetpm)
					return err
				}
				if certify(tpm2.PasswordAuth(nil)) == nil {
					t.Error("Certify with a password session succeeded; adminWithPolicy requires a policy")
				}
				ps, closePS, err := tpm2.PolicySession(thetpm, kc.nameAlg, 16)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := (tpm2.PolicyCommandCode{PolicySession: ps.Handle(), Code: tpm2.TPMCCCertify}).Execute(thetpm); err != nil {
					t.Fatal(err)
				}
				err = certify(ps)
				_ = closePS()
				if err != nil {
					t.Errorf("Certify via PolicyCommandCode(Certify): %v", err)
				}

				// ObjectChangeAuth is refused for both keys.
				for _, k := range []struct {
					name   string
					handle uint32
					kname  tpm2.TPM2BName
					alg    tpm2.TPMAlgID
				}{
					{"Device key", tpmlib.DAKHandle, dakName, kc.nameAlg},
					{"HMAC key", tpmlib.HMACKeyHandle, hkName, tpm2.TPMAlgSHA256},
				} {
					ps, closePS, err := tpm2.PolicySession(thetpm, k.alg, 16)
					if err != nil {
						t.Fatal(err)
					}
					_, _ = (tpm2.PolicyCommandCode{PolicySession: ps.Handle(), Code: tpm2.TPMCCObjectChangeAuth}).Execute(thetpm)
					_, err = tpm2.ObjectChangeAuth{
						ObjectHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(k.handle), Name: k.kname, Auth: ps},
						ParentHandle: tpm2.NamedHandle{Handle: srk.Handle, Name: srk.Name},
						NewAuth:      tpm2.TPM2BAuth{Buffer: []byte("x")},
					}.Execute(thetpm)
					_ = closePS()
					if err == nil {
						t.Errorf("%s: ObjectChangeAuth succeeded", k.name)
					}
				}
			})
		})
	}
}

// testLifecycle: DI -> load -> sign/HMAC -> TO2 credential update -> load,
// with DCTPM recording the key handles, as cred/tpm_store.go does it.
func testLifecycle(t *testing.T) {
	thetpm := openTPM(t)
	kc := keyCases(t, thetpm)[0]
	dakPub := provisionKeys(t, thetpm, kc)

	pkh := sha512.Sum384([]byte("owner key"))
	di := specDCTPM{
		Magic: tpmlib.DCTPMMagic, Active: true, Version: 200, DeviceInfo: "spec-lifecycle",
		GUID:            protocol.GUID{0xa1, 0xb2, 0xc3, 0xd4},
		RvInfo:          mustRvInfo(t, "rvserver.local"),
		PublicKeyHash:   protocol.Hash{Algorithm: protocol.Sha384Hash, Value: pkh[:]},
		DeviceKeyType:   tpmlib.DeviceKeyTypeDAK,
		DeviceKeyHandle: tpmlib.DAKHandle,
		HMACKeyHandle:   tpmlib.HMACKeyHandle,
	}
	write := func(v specDCTPM) {
		t.Helper()
		b, err := cbor.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := tpmlib.WriteDCTPM(thetpm, b, usePlatformDCTPM()); err != nil {
			t.Fatalf("WriteDCTPM: %v", err)
		}
	}
	load := func() specDCTPM {
		t.Helper()
		info, err := tpmlib.ReadNVCredentials(thetpm)
		if err != nil {
			t.Fatal(err)
		}
		if !info.HasDCTPM || !info.HasDAK || !info.HasHMACKey {
			t.Fatalf("missing FDO state: %+v", info)
		}
		var got specDCTPM
		if err := tpmlib.DecodeDCTPM(info.RawDCTPM, &got); err != nil {
			t.Fatal(err)
		}
		if got.Magic != tpmlib.DCTPMMagic {
			t.Fatalf("magic 0x%08X", got.Magic)
		}
		return got
	}

	write(di)
	got := load()
	if got.GUID != di.GUID || got.DeviceKeyType != tpmlib.DeviceKeyTypeDAK ||
		got.DeviceKeyHandle != tpmlib.DAKHandle || got.HMACKeyHandle != tpmlib.HMACKeyHandle {
		t.Fatalf("DI round trip: %+v", got)
	}
	readPub, err := tpmlib.ReadDAKPublicKey(thetpm)
	if err != nil {
		t.Fatal(err)
	}
	if !readPub.(*ecdsa.PublicKey).Equal(dakPub) {
		t.Fatal("persisted DAK public key differs from the one created at DI")
	}

	hmacOf := func() []byte {
		h, err := tpmlib.NewSpecHmac(thetpm, crypto.SHA256, got.HMACKeyHandle)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = h.Write([]byte("OVHeader"))
		return h.Sum(nil)
	}
	before := hmacOf()

	// TO2 credential update: new GUID, longer RVInfo, same keys.
	to2 := di
	to2.GUID = protocol.GUID{0x0f, 0x0e, 0x0d}
	to2.RvInfo = append(mustRvInfo(t, "rvserver.local"), mustRvInfo(t, "rv.owner.example.com")...)
	write(to2)
	got = load()
	if got.GUID != to2.GUID || len(got.RvInfo) != 2 {
		t.Fatalf("TO2 update not visible: %+v", got)
	}
	if !bytes.Equal(before, hmacOf()) {
		t.Fatal("HMAC key changed across the DCTPM update")
	}
	if _, err := tpmlib.ProveDAKPossession(thetpm, nil); err != nil {
		t.Fatalf("DAK unusable after update: %v", err)
	}

	// CleanupFDOState removes everything.
	tpmlib.CleanupFDOState(thetpm)
	info, err := tpmlib.ReadNVCredentials(thetpm)
	if err != nil {
		t.Fatal(err)
	}
	if info.HasDCTPM || info.HasDAK || info.HasHMACKey {
		t.Fatalf("FDO state left after CleanupFDOState: %+v", info)
	}
}
