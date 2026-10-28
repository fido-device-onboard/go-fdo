// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package tpm_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"

	"github.com/fido-device-onboard/go-fdo/tpm"
)

// Digests from the FDO TPM spec, Table 12.
var specDeviceKeyPolicy = map[tpm2.TPMAlgID]string{
	tpm2.TPMAlgSHA256: "048e9a3ace08583f79f344ff785bbea9f07ac7fa3325b3d49a21dd5194c65850",
	tpm2.TPMAlgSHA384: "a7108d531f393410f00d93745061f31f10b50042fdd0e0a0353bd1be088b50acc12cee7ca47caf8a928290beff81019a",
}

func TestDeviceKeyAuthPolicyDigest(t *testing.T) {
	for alg, want := range specDeviceKeyPolicy {
		got, err := tpm.DeviceKeyAuthPolicy(alg)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got.Buffer) != want {
			t.Errorf("alg 0x%04x: digest %x, want %s (spec Table 12)", uint16(alg), got.Buffer, want)
		}
		calc, err := tpm2.NewPolicyCalculator(alg)
		if err != nil {
			t.Fatal(err)
		}
		if err := (tpm2.PolicyCommandCode{Code: tpm2.TPMCCCertify}).Update(calc); err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(calc.Hash().Digest) != want {
			t.Errorf("alg 0x%04x: go-tpm policy calculator disagrees with spec Table 12", uint16(alg))
		}
	}
	if _, err := tpm.DeviceKeyAuthPolicy(tpm2.TPMAlgSHA1); err == nil {
		t.Error("expected error for SHA-1 nameAlg")
	}
}

// TestDeviceKeyCertifyPolicy checks the spec's Device key / HMAC key
// templates on the simulator, for both creation methods: the Device key
// carries the Certify policy and noDA, still signs with an empty password,
// can be certified by an AK through a PolicyCommandCode(Certify) session, and
// refuses TPM2_ObjectChangeAuth; the HMAC key has an empty policy and noDA.
func TestDeviceKeyCertifyPolicy(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("error opening TPM simulator: %v", err)
	}
	defer func() { _ = sim.Close() }()

	srk, err := tpm.CreateSRK(sim)
	if err != nil {
		t.Fatal(err)
	}
	defer flush(sim, srk.Handle)

	ak := createAK(t, sim, *srk)
	defer flush(sim, ak.Handle)

	t.Run("child", func(t *testing.T) {
		dak, _, err := tpm.CreateChildECKey(sim, *srk, tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256)
		if err != nil {
			t.Fatal(err)
		}
		checkDeviceKey(t, sim, *dak, *ak)

		// ObjectChangeAuth fails with either command code in the session.
		for _, cc := range []tpm2.TPMCC{tpm2.TPMCCCertify, tpm2.TPMCCObjectChangeAuth} {
			ps, closePS, err := tpm2.PolicySession(sim, tpm2.TPMAlgSHA256, 16)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := (tpm2.PolicyCommandCode{PolicySession: ps.Handle(), Code: cc}).Execute(sim); err != nil {
				t.Fatal(err)
			}
			_, err = tpm2.ObjectChangeAuth{
				ObjectHandle: tpm2.AuthHandle{Handle: dak.Handle, Name: dak.Name, Auth: ps},
				ParentHandle: tpm2.NamedHandle{Handle: srk.Handle, Name: srk.Name},
				NewAuth:      tpm2.TPM2BAuth{Buffer: []byte("x")},
			}.Execute(sim)
			_ = closePS()
			if err == nil {
				t.Errorf("ObjectChangeAuth succeeded with policy CC 0x%x", uint32(cc))
			}
		}

		flush(sim, dak.Handle) // the simulator has 3 transient object slots

		hk, err := tpm.CreateChildHMACKey(sim, *srk, tpm2.TPMAlgSHA256)
		if err != nil {
			t.Fatal(err)
		}
		defer flush(sim, hk.Handle)
		checkHMACKey(t, sim, *hk)
	})

	t.Run("primary", func(t *testing.T) {
		us := make([]byte, 64)
		us[0] = 1
		dak, _, err := tpm.GenerateSpecECKey(sim, tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256, us)
		if err != nil {
			t.Fatal(err)
		}
		checkDeviceKey(t, sim, *dak, *ak)
		flush(sim, dak.Handle)

		hk, err := tpm.GenerateSpecHMACKey(sim, tpm2.TPMAlgSHA256, us[:32])
		if err != nil {
			t.Fatal(err)
		}
		defer flush(sim, hk.Handle)
		checkHMACKey(t, sim, *hk)
	})
}

func checkDeviceKey(t *testing.T, sim tpm.TPM, dak, ak tpm2.NamedHandle) {
	t.Helper()
	pub := readPublic(t, sim, dak)
	if !pub.ObjectAttributes.NoDA || !pub.ObjectAttributes.AdminWithPolicy || !pub.ObjectAttributes.UserWithAuth {
		t.Errorf("Device key attributes: %+v", pub.ObjectAttributes)
	}
	if got := hex.EncodeToString(pub.AuthPolicy.Buffer); got != specDeviceKeyPolicy[tpm2.TPMAlgSHA256] {
		t.Errorf("Device key authPolicy %s, want spec Table 12", got)
	}

	// USER role: sign with an empty password, no policy session.
	digest := sha256.Sum256([]byte("fdo"))
	if _, err := (tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{Handle: dak.Handle, Name: dak.Name, Auth: tpm2.PasswordAuth(nil)},
		Digest:    tpm2.TPM2BDigest{Buffer: digest[:]},
		InScheme: tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256})},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}).Execute(sim); err != nil {
		t.Errorf("Sign with empty password: %v", err)
	}

	certify := func(auth tpm2.Session) error {
		_, err := tpm2.Certify{
			ObjectHandle:   tpm2.AuthHandle{Handle: dak.Handle, Name: dak.Name, Auth: auth},
			SignHandle:     tpm2.AuthHandle{Handle: ak.Handle, Name: ak.Name, Auth: tpm2.PasswordAuth(nil)},
			QualifyingData: tpm2.TPM2BData{Buffer: []byte("owner-nonce")},
			InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
		}.Execute(sim)
		return err
	}
	// ADMIN role without a policy session is refused (adminWithPolicy=1).
	if certify(tpm2.PasswordAuth(nil)) == nil {
		t.Error("Certify with a password session succeeded; want policy required")
	}
	ps, closePS, err := tpm2.PolicySession(sim, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closePS() }()
	if _, err := (tpm2.PolicyCommandCode{PolicySession: ps.Handle(), Code: tpm2.TPMCCCertify}).Execute(sim); err != nil {
		t.Fatal(err)
	}
	if err := certify(ps); err != nil {
		t.Errorf("Certify via PolicyCommandCode(Certify): %v", err)
	}
}

func checkHMACKey(t *testing.T, sim tpm.TPM, hk tpm2.NamedHandle) {
	t.Helper()
	pub := readPublic(t, sim, hk)
	if !pub.ObjectAttributes.NoDA {
		t.Errorf("HMAC key noDA not set: %+v", pub.ObjectAttributes)
	}
	if len(pub.AuthPolicy.Buffer) != 0 {
		t.Errorf("HMAC key authPolicy %x, want empty (spec Table 12)", pub.AuthPolicy.Buffer)
	}
}

func readPublic(t *testing.T, sim tpm.TPM, h tpm2.NamedHandle) *tpm2.TPMTPublic {
	t.Helper()
	rp, err := tpm2.ReadPublic{ObjectHandle: h.Handle}.Execute(sim)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := rp.OutPublic.Contents()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func createAK(t *testing.T, sim tpm.TPM, srk tpm2.NamedHandle) *tpm2.NamedHandle {
	t.Helper()
	parent := tpm2.AuthHandle{Handle: srk.Handle, Name: srk.Name, Auth: tpm2.PasswordAuth(nil)}
	cr, err := tpm2.Create{ParentHandle: parent, InPublic: tpm2.New2B(tpm2.TPMTPublic{
		Type: tpm2.TPMAlgECC, NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
			UserWithAuth: true, NoDA: true, Restricted: true, SignEncrypt: true},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			CurveID: tpm2.TPMECCNistP256,
			Scheme: tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256})},
		}),
	})}.Execute(sim)
	if err != nil {
		t.Fatal(err)
	}
	lr, err := tpm2.Load{ParentHandle: parent, InPrivate: cr.OutPrivate, InPublic: cr.OutPublic}.Execute(sim)
	if err != nil {
		t.Fatal(err)
	}
	return &tpm2.NamedHandle{Handle: lr.ObjectHandle, Name: lr.Name}
}

func flush(sim tpm.TPM, h tpm2.TPMHandle) {
	_, _ = tpm2.FlushContext{FlushHandle: h}.Execute(sim)
}
