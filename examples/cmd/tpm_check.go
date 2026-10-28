// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

//go:build (tpm || tpmsim) && !tinygo

package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"fmt"

	"github.com/google/go-tpm/tpm2"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/tpm"
)

// tpmCheckSpec checks the FDO state in the TPM, whichever implementation
// wrote it, against "Securing FDO Credentials in the TPM": DCTPM index
// (Table 9), Device key and HMAC key templates (Tables 11, 12), and the
// Device key's Certify-only ADMIN policy. It prints one PASS/FAIL/INFO line
// per check and fails if any check fails. It creates and flushes a transient
// SRK and attestation key; it does not change the FDO state.
func tpmCheckSpec() error {
	tpmc, err := tpmOpen(tpmPath)
	if err != nil {
		return fmt.Errorf("opening TPM: %w", err)
	}
	defer func() { _ = tpmc.Close() }()

	failed := 0
	check := func(ok bool, format string, args ...any) {
		status := "PASS"
		if !ok {
			status = "FAIL"
			failed++
		}
		fmt.Printf("%s  %s\n", status, fmt.Sprintf(format, args...))
	}
	info := func(format string, args ...any) { fmt.Printf("INFO  %s\n", fmt.Sprintf(format, args...)) }

	// --- DCTPM index ---
	dakHandle, hmacHandle := uint32(tpm.DAKHandle), uint32(tpm.HMACKeyHandle)
	rp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(tpm.DCTPMIndex)}.Execute(tpmc)
	if err != nil {
		return fmt.Errorf("DCTPM (0x%08X) not defined: %w", tpm.DCTPMIndex, err)
	}
	nvPub, err := rp.NVPublic.Contents()
	if err != nil {
		return err
	}
	a := nvPub.Attributes
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"OWNERWRITE", a.OwnerWrite}, {"AUTHWRITE", a.AuthWrite},
		{"OWNERREAD", a.OwnerRead}, {"AUTHREAD", a.AuthRead},
		{"NO_DA", a.NoDA}, {"WRITE_STCLEAR", a.WriteSTClear},
		{"POLICYWRITE=0", !a.PolicyWrite}, {"POLICYREAD=0", !a.PolicyRead},
	} {
		check(c.ok, "DCTPM attribute %s (Table 9)", c.name)
	}
	info("DCTPM size %d bytes, PLATFORMCREATE=%v", nvPub.DataSize, a.PlatformCreate)

	nvInfo, err := tpm.ReadNVCredentials(tpmc)
	if err != nil {
		return err
	}
	var dctpm dctpmDisplay
	if err := tpm.DecodeDCTPM(nvInfo.RawDCTPM, &dctpm); err != nil {
		check(false, "DCTPM decodes as one CBOR item: %v", err)
	} else {
		check(dctpm.Magic == tpm.DCTPMMagic, "DCTPM magic 0x%08X", dctpm.Magic)
		var items []cbor.RawBytes
		if err := tpm.DecodeDCTPM(nvInfo.RawDCTPM, &items); err == nil {
			check(len(items) >= 11, "DCTPM has DCMinFirmwareRev (item 10): %d items, value %d", len(items), dctpm.MinFirmwareRev)
		}
		check(dctpm.DeviceKeyType <= tpm.DeviceKeyTypeLDevID, "DCTPM DeviceKeyType %d (%s; 0 = DAK, 1 = IDevID, 2 = LDevID)",
			dctpm.DeviceKeyType, deviceKeyTypeName(dctpm.DeviceKeyType))
		if dctpm.DeviceKeyHandle != 0 {
			dakHandle = dctpm.DeviceKeyHandle
		}
		if dctpm.HMACKeyHandle != 0 {
			hmacHandle = dctpm.HMACKeyHandle
		}
		info("DCTPM GUID %s, DeviceKeyHandle 0x%08X, HMACKeyHandle 0x%08X", dctpm.GUID, dakHandle, hmacHandle)
	}

	// --- Key templates ---
	keyPub := func(h uint32) (*tpm2.TPMTPublic, tpm2.TPM2BName, error) {
		r, err := tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(h)}.Execute(tpmc)
		if err != nil {
			return nil, tpm2.TPM2BName{}, err
		}
		p, err := r.OutPublic.Contents()
		return p, r.Name, err
	}
	attrs := func(which string, o tpm2.TPMAObject) {
		for _, c := range []struct {
			name string
			ok   bool
		}{
			{"fixedTPM", o.FixedTPM}, {"fixedParent", o.FixedParent},
			{"sensitiveDataOrigin", o.SensitiveDataOrigin}, {"userWithAuth", o.UserWithAuth},
			{"adminWithPolicy", o.AdminWithPolicy}, {"noDA", o.NoDA}, {"sign", o.SignEncrypt},
			{"restricted=0", !o.Restricted}, {"decrypt=0", !o.Decrypt},
		} {
			check(c.ok, "%s attribute %s (Table 11)", which, c.name)
		}
	}

	dakPub, dakName, err := keyPub(dakHandle)
	if err != nil {
		return fmt.Errorf("device key at 0x%08X: %w", dakHandle, err)
	}
	attrs("Device key", dakPub.ObjectAttributes)
	want, err := tpm.DeviceKeyAuthPolicy(dakPub.NameAlg)
	check(err == nil && bytes.Equal(dakPub.AuthPolicy.Buffer, want.Buffer),
		"Device key authPolicy = PolicyCommandCode(TPM_CC_Certify) (Table 12): got %x", dakPub.AuthPolicy.Buffer)

	hkPub, _, err := keyPub(hmacHandle)
	if err != nil {
		return fmt.Errorf("HMAC key at 0x%08X: %w", hmacHandle, err)
	}
	attrs("HMAC key", hkPub.ObjectAttributes)
	check(len(hkPub.AuthPolicy.Buffer) == 0, "HMAC key authPolicy empty (Table 12): got %x", hkPub.AuthPolicy.Buffer)
	check(hkPub.NameAlg == dakPub.NameAlg, "HMAC key nameAlg matches the Device key (Table 10): HMAC 0x%04x, Device 0x%04x",
		uint16(hkPub.NameAlg), uint16(dakPub.NameAlg))
	kh, err := hkPub.Parameters.KeyedHashDetail()
	var hmacHash tpm2.TPMAlgID
	if err == nil && kh.Scheme.Scheme == tpm2.TPMAlgHMAC {
		if d, err := kh.Scheme.Details.HMAC(); err == nil {
			hmacHash = d.HashAlg
		}
	}
	check(hmacHash == hkPub.NameAlg, "HMAC key scheme TPM_ALG_HMAC with hash = nameAlg (Table 10): scheme hash 0x%04x", uint16(hmacHash))
	own := crypto.SHA256
	if hkPub.NameAlg == tpm2.TPMAlgSHA384 {
		own = crypto.SHA384
	}
	hm, err := tpm.NewSpecHmac(tpmc, own, hmacHandle)
	if err == nil {
		_, _ = hm.Write([]byte("fdo"))
		if s := hm.Sum(nil); hm.Err() != nil {
			err = hm.Err()
		} else if len(s) != own.Size() {
			err = fmt.Errorf("%d-byte result", len(s))
		}
		_ = hm.Close()
	}
	check(err == nil, "HMAC-%v with the persisted HMAC key: %v", own, err)

	// --- Device key use: USER role with empty auth ---
	h, err := dakPub.NameAlg.Hash()
	if err != nil {
		return fmt.Errorf("device key nameAlg: %w", err)
	}
	digest := make([]byte, h.Size()) // the scheme hash matches nameAlg for FDO keys
	_, _ = rand.Read(digest)
	_, err = tpm2.Sign{
		KeyHandle:  tpm2.AuthHandle{Handle: tpm2.TPMHandle(dakHandle), Name: dakName, Auth: tpm2.PasswordAuth(nil)},
		Digest:     tpm2.TPM2BDigest{Buffer: digest},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}.Execute(tpmc)
	check(err == nil, "Device key signs with empty authValue (err=%v)", err)

	// --- ADMIN role: Certify only via the policy ---
	srk, err := tpm.CreateSRK(tpmc)
	if err != nil {
		return err
	}
	defer func() { _, _ = (tpm2.FlushContext{FlushHandle: srk.Handle}).Execute(tpmc) }()
	ak, err := createCheckAK(tpmc, *srk)
	if err != nil {
		return err
	}
	defer func() { _, _ = (tpm2.FlushContext{FlushHandle: ak.Handle}).Execute(tpmc) }()

	certify := func(auth tpm2.Session) error {
		_, err := tpm2.Certify{
			ObjectHandle:   tpm2.AuthHandle{Handle: tpm2.TPMHandle(dakHandle), Name: dakName, Auth: auth},
			SignHandle:     tpm2.AuthHandle{Handle: ak.Handle, Name: ak.Name, Auth: tpm2.PasswordAuth(nil)},
			QualifyingData: tpm2.TPM2BData{Buffer: []byte("tpm-check")},
			InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
		}.Execute(tpmc)
		return err
	}
	check(certify(tpm2.PasswordAuth(nil)) != nil, "Device key: Certify with a password session refused (adminWithPolicy)")
	withPolicy := func(cc tpm2.TPMCC, run func(tpm2.Session) error) error {
		ps, closePS, err := tpm2.PolicySession(tpmc, dakPub.NameAlg, 16)
		if err != nil {
			return err
		}
		defer func() { _ = closePS() }()
		if _, err := (tpm2.PolicyCommandCode{PolicySession: ps.Handle(), Code: cc}).Execute(tpmc); err != nil {
			return err
		}
		return run(ps)
	}
	err = withPolicy(tpm2.TPMCCCertify, certify)
	check(err == nil, "Device key: Certify via PolicyCommandCode(Certify) succeeds (err=%v)", err)
	err = withPolicy(tpm2.TPMCCObjectChangeAuth, func(ps tpm2.Session) error {
		_, err := tpm2.ObjectChangeAuth{
			ObjectHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(dakHandle), Name: dakName, Auth: ps},
			ParentHandle: tpm2.NamedHandle{Handle: srk.Handle, Name: srk.Name},
			NewAuth:      tpm2.TPM2BAuth{Buffer: []byte("x")},
		}.Execute(tpmc)
		return err
	})
	check(err != nil, "Device key: ObjectChangeAuth refused")

	if failed > 0 {
		return fmt.Errorf("%d check(s) failed", failed)
	}
	fmt.Println("All checks passed")
	return nil
}

// createCheckAK creates a transient restricted ECC P-256 signing key (an
// attestation key) under the SRK, used only as the signer for TPM2_Certify.
func createCheckAK(t tpm.TPM, srk tpm2.NamedHandle) (*tpm2.NamedHandle, error) {
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
	})}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("create attestation key: %w", err)
	}
	lr, err := tpm2.Load{ParentHandle: parent, InPrivate: cr.OutPrivate, InPublic: cr.OutPublic}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("load attestation key: %w", err)
	}
	return &tpm2.NamedHandle{Handle: lr.ObjectHandle, Name: lr.Name}, nil
}
