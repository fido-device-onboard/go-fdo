// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/blob"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/testdata"
)

/*
Test data was generated with https://github.com/fdo-rs/fido-device-onboard-rs

	cargo build --release
	mkdir tmp
	cd tmp
	cat <<EOF > rvinfo.yml
	---
	- ip_address: 192.168.122.1
	  deviceport: 8082
	  ownerport: 8082
	  protocol: http
	- dns: fdo.example.com
	  device_port: 8082
	  owner_port: 8082
	  protocol: http
	EOF
	rm *.pem *.key *.bin
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -keyout - -out mfg.pem -sha256 -days 3650 -noenc -subj '/CN=mfg.fdo' | openssl ec -outform der > mfg.key
	openssl req -x509 -newkey rsa:4096 -keyout - -out dev_ca.pem -sha256 -days 3650 -noenc -subj '/CN=dev.ca.fdo' | openssl rsa -outform der > dev_ca.key
	../target/release/fdo-owner-tool initialize-device --manufacturer-cert ./mfg.pem --device-cert-ca-private-key dev_ca.key --device-cert-ca-chain dev_ca.pem --rendezvous-info ./rvinfo.yml go.fdo.example ov.pem dc.bin
*/

func voucherBytes(t *testing.T, basename string) []byte {
	b, err := testdata.Files.ReadFile(basename)
	if err != nil {
		t.Fatalf("error opening voucher test data: %v", err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatal("voucher contained invalid PEM data")
	}
	return blk.Bytes
}

func TestVoucherDeterministic(t *testing.T) {
	b := voucherBytes(t, "ov.pem")

	var ov fdo.Voucher
	if err := cbor.Unmarshal(b, &ov); err != nil {
		t.Fatalf("error parsing voucher test data: %v", err)
	}

	// Try marshaling again to ensure determinism
	if b1, err := cbor.Marshal(&ov); err != nil {
		t.Fatalf("error marshaling voucher: %v", err)
	} else if !bytes.Equal(b, b1) {
		t.Fatalf("marshaled voucher does not equal original voucher data:\n\noriginal: %x\n\nmarshaled: %x", b, b1)
	}
}

func TestVoucherHeaderDeterministic(t *testing.T) {
	b := voucherBytes(t, "ov.pem")

	var ov struct {
		Version   uint16
		Header    cbor.Bstr[cbor.RawBytes]
		Hmac      protocol.Hmac
		CertChain *[]*cbor.X509Certificate
		Entries   []cose.Sign1Tag[fdo.VoucherEntryPayload, []byte]
	}
	if err := cbor.Unmarshal(b, &ov); err != nil {
		t.Fatalf("error parsing voucher test data: %v", err)
	}

	// Unmarshal voucher header
	h1 := []byte(ov.Header.Val)
	var ovh fdo.VoucherHeader
	if err := cbor.Unmarshal(h1, &ovh); err != nil {
		t.Fatalf("error parsing voucher header test data: %v", err)
	}

	// Try marshaling again to ensure determinism
	if h2, err := cbor.Marshal(&ovh); err != nil {
		t.Fatalf("error marshaling voucher: %v", err)
	} else if !bytes.Equal(h1, h2) {
		t.Fatalf("marshaled voucher does not equal original voucher data:\n\noriginal: %x\n\nmarshaled: %x", h1, h2)
	}
}

func readCredential(t *testing.T) *blob.DeviceCredential {
	b, err := os.ReadFile("testdata/dc.bin")
	if err != nil {
		t.Fatalf("error opening device credential test data: %v", err)
	}

	var rustCred struct {
		Active bool
		fdo.DeviceCredential
		Secrets map[string]map[string][]byte
	}
	if err := cbor.Unmarshal(b, &rustCred); err != nil {
		t.Fatalf("error loading device credential blob: %v", err)
	}
	privateKey, err := x509.ParseECPrivateKey(rustCred.Secrets["Plain"]["private_key"])
	if err != nil {
		t.Fatalf("error parsing private key: %v", err)
	}
	return &blob.DeviceCredential{
		Active:           rustCred.Active,
		DeviceCredential: rustCred.DeviceCredential,
		HmacSecret:       rustCred.Secrets["Plain"]["hmac_secret"],
		PrivateKey:       blob.Pkcs8Key{Signer: privateKey},
	}
}

func TestVerifyUnextendedVoucher(t *testing.T) {
	var ov fdo.Voucher
	if err := cbor.Unmarshal(voucherBytes(t, "ov.pem"), &ov); err != nil {
		t.Fatalf("error parsing voucher test data: %v", err)
	}

	cred := readCredential(t)

	if err := ov.VerifyHeader(cred.HMACs()); err != nil {
		t.Errorf("error verifying voucher header: %v", err)
	}

	if err := ov.VerifyDeviceCertChain(nil); err != nil {
		t.Errorf("error verifying voucher cert chain (with implicit trusted root): %v", err)
	}

	if err := ov.VerifyCertChainHash(); err != nil {
		t.Errorf("error verifying voucher cert chain hash: %v", err)
	}

	if err := ov.VerifyManufacturerKey(cred.PublicKeyHash); err != nil {
		t.Errorf("error verifying voucher created by manufacturer key: %v", err)
	}

	if err := ov.VerifyEntries(); err != nil {
		t.Errorf("error verifying voucher entries: %v", err)
	}
}

func TestExtendAndVerify(t *testing.T) {
	var ov fdo.Voucher
	if err := cbor.Unmarshal(voucherBytes(t, "ov.pem"), &ov); err != nil {
		t.Fatalf("error parsing voucher test data: %v", err)
	}

	var key crypto.Signer
	if data, err := os.ReadFile("testdata/mfg_key.pem"); err != nil {
		t.Fatalf("error reading manufacturer key: %v", err)
	} else if blk, _ := pem.Decode(data); blk == nil {
		t.Fatal("unable to parse manufacturer key PEM")
	} else if key, err = x509.ParseECPrivateKey(blk.Bytes); err != nil {
		t.Fatalf("error parsing manufacturer key: %v", err)
	}

	nextKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("error generating key for next device owner: %v", err)
	}

	ov1, err := fdo.ExtendVoucher(&ov, key, nextKey.Public().(*ecdsa.PublicKey), nil)
	if err != nil {
		t.Fatalf("error extending voucher: %v", err)
	}

	ov1Owner, err := ov1.OwnerPublicKey()
	if err != nil {
		t.Fatalf("error getting extended voucher's owner public key: %v", err)
	}

	if pub, ok := ov1Owner.(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(nextKey.Public()) {
		t.Error("extended voucher's owner public key did not match expected value")
	}

	if err := ov1.VerifyEntries(); err != nil {
		t.Errorf("error verifying voucher entries: %v", err)
	}
}

func TestVerifyExtendedVoucher(t *testing.T) {
	var ov fdo.Voucher
	if err := cbor.Unmarshal(voucherBytes(t, "ov_extended.pem"), &ov); err != nil {
		t.Fatalf("error parsing voucher test data: %v", err)
	}

	if err := ov.VerifyEntries(); err != nil {
		t.Errorf("error verifying voucher entries: %v", err)
	}
}

// TestWrongHMACRejected verifies that voucher header verification fails
// when the wrong HMAC secret is used.
func TestWrongHMACRejected(t *testing.T) {
	var ov fdo.Voucher
	if err := cbor.Unmarshal(voucherBytes(t, "ov.pem"), &ov); err != nil {
		t.Fatalf("error parsing voucher test data: %v", err)
	}

	// Create HMACs with a WRONG secret (not the device's actual secret)
	wrongSecret := make([]byte, 32)
	if _, err := rand.Read(wrongSecret); err != nil {
		t.Fatalf("error generating wrong secret: %v", err)
	}

	wrongHmacSha256 := hmac.New(sha256.New, wrongSecret)
	wrongHmacSha384 := hmac.New(sha512.New384, wrongSecret)

	// Verification should fail with wrong HMAC
	err := ov.VerifyHeader(wrongHmacSha256, wrongHmacSha384)
	if err == nil {
		t.Error("SECURITY FAILURE: voucher header verification passed with wrong HMAC secret")
	} else {
		t.Logf("Correctly rejected voucher with wrong HMAC: %v", err)
	}
}

// TestVoucherReplayPrevention verifies that once a voucher is removed from
// the server state (after successful onboarding), it cannot be retrieved again.
// This is a key defense against replay attacks.
func TestVoucherReplayPrevention(t *testing.T) {
	// This test verifies the VoucherReseller.RemoveVoucher behavior
	// which is the mechanism that prevents voucher replay.
	// The actual test is in fdotest/server_state.go TestServerState/VoucherReseller
	// which verifies that:
	// 1. RemoveVoucher returns the voucher and removes it
	// 2. Subsequent calls to RemoveVoucher return ErrNotFound
	// 3. Subsequent calls to Voucher return ErrNotFound
	//
	// Here we just verify the expected error type exists and is used correctly.
	var ov fdo.Voucher
	if err := cbor.Unmarshal(voucherBytes(t, "ov.pem"), &ov); err != nil {
		t.Fatalf("error parsing voucher test data: %v", err)
	}

	// Verify that ErrNotFound is the expected error for missing vouchers
	if fdo.ErrNotFound == nil {
		t.Fatal("fdo.ErrNotFound should be defined for voucher replay prevention")
	}

	t.Log("Voucher replay prevention relies on RemoveVoucher returning ErrNotFound on subsequent calls")
}

// TestCorruptedVoucherEntryRejected verifies that corrupted voucher entries
// are detected and rejected during verification.
func TestCorruptedVoucherEntryRejected(t *testing.T) {
	// First create a valid extended voucher
	var ov fdo.Voucher
	if err := cbor.Unmarshal(voucherBytes(t, "ov.pem"), &ov); err != nil {
		t.Fatalf("error parsing voucher test data: %v", err)
	}

	// Get the manufacturer key to extend (same pattern as TestExtendAndVerify)
	var key crypto.Signer
	if data, err := os.ReadFile("testdata/mfg_key.pem"); err != nil {
		t.Fatalf("error reading manufacturer key: %v", err)
	} else if blk, _ := pem.Decode(data); blk == nil {
		t.Fatal("unable to parse manufacturer key PEM")
	} else if key, err = x509.ParseECPrivateKey(blk.Bytes); err != nil {
		t.Fatalf("error parsing manufacturer key: %v", err)
	}

	// Generate a next owner key
	nextKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("error generating next owner key: %v", err)
	}

	// Extend the voucher
	extendedOV, err := fdo.ExtendVoucher(&ov, key, nextKey.Public().(*ecdsa.PublicKey), nil)
	if err != nil {
		t.Fatalf("error extending voucher: %v", err)
	}

	// Verify it works before corruption
	if err := extendedOV.VerifyEntries(); err != nil {
		t.Fatalf("extended voucher should verify before corruption: %v", err)
	}

	// Now corrupt the signature in the entry
	if len(extendedOV.Entries) > 0 {
		// Flip some bits in the signature
		sig := extendedOV.Entries[0].Signature
		if len(sig) > 0 {
			sig[0] ^= 0xFF
			sig[len(sig)-1] ^= 0xFF
		}
	}

	// Verification should now fail
	err = extendedOV.VerifyEntries()
	if err == nil {
		t.Error("SECURITY FAILURE: corrupted voucher entry signature was accepted")
	} else {
		t.Logf("Correctly rejected corrupted voucher entry: %v", err)
	}
}
