// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/blob"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
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
	b, err := os.ReadFile(filepath.Join("testdata", basename))
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
		Hmac      fdo.Hmac
		CertChain *[]*cbor.X509Certificate
		Entries   []cose.Sign1Tag[fdo.VoucherEntryPayload]
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
		PrivateKey:       blob.Pkcs8Key{PrivateKey: privateKey},
	}
}

func TestVerifyUnextendedVoucher(t *testing.T) {
	var ov fdo.Voucher
	if err := cbor.Unmarshal(voucherBytes(t, "ov.pem"), &ov); err != nil {
		t.Fatalf("error parsing voucher test data: %v", err)
	}

	cred := readCredential(t)

	if err := ov.VerifyHeader(cred); err != nil {
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
