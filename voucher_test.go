// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"encoding/pem"
	"os"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
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

func readVoucher(t *testing.T) *fdo.Voucher {
	b, err := os.ReadFile("testdata/ov.pem")
	if err != nil {
		t.Fatalf("error opening voucher test data: %v", err)
	}
	blk, more := pem.Decode(b)
	if len(more) > 0 {
		t.Fatal("voucher PEM contained unparsed data")
	}

	var ov fdo.Voucher
	if err := cbor.Unmarshal(blk.Bytes, &ov); err != nil {
		t.Fatalf("error parsing voucher test data: %v", err)
	}
	return &ov
}

func readCredential(t *testing.T) *fdo.DeviceCredentialBlob {
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
	return &fdo.DeviceCredentialBlob{
		Active:           rustCred.Active,
		DeviceCredential: rustCred.DeviceCredential,
		HmacSecret:       rustCred.Secrets["Plain"]["hmac_secret"],
		PrivateKey:       rustCred.Secrets["Plain"]["private_key"],
	}
}

func TestVerifyVoucher(t *testing.T) {
	ov := readVoucher(t)
	cred := readCredential(t)

	if err := ov.VerifyHeader(cred); err != nil {
		t.Error("error verifying voucher header", err)
	}

	if err := ov.VerifyCertChain(nil); err != nil {
		t.Error("error verifying voucher cert chain (with implicit trusted root)", err)
	}

	if err := ov.VerifyCertChainHash(); err != nil {
		t.Error("error verifying voucher cert chain hash", err)
	}

	if err := ov.VerifyEntries(cred.PublicKeyHash); err != nil {
		t.Error("error verifying voucher entries", err)
	}
}
