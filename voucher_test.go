// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"os"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
)

func readVoucher(t *testing.T) (ov fdo.Voucher) {
	b, err := os.ReadFile("testdata/voucher.bin")
	if err != nil {
		t.Fatalf("error opening voucher test data: %v", err)
	}
	if err := cbor.Unmarshal(b, &ov); err != nil {
		t.Fatalf("error parsing voucher test data: %v", err)
	}
	return ov
}

func readCredential(t *testing.T) (cred fdo.DeviceCredentialBlob) {
	// Load device credential
	b, err := os.ReadFile("testdata/DC.bin")
	if err != nil {
		t.Fatalf("error opening device credential test data: %v", err)
	}
	if err := cbor.Unmarshal(b, &cred); err != nil {
		t.Fatalf("error loading device credential blob: %v", err)
	}
	return cred
}

func TestVerifyVoucher(t *testing.T) {
	ov := readVoucher(t)
	cred := readCredential(t)

	if err := ov.VerifyHeader(&cred); err != nil {
		t.Error("error verifying voucher header", err)
	}

	if err := ov.VerifyCertChain(nil); err != nil {
		t.Fatal("error verifying voucher cert chain (with implicit trusted root)", err)
	}

	if err := ov.VerifyCertChainHash(); err != nil {
		t.Fatal("error verifying voucher cert chain hash", err)
	}

	if err := ov.VerifyEntries(); err != nil {
		t.Fatal("error verifying voucher entries", err)
	}
}
