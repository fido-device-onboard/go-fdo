// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"os"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
)

func TestDecodeVoucher(t *testing.T) {
	b, err := os.ReadFile("testdata/voucher.bin")
	if err != nil {
		t.Fatal("error opening voucher test data", err)
	}

	var ov fdo.Voucher
	if err := cbor.Unmarshal(b, &ov); err != nil {
		t.Fatal("error parsing voucher test data", err)
	}

	if err := ov.VerifyCertChain(nil); err != nil {
		t.Fatal("error verifying voucher cert chain (with implicit trusted root)", err)
	}

	if err := ov.VerifyEntries(); err != nil {
		t.Fatal("error verifying voucher entries", err)
	}
}
