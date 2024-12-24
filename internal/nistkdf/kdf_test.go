// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package nistkdf_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"testing"

	"github.com/fido-device-onboard/go-fdo/internal/build"
	"github.com/fido-device-onboard/go-fdo/internal/nistkdf"
)

func TestKnownResult(t *testing.T) {
	if build.TinyGo {
		return
	}

	// EC256
	shSeHex := "08c9dc0cc5e9dd2558a12ae60cd00670d01a09cca52bae8a671a21e1babdb25bc21963c48b4aa77bb8ed338f0c5a15efee069ce10a09be2aacf857b8dcd9df8e"
	resultHex := "e5e959c8cbdd5989c819f7ea8c69bcb3f70a442830ba235c5aa0b4047d0cda0b"

	shSe, err := hex.DecodeString(shSeHex)
	if err != nil {
		t.Fatal(err)
	}
	expect, err := hex.DecodeString(resultHex)
	if err != nil {
		t.Fatal(err)
	}
	got := nistkdf.KDF(crypto.SHA256, shSe, nil, 256)
	if !bytes.Equal(expect, got) {
		t.Fatalf("expected %x, got %x", expect, got)
	}
}
