// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cose"
)

func TestMac0(t *testing.T) {
	// Input:
	//
	//   o  MAC: AES-CMAC, 256-bit key, truncated to 64 bits
	//   o  Recipient class: direct shared secret
	//   o  Shared secret: '849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188'
	//
	// Output:
	//
	//   17(
	//
	//    [
	//      / protected / h'a1010f' / {
	//          \ alg \ 1:15 \ AES-CBC-MAC-256//64 \
	//        } / ,
	//      / unprotected / {},
	//      / payload / 'This is the content.',
	//      / tag / h'726043745027214f'
	//    ]
	//
	//   )

	// Given input/output
	key, err := hex.DecodeString("849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("This is the content.")
	expect, err := hex.DecodeString("726043745027214f")
	if err != nil {
		t.Fatal(err)
	}

	// Digest to compute
	var m0 cose.Mac0[[]byte, []byte]
	if err := m0.Digest(cose.AesCbcMac256_64, key, &payload, nil); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m0.Value, expect) {
		t.Fatalf("Mac0 did not match expected value %x, got %x", expect, m0.Value)
	}
}
