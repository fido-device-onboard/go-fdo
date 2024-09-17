// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
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

func TestMac0OverEncrypt0(t *testing.T) {
	data, err := hex.DecodeString("8443a10105a059014c8340a20139fffa0550f3179d6354c8d6ef57371c559b05d2b2590130ce37b946f68c3979201d93848ffdf327511ba539c459c8a799d3defcc405f0e359667cbc92ce61b4d6fba09eb2321b9fb26e75c0f0a69eba1266752f4f2ea630383eb17fc131af52571c98fac24c1e8e9fd737a37769dbd6a016ae23c1b06101dec50d7cb38907ce78b3013c446fdd1e2e1f6843c5cb8f46f0f173a945d7b99a3a3f7ff62baa98bc7031a6e70ce8007384da96200a1ba2de7c4d945e0c17c8ad8eb3ba643aaa541527ab88e550df8894bcdc079050c3e985c05da8cd5a652cb020262afc6b2a50d64a542cb8449d32d070611b9f89b2f61c3394407257a9074bd37c8b9a562e85df45332c70325651e586cabe405bef832ee3424e9b99fe86c3ddbe640904e68adca8abada671dc6d3c3d67c7b731f82584d953730616fb8b5d19d01c2c2c76c9a9a0765551af01519658202fcf175c1d68d592c0fc1285789fd9090ffc97b78335582f5e3ce83ce6cc6a96")
	if err != nil {
		t.Fatal(err)
	}

	var mac0 cose.Mac0[cose.Encrypt0[cbor.RawBytes, []byte], []byte]
	if err := cbor.Unmarshal(data, &mac0); err != nil {
		t.Fatal(err)
	}
}
