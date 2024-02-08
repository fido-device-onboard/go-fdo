// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

func TestSignAndVerify(t *testing.T) {
	t.Run("es256", func(t *testing.T) {
		// Test from https://github.com/cose-wg/Examples/blob/b7a0a92bcdcba1e35c2075140e0c7c64e6e13551/sign1-tests/sign-pass-02.json
		x, _ := base64.RawURLEncoding.DecodeString("usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8")
		y, _ := base64.RawURLEncoding.DecodeString("IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4")
		d, _ := base64.RawURLEncoding.DecodeString("V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM")
		key256 := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(x),
				Y:     new(big.Int).SetBytes(y),
			},
			D: new(big.Int).SetBytes(d),
		}
		expect256, _ := hex.DecodeString("d28443a10126a10442313154546869732069732074686520636f6e74656e742e584010729cd711cb3813d8d8e944a8da7111e7b258c9bdca6135f7ae1adbee9509891267837e1e33bd36c150326ae62755c6bd8e540c3e8f92d7d225e8db72b8820b")

		s1 := cose.Sign1[[]byte, []byte]{
			Header: cose.Header{
				Unprotected: cose.HeaderMap{
					cose.Label{Int64: 4}: []byte("11"),
				},
			},
			Payload: cbor.NewByteWrap[[]byte]([]byte("This is the content.")),
		}

		externalAAD, _ := hex.DecodeString("11aa22bb33cc44dd55006699")

		if err := s1.Sign(key256, nil, externalAAD, nil); err != nil {
			t.Fatalf("error signing: %v", err)
		}
		if len(s1.Signature) != 64 {
			t.Fatalf("signature length correct: expected %d, got %d", 64, len(s1.Signature))
		}

		// Marshal and Unmarshal
		data, err := cbor.Marshal(s1.Tag())
		if err != nil {
			t.Fatalf("error marshaling: %v", err)
		}
		if !bytes.Equal(expect256, data) {
			t.Fatalf("\nexpected %x\ngot      %x", expect256, data)
		}
		var s1t cose.Sign1Tag[[]byte, []byte]
		if err := cbor.Unmarshal(data, &s1t); err != nil {
			t.Fatalf("error unmarshaling: %v", err)
		}

		passed, err := s1t.Verify(key256.Public(), nil, externalAAD)
		if err != nil {
			t.Fatalf("error verifying: %v", err)
		}
		if !passed {
			t.Fatal("verification failed")
		}
	})

	t.Run("es384", func(t *testing.T) {
		var s1 cose.Sign1[[]byte, []byte]
		key384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Errorf("error generating ec key p384: %v", err)
			return
		}

		payload := []byte("Hello world!")
		if err := s1.Sign(key384, &payload, nil, nil); err != nil {
			t.Fatalf("error signing: %v", err)
		}
		if len(s1.Signature) != 96 {
			t.Fatalf("signature length correct: expected %d, got %d", 96, len(s1.Signature))
		}

		// Marshal and Unmarshal
		data, err := cbor.Marshal(s1)
		if err != nil {
			t.Fatalf("error marshaling: %v", err)
		}
		var s1a cose.Sign1[[]byte, []byte]
		if err := cbor.Unmarshal(data, &s1a); err != nil {
			t.Fatalf("error unmarshaling: %v", err)
		}

		passed, err := s1a.Verify(key384.Public(), nil, nil)
		if err != nil {
			t.Fatalf("error verifying: %v", err)
		}
		if !passed {
			t.Fatal("verification failed")
		}
	})
}
