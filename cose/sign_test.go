// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

func TestSignAndVerify(t *testing.T) {
	key256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Errorf("error generating ec key p256: %v", err)
		return
	}

	key384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Errorf("error generating ec key p384: %v", err)
		return
	}

	s1 := cose.Sign1[[]byte, []byte]{
		Payload: cbor.NewByteWrap[[]byte]([]byte("This is the content.")),
	}

	t.Run("es256", func(t *testing.T) {
		if err := s1.Sign(key256, nil, nil, nil); err != nil {
			t.Errorf("error signing: %v", err)
			return
		}
		if len(s1.Signature) != 64 {
			t.Errorf("signature length correct: expected %d, got %d", 64, len(s1.Signature))
			return
		}

		// Marshal and Unmarshal
		data, err := cbor.Marshal(s1)
		if err != nil {
			t.Errorf("error marshaling: %v", err)
			return
		}
		var s1a cose.Sign1[[]byte, []byte]
		if err := cbor.Unmarshal(data, &s1a); err != nil {
			t.Errorf("error unmarshaling: %v", err)
			return
		}

		passed, err := s1a.Verify(key256.Public(), nil, nil)
		if err != nil {
			t.Errorf("error verifying: %v", err)
			return
		}
		if !passed {
			t.Error("verification failed")
			return
		}
	})

	t.Run("es384", func(t *testing.T) {
		if err := s1.Sign(key384, nil, nil, nil); err != nil {
			t.Errorf("error signing: %v", err)
			return
		}
		if len(s1.Signature) != 96 {
			t.Errorf("signature length correct: expected %d, got %d", 96, len(s1.Signature))
			return
		}

		// Marshal and Unmarshal
		data, err := cbor.Marshal(s1)
		if err != nil {
			t.Errorf("error marshaling: %v", err)
			return
		}
		var s1a cose.Sign1[[]byte, []byte]
		if err := cbor.Unmarshal(data, &s1a); err != nil {
			t.Errorf("error unmarshaling: %v", err)
			return
		}

		passed, err := s1a.Verify(key384.Public(), nil, nil)
		if err != nil {
			t.Errorf("error verifying: %v", err)
			return
		}
		if !passed {
			t.Error("verification failed")
			return
		}
	})
}
