// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestCCM(t *testing.T) {
	t.Skip("CCM not yet implemented")

	var (
		key         = []byte{0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f}
		nonce       = []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16}
		externalAAD = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
		plaintext   = []byte{0x20, 0x21, 0x22, 0x23}
		expect      = []byte{0x71, 0x62, 0x01, 0x5b, 0x4d, 0xac, 0x25, 0x5d}
		tagBits     = 32
	)

	crypter, err := aesCcm(8*(15-len(nonce)), tagBits)(key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := crypter.Encrypt(rand.Reader, plaintext, externalAAD, HeaderMap{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expect, got) {
		t.Errorf("expected ciphertext %x, got %x", expect, got)
	}
	plaintext1, err := crypter.Decrypt(rand.Reader, expect, externalAAD, HeaderMap{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, plaintext1) {
		t.Errorf("expected plaintext %x, got %x", plaintext, plaintext1)
	}
}
