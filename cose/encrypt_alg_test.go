// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import (
	"bytes"
	"crypto/rand"
	"strconv"
	"strings"
	"testing"

	"github.com/fido-device-onboard/go-fdo/internal/build"
)

func TestEncryptDecrypt(t *testing.T) {
	type testCase struct {
		Name      string
		Plaintext []byte
		AAD       []byte
	}

	for _, table := range []struct {
		AlgName string
		Alg     func([]byte) (Crypter, error)
		KeyBits int
	}{
		{AlgName: "AES-GCM", Alg: aesGcm, KeyBits: 128},
		{AlgName: "AES-GCM", Alg: aesGcm, KeyBits: 192},
		{AlgName: "AES-GCM", Alg: aesGcm, KeyBits: 256},
		{AlgName: "AES-CTR", Alg: aesCtr, KeyBits: 128},
		{AlgName: "AES-CTR", Alg: aesCtr, KeyBits: 192},
		{AlgName: "AES-CTR", Alg: aesCtr, KeyBits: 256},
		{AlgName: "AES-CBC", Alg: aesCbc, KeyBits: 128},
		{AlgName: "AES-CBC", Alg: aesCbc, KeyBits: 192},
		{AlgName: "AES-CBC", Alg: aesCbc, KeyBits: 256},
	} {
		t.Run(table.AlgName+"-"+strconv.Itoa(table.KeyBits), func(t *testing.T) {
			cases := []testCase{
				{
					Name:      "NonEmptyPlaintext/EmptyAAD",
					Plaintext: []byte("Hello World!"),
					AAD:       []byte{},
				},
			}
			if table.AlgName == "AES-GCM" {
				cases = []testCase{
					{
						Name:      "EmptyPlaintext/EmptyAAD",
						Plaintext: []byte{},
						AAD:       []byte{},
					},
					{
						Name:      "EmptyPlaintext/NonEmptyAAD",
						Plaintext: []byte{},
						AAD:       []byte("additional authenticated data"),
					},
					{
						Name:      "NonEmptyPlaintext/EmptyAAD",
						Plaintext: []byte("Hello World!"),
						AAD:       []byte{},
					},
					{
						Name:      "NonEmptyPlaintext/NonEmptyAAD",
						Plaintext: []byte("Hello World!"),
						AAD:       []byte("additional authenticated data"),
					},
				}
			}

			for _, tc := range cases {
				t.Run(tc.Name, func(t *testing.T) {
					key := make([]byte, table.KeyBits/8)
					crypter, err := table.Alg(key)
					if err != nil {
						t.Fatalf("creating crypter: %v", err)
					}

					ciphertext, unprotected := mustEncrypt(t, crypter, tc.Plaintext, tc.AAD)

					if table.AlgName == "AES-GCM" {
						// COSE carries the 12 byte GCM nonce in the IV header
						if iv := mustParseIV(t, unprotected); len(iv) != 12 {
							t.Errorf("expected 12-byte IV, got %d bytes", len(iv))
						}

						// Ciphertext includes only the encrypted payload and the 16 byte authentication tag.
						if want := len(tc.Plaintext) + 16; len(ciphertext) != want {
							t.Errorf("expected ciphertext length %d, got %d", want, len(ciphertext))
						}
					}

					got, err := crypter.Decrypt(rand.Reader, ciphertext, tc.AAD, unprotected)
					if err != nil {
						t.Fatalf("decrypting: %v", err)
					}
					if !bytes.Equal(tc.Plaintext, got) {
						t.Fatalf("expected %q, got %q", string(tc.Plaintext), string(got))
					}
				})
			}
		})
	}
}

// gcmKeyBits are the AES key sizes registered for AES-GCM.
var gcmKeyBits = []int{128, 192, 256}

func TestGCMUniqueIV(t *testing.T) {
	plaintext := []byte("Hello World!")
	aad := []byte("additional authenticated data")

	for _, keyBits := range gcmKeyBits {
		t.Run(strconv.Itoa(keyBits), func(t *testing.T) {
			crypter := newGCMCrypter(t, keyBits)

			// Reusing a nonce under the same key breaks both the confidentiality
			// and the authenticity of GCM, so every encryption needs a fresh IV.
			ciphertext1, unprotected1 := mustEncrypt(t, crypter, plaintext, aad)
			ciphertext2, unprotected2 := mustEncrypt(t, crypter, plaintext, aad)

			if bytes.Equal(mustParseIV(t, unprotected1), mustParseIV(t, unprotected2)) {
				t.Error("expected a unique IV per encryption, got the same IV twice")
			}
			if bytes.Equal(ciphertext1, ciphertext2) {
				t.Error("expected distinct ciphertexts for identical inputs, got the same ciphertext twice")
			}
		})
	}
}

func TestGCMInvalidIVSize(t *testing.T) {
	aad := []byte("additional authenticated data")

	for _, keyBits := range gcmKeyBits {
		t.Run(strconv.Itoa(keyBits), func(t *testing.T) {
			crypter := newGCMCrypter(t, keyBits)
			ciphertext, _ := mustEncrypt(t, crypter, []byte("Hello World!"), aad)

			// Empty, one byte either side of the required 12, and the AES block size.
			for _, ivSize := range []int{0, 11, 13, 16} {
				unprotected := HeaderMap{IvLabel: make([]byte, ivSize)}
				_, err := crypter.Decrypt(rand.Reader, ciphertext, aad, unprotected)

				// Wrongly sized IV would also fail authentication so match the error to confirm the size check is what rejected it.
				if err == nil || !strings.Contains(err.Error(), "invalid IV size") {
					t.Errorf("%d-byte IV: expected invalid IV size error, got %v", ivSize, err)
				}
			}
		})
	}
}

func TestGCMTamperedInput(t *testing.T) {
	plaintext := []byte("Hello World!")
	aad := []byte("additional authenticated data")

	for _, keyBits := range gcmKeyBits {
		t.Run(strconv.Itoa(keyBits), func(t *testing.T) {
			crypter := newGCMCrypter(t, keyBits)
			ciphertext, unprotected := mustEncrypt(t, crypter, plaintext, aad)
			iv := mustParseIV(t, unprotected)

			// The untampered input must decrypt so that each failure below is
			// caused by the tampering alone.
			if _, err := crypter.Decrypt(rand.Reader, ciphertext, aad, HeaderMap{IvLabel: iv}); err != nil {
				t.Fatalf("decrypting untampered input: %v", err)
			}

			// The ciphertext is the encrypted payload followed by the 16 byte
			// authentication tag so its first byte is payload and its last is tag.
			for _, tc := range []struct {
				Name       string
				Ciphertext []byte
				AAD        []byte
				IV         []byte
			}{
				{Name: "FlippedCiphertextBit", Ciphertext: flipBit(ciphertext, 0), AAD: aad, IV: iv},
				{Name: "FlippedTagBit", Ciphertext: flipBit(ciphertext, len(ciphertext)-1), AAD: aad, IV: iv},
				{Name: "FlippedIVBit", Ciphertext: ciphertext, AAD: aad, IV: flipBit(iv, 0)},
				{Name: "MismatchedAAD", Ciphertext: ciphertext, AAD: []byte("other additional authenticated data"), IV: iv},
			} {
				t.Run(tc.Name, func(t *testing.T) {
					if _, err := crypter.Decrypt(rand.Reader, tc.Ciphertext, tc.AAD, HeaderMap{IvLabel: tc.IV}); err == nil {
						t.Fatal("expected decryption to fail")
					}
				})
			}
		})
	}
}

func TestCCM(t *testing.T) {
	if build.TinyGo {
		return
	}
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
	got, _, err := crypter.Encrypt(rand.Reader, plaintext, externalAAD)
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

func newGCMCrypter(t *testing.T, keyBits int) Crypter {
	t.Helper()
	crypter, err := aesGcm(make([]byte, keyBits/8))
	if err != nil {
		t.Fatalf("creating crypter: %v", err)
	}
	return crypter
}

// mustEncrypt encrypts a copy of plaintext, because some crypters encrypt in
// place and would otherwise overwrite the caller's expected value.
func mustEncrypt(t *testing.T, crypter Crypter, plaintext, aad []byte) ([]byte, HeaderMap) {
	t.Helper()
	ciphertext, unprotected, err := crypter.Encrypt(rand.Reader, bytes.Clone(plaintext), aad)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	return ciphertext, unprotected
}

func mustParseIV(t *testing.T, unprotected HeaderParser) []byte {
	t.Helper()
	var iv []byte
	if ok, err := unprotected.Parse(IvLabel, &iv); err != nil {
		t.Fatalf("parsing IV header: %v", err)
	} else if !ok {
		t.Fatal("missing IV header")
	}
	return iv
}

// flipBit returns a copy of b with the lowest bit of b[i] inverted.
func flipBit(b []byte, i int) []byte {
	flipped := bytes.Clone(b)
	flipped[i] ^= 1
	return flipped
}
