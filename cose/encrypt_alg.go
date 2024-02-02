// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
)

// EncryptAlgorithm is the encryption type.
type EncryptAlgorithm int64

// NewCrypter returns a new Crypter for the given encryption algorithm.
func (alg EncryptAlgorithm) NewCrypter(key []byte) (Crypter, error) {
	if keySize := alg.KeySize(); len(key) != int(keySize) {
		return nil, fmt.Errorf("requires %d bit key", keySize*8)
	}

	newCrypter, ok := encryptAlgorithms[alg]
	if !ok {
		panic("encrypt algorithm not registered")
	}
	return newCrypter(key)
}

// SupportsAD reports whether the algorithm supports additional authenticated
// data.
func (alg EncryptAlgorithm) SupportsAD() bool {
	info, ok := encryptAlgorithmInfo[alg]
	if !ok {
		panic("encrypt algorithm not registered")
	}
	return info.AD
}

// KeySize returns the key length in bytes that the algorithm requires.
func (alg EncryptAlgorithm) KeySize() uint16 {
	info, ok := encryptAlgorithmInfo[alg]
	if !ok {
		panic("encrypt algorithm not registered")
	}
	return info.KeySize
}

/*
AES-GCM Algorithm Values

	+---------+-------+------------------------------------------+
	| Name    | Value | Description                              |
	+---------+-------+------------------------------------------+
	| A128GCM | 1     | AES-GCM mode w/ 128-bit key, 128-bit tag |
	| A192GCM | 2     | AES-GCM mode w/ 192-bit key, 128-bit tag |
	| A256GCM | 3     | AES-GCM mode w/ 256-bit key, 128-bit tag |
	+---------+-------+------------------------------------------+
*/
const (
	A128GCM EncryptAlgorithm = 1
	A192GCM EncryptAlgorithm = 2
	A256GCM EncryptAlgorithm = 3
)

const gcmNonceSize = 96 / 8

/*
AES-CCM Algorithm Values

	+--------------------+-------+----+-----+-----+---------------------+
	| Name               | Value | L  | M   | k   | Description         |
	+--------------------+-------+----+-----+-----+---------------------+
	| AES-CCM-16-64-128  | 10    | 16 | 64  | 128 | AES-CCM mode        |
	|                    |       |    |     |     | 128-bit key, 64-bit |
	|                    |       |    |     |     | tag, 13-byte nonce  |
	| AES-CCM-16-64-256  | 11    | 16 | 64  | 256 | AES-CCM mode        |
	|                    |       |    |     |     | 256-bit key, 64-bit |
	|                    |       |    |     |     | tag, 13-byte nonce  |
	| AES-CCM-64-64-128  | 12    | 64 | 64  | 128 | AES-CCM mode        |
	|                    |       |    |     |     | 128-bit key, 64-bit |
	|                    |       |    |     |     | tag, 7-byte nonce   |
	| AES-CCM-64-64-256  | 13    | 64 | 64  | 256 | AES-CCM mode        |
	|                    |       |    |     |     | 256-bit key, 64-bit |
	|                    |       |    |     |     | tag, 7-byte nonce   |
	| AES-CCM-16-128-128 | 30    | 16 | 128 | 128 | AES-CCM mode        |
	|                    |       |    |     |     | 128-bit key,        |
	|                    |       |    |     |     | 128-bit tag,        |
	|                    |       |    |     |     | 13-byte nonce       |
	| AES-CCM-16-128-256 | 31    | 16 | 128 | 256 | AES-CCM mode        |
	|                    |       |    |     |     | 256-bit key,        |
	|                    |       |    |     |     | 128-bit tag,        |
	|                    |       |    |     |     | 13-byte nonce       |
	| AES-CCM-64-128-128 | 32    | 64 | 128 | 128 | AES-CCM mode        |
	|                    |       |    |     |     | 128-bit key,        |
	|                    |       |    |     |     | 128-bit tag, 7-byte |
	|                    |       |    |     |     | nonce               |
	| AES-CCM-64-128-256 | 33    | 64 | 128 | 256 | AES-CCM mode        |
	|                    |       |    |     |     | 256-bit key,        |
	|                    |       |    |     |     | 128-bit tag, 7-byte |
	|                    |       |    |     |     | nonce               |
	+--------------------+-------+----+-----+-----+---------------------+
*/
const (
	AesCcm16_64_128  EncryptAlgorithm = 10
	AesCcm16_64_256  EncryptAlgorithm = 11
	AesCcm64_64_128  EncryptAlgorithm = 12
	AesCcm64_64_256  EncryptAlgorithm = 13
	AesCcm16_128_128 EncryptAlgorithm = 30
	AesCcm16_128_256 EncryptAlgorithm = 31
	AesCcm64_128_128 EncryptAlgorithm = 32
	AesCcm64_128_256 EncryptAlgorithm = 33
)

type algInfo struct {
	AD      bool
	KeySize uint16
}

var encryptAlgorithmInfo = make(map[EncryptAlgorithm]algInfo)
var encryptAlgorithms = make(map[EncryptAlgorithm]func([]byte) (Crypter, error))

// RegisterEncryptAlgorithm adds a new encryption algorithm for use in this
// library. This function should be called in an init func.
func RegisterEncryptAlgorithm(alg EncryptAlgorithm, ad bool, keyBits uint16, f func([]byte) (Crypter, error)) {
	if _, ok := encryptAlgorithms[alg]; ok {
		panic("encrypt algorithm already registered")
	}
	if f == nil {
		panic("cannot register nil func")
	}
	encryptAlgorithmInfo[alg] = algInfo{AD: ad, KeySize: keyBits / 8}
	encryptAlgorithms[alg] = f
}

func init() {
	RegisterEncryptAlgorithm(A128GCM, true, 128, aesGcm)
	RegisterEncryptAlgorithm(A192GCM, true, 192, aesGcm)
	RegisterEncryptAlgorithm(A256GCM, true, 256, aesGcm)
	RegisterEncryptAlgorithm(AesCcm16_64_128, true, 128, aesCcm(16, 64))
	RegisterEncryptAlgorithm(AesCcm16_64_256, true, 256, aesCcm(16, 64))
	RegisterEncryptAlgorithm(AesCcm64_64_128, true, 128, aesCcm(64, 64))
	RegisterEncryptAlgorithm(AesCcm64_64_256, true, 256, aesCcm(64, 64))
	RegisterEncryptAlgorithm(AesCcm16_128_128, true, 128, aesCcm(16, 128))
	RegisterEncryptAlgorithm(AesCcm16_128_256, true, 256, aesCcm(16, 128))
	RegisterEncryptAlgorithm(AesCcm64_128_128, true, 128, aesCcm(64, 128))
	RegisterEncryptAlgorithm(AesCcm64_128_256, true, 256, aesCcm(64, 128))
}

func aesGcm(key []byte) (Crypter, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(b, gcmNonceSize)
	if err != nil {
		return nil, err
	}
	return &aeadCrypter{AEAD: aead}, nil
}

func aesCcm(msgExp, tagBits int) func([]byte) (Crypter, error) {
	return func(key []byte) (Crypter, error) {
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		if tagBits/8 > b.BlockSize() {
			return nil, fmt.Errorf("tag size too large")
		}
		return &aeadCrypter{AEAD: &ccmAEAD{
			Block:  b,
			MsgExp: msgExp,
			Mac:    aesCbcMac{Block: b, TagSize: tagBits / 8},
		}}, nil
	}
}

type aeadCrypter struct {
	AEAD cipher.AEAD
}

func (c *aeadCrypter) Encrypt(rand io.Reader, plaintext, externalAAD []byte, _ HeaderMap) ([]byte, error) {
	if externalAAD == nil {
		return nil, fmt.Errorf("AAD must be provided")
	}
	nonce := make([]byte, c.AEAD.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("error generating random nonce: %w", err)
	}
	return c.AEAD.Seal(nonce, nonce, plaintext, externalAAD), nil
}

func (c *aeadCrypter) Decrypt(rand io.Reader, ciphertext, externalAAD []byte, _ HeaderMap) ([]byte, error) {
	if externalAAD == nil {
		return nil, fmt.Errorf("AAD must be provided")
	}
	if len(ciphertext) < c.AEAD.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return c.AEAD.Open(
		ciphertext[:0],
		ciphertext[:c.AEAD.NonceSize()],
		ciphertext[c.AEAD.NonceSize():],
		externalAAD,
	)
}

type ccmAEAD struct {
	Block  cipher.Block
	MsgExp int // msg size limit is 2^x
	Mac    aesCbcMac
}

func (c *ccmAEAD) NonceSize() int { return 15 - (c.MsgExp / 8) }

func (c *ccmAEAD) Overhead() int { return c.Mac.Size() }

func (c *ccmAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(plaintext) > 1<<c.MsgExp {
		return nil
	}

	// tag := c.tag(plaintext, additionalData)

	panic("unimplemented")
}

func (c *ccmAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) > c.Overhead()+1<<c.MsgExp {
		return nil, fmt.Errorf("ciphertext too long")
	}

	// tag := c.tag(plaintext, additionalData)

	panic("unimplemented")
}

func (c *ccmAEAD) tag(plaintext, additionalData []byte) []byte {
	c.Mac.Reset()
	panic("unimplemented")
}
