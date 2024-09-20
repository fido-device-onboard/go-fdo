// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"math"
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
	RegisterEncryptAlgorithm(A128CTR, false, 128, aesCtr)
	RegisterEncryptAlgorithm(A192CTR, false, 192, aesCtr)
	RegisterEncryptAlgorithm(A256CTR, false, 256, aesCtr)
	RegisterEncryptAlgorithm(A128CBC, false, 128, aesCbc)
	RegisterEncryptAlgorithm(A192CBC, false, 192, aesCbc)
	RegisterEncryptAlgorithm(A256CBC, false, 256, aesCbc)
}

func aesGcm(key []byte) (Crypter, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(b)
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

func (c *aeadCrypter) Encrypt(rand io.Reader, plaintext, additionalData []byte) ([]byte, HeaderMap, error) {
	if additionalData == nil {
		return nil, nil, fmt.Errorf("AAD must be provided")
	}

	nonce := make([]byte, c.AEAD.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("error generating random nonce: %w", err)
	}

	return c.AEAD.Seal(plaintext[:0], nonce, plaintext, additionalData), HeaderMap{IvLabel: nonce}, nil
}

func (c *aeadCrypter) Decrypt(rand io.Reader, ciphertext, additionalData []byte, unprotected HeaderParser) ([]byte, error) {
	if additionalData == nil {
		return nil, fmt.Errorf("AAD must be provided")
	}

	var nonce []byte
	if ok, err := unprotected.Parse(IvLabel, &nonce); err != nil {
		return nil, fmt.Errorf("error reading IV from unprotected headers: %w", err)
	} else if !ok {
		return nil, fmt.Errorf("missing expected IV unprotected header")
	}

	return c.AEAD.Open(ciphertext[:0], nonce, ciphertext, additionalData)
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

//nolint:unused
func (c *ccmAEAD) tag(plaintext, additionalData []byte) []byte {
	c.Mac.Reset()
	panic("unimplemented")
}

/*
AES-CTR Algorithm Values

	+=========+========+==========+=============+=============+
	| Name    | Value  | Key Size | Description | Recommended |
	+=========+========+==========+=============+=============+
	| A128CTR | -65534 |   128    |  AES-CTR w/ |  Deprecated |
	|         |        |          | 128-bit key |             |
	+---------+--------+----------+-------------+-------------+
	| A192CTR | -65533 |   192    |  AES-CTR w/ |  Deprecated |
	|         |        |          | 192-bit key |             |
	+---------+--------+----------+-------------+-------------+
	| A256CTR | -65532 |   256    |  AES-CTR w/ |  Deprecated |
	|         |        |          | 256-bit key |             |
	+---------+--------+----------+-------------+-------------+
*/
const (
	A128CTR EncryptAlgorithm = -65534
	A192CTR EncryptAlgorithm = -65533
	A256CTR EncryptAlgorithm = -65532
)

func aesCtr(key []byte) (Crypter, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &ctrCrypter{Cipher: b}, nil
}

type ctrCrypter struct {
	Cipher cipher.Block
}

func (c *ctrCrypter) Encrypt(rand io.Reader, plaintext, additionalData []byte) (ciphertext []byte, unprotected HeaderMap, err error) {
	if len(additionalData) > 0 {
		return nil, nil, fmt.Errorf("additional data must be empty")
	}

	iv := make([]byte, c.Cipher.BlockSize())
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, nil, err
	}

	ciphertext = plaintext
	ctr := cipher.NewCTR(c.Cipher, iv)
	ctr.XORKeyStream(ciphertext, plaintext)

	return ciphertext, HeaderMap{IvLabel: iv}, nil
}

func (c *ctrCrypter) Decrypt(rand io.Reader, ciphertext, additionalData []byte, unprotected HeaderParser) (plaintext []byte, err error) {
	if len(additionalData) > 0 {
		return nil, fmt.Errorf("additional data must be empty")
	}

	var iv []byte
	if ok, err := unprotected.Parse(IvLabel, &iv); err != nil {
		return nil, fmt.Errorf("error parsing IV: %w", err)
	} else if !ok {
		return nil, fmt.Errorf("IV not included in header")
	}

	plaintext = ciphertext
	ctr := cipher.NewCTR(c.Cipher, iv)
	ctr.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

/*
AES-CBC Algorithm Values

	+=========+========+==========+=============+=============+
	| Name    | Value  | Key Size | Description | Recommended |
	+=========+========+==========+=============+=============+
	| A128CBC | -65531 |   128    |  AES-CBC w/ |  Deprecated |
	|         |        |          | 128-bit key |             |
	+---------+--------+----------+-------------+-------------+
	| A192CBC | -65530 |   192    |  AES-CBC w/ |  Deprecated |
	|         |        |          | 192-bit key |             |
	+---------+--------+----------+-------------+-------------+
	| A256CBC | -65529 |   256    |  AES-CBC w/ |  Deprecated |
	|         |        |          | 256-bit key |             |
	+---------+--------+----------+-------------+-------------+
*/
const (
	A128CBC EncryptAlgorithm = -65531
	A192CBC EncryptAlgorithm = -65530
	A256CBC EncryptAlgorithm = -65529
)

func aesCbc(key []byte) (Crypter, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &cbcCrypter{Cipher: b}, nil
}

type cbcCrypter struct {
	Cipher cipher.Block
}

func (c *cbcCrypter) Encrypt(rand io.Reader, plaintext, additionalData []byte) (ciphertext []byte, unprotected HeaderMap, err error) {
	if len(additionalData) > 0 {
		return nil, nil, fmt.Errorf("additional data must be empty")
	}

	iv := make([]byte, c.Cipher.BlockSize())
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, nil, err
	}

	plaintext = pad(plaintext, c.Cipher.BlockSize())
	ciphertext = plaintext
	cbc := cipher.NewCBCEncrypter(c.Cipher, iv)
	cbc.CryptBlocks(ciphertext, plaintext)

	return ciphertext, HeaderMap{IvLabel: iv}, nil
}

func (c *cbcCrypter) Decrypt(rand io.Reader, ciphertext, additionalData []byte, unprotected HeaderParser) (plaintext []byte, err error) {
	if len(additionalData) > 0 {
		return nil, fmt.Errorf("additional data must be empty")
	}

	var iv []byte
	if ok, err := unprotected.Parse(IvLabel, &iv); err != nil {
		return nil, fmt.Errorf("error parsing IV: %w", err)
	} else if !ok {
		return nil, fmt.Errorf("IV not included in header")
	}

	plaintext = ciphertext
	cbc := cipher.NewCBCDecrypter(c.Cipher, iv)
	cbc.CryptBlocks(plaintext, ciphertext)
	plaintext = unpad(plaintext)

	return plaintext, err
}

// PKCS#7 padding
func pad(b []byte, blockSize int) []byte {
	padSize := blockSize - len(b)%blockSize
	if padSize < 0 || padSize > math.MaxUint8 {
		// This panic is to convince gosec padSize is safe to cast to a byte
		panic("pad size miscalculated")
	}
	padding := bytes.Repeat([]byte{uint8(padSize)}, padSize)
	return append(b, padding...)
}

// PKCS#7 padding
func unpad(b []byte) []byte {
	padSize := int(b[len(b)-1])
	return b[:len(b)-padSize]
}
