// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"fmt"
	"hash"
)

// MacAlgorithm is the MAC type.
type MacAlgorithm int64

// NewMac returns a new mac for the given MAC algorithm.
func (alg MacAlgorithm) NewMac(key []byte) (hash.Hash, error) {
	if keySize := alg.KeySize(); len(key) != int(keySize) {
		return nil, fmt.Errorf("requires %d bit key", keySize*8)
	}

	newHash, ok := macAlgorithms[alg]
	if !ok {
		panic("mac algorithm not registered")
	}
	return newHash(key)
}

// KeySize returns the key length in bytes that the algorithm requires. While
// HMac algorithms can handle keys of different sizes, the recommended lengths
// are required by this package: 128 bits for SHA256 and 256 bits for SHA512
// family.
func (alg MacAlgorithm) KeySize() uint16 {
	keySize, ok := macAlgorithmKeySizes[alg]
	if !ok {
		panic("encrypt algorithm not registered")
	}
	return keySize
}

/*
HMAC Algorithm Values

	+-----------+-------+---------+----------+--------------------------+
	| Name      | Value | Hash    | Tag      | Description              |
	|           |       |         | Length   |                          |
	+-----------+-------+---------+----------+--------------------------+
	| HMAC      | 4     | SHA-256 | 64       | HMAC w/ SHA-256          |
	| 256/64    |       |         |          | truncated to 64 bits     |
	| HMAC      | 5     | SHA-256 | 256      | HMAC w/ SHA-256          |
	| 256/256   |       |         |          |                          |
	| HMAC      | 6     | SHA-384 | 384      | HMAC w/ SHA-384          |
	| 384/384   |       |         |          |                          |
	| HMAC      | 7     | SHA-512 | 512      | HMAC w/ SHA-512          |
	| 512/512   |       |         |          |                          |
	+-----------+-------+---------+----------+--------------------------+
*/
const (
	HMac256_64 MacAlgorithm = 4
	HMac256    MacAlgorithm = 5
	HMac384    MacAlgorithm = 6
	HMac512    MacAlgorithm = 7
)

/*
AES-CBC-MAC Algorithm Values

	+-------------+-------+----------+----------+-----------------------+
	| Name        | Value | Key      | Tag      | Description           |
	|             |       | Length   | Length   |                       |
	+-------------+-------+----------+----------+-----------------------+
	| AES-MAC     | 14    | 128      | 64       | AES-MAC 128-bit key,  |
	| 128/64      |       |          |          | 64-bit tag            |
	| AES-MAC     | 15    | 256      | 64       | AES-MAC 256-bit key,  |
	| 256/64      |       |          |          | 64-bit tag            |
	| AES-MAC     | 25    | 128      | 128      | AES-MAC 128-bit key,  |
	| 128/128     |       |          |          | 128-bit tag           |
	| AES-MAC     | 26    | 256      | 128      | AES-MAC 256-bit key,  |
	| 256/128     |       |          |          | 128-bit tag           |
	+-------------+-------+----------+----------+-----------------------+
*/
const (
	AesCbcMac128_64  MacAlgorithm = 14
	AesCbcMac256_64  MacAlgorithm = 15
	AesCbcMac128_128 MacAlgorithm = 25
	AesCbcMac256_128 MacAlgorithm = 26
)

var macAlgorithmKeySizes = make(map[MacAlgorithm]uint16)
var macAlgorithms = make(map[MacAlgorithm]func([]byte) (hash.Hash, error))

// RegisterMacAlgorithm adds a new mac algorithm for use in this library. This
// function should be called in an init func.
func RegisterMacAlgorithm(alg MacAlgorithm, keyBits uint16, f func([]byte) (hash.Hash, error)) {
	if _, ok := macAlgorithms[alg]; ok {
		panic("mac algorithm already registered")
	}
	if f == nil {
		panic("cannot register nil func")
	}
	macAlgorithmKeySizes[alg] = keyBits / 8
	macAlgorithms[alg] = f
}

func init() {
	RegisterMacAlgorithm(HMac256_64, 128,
		func(key []byte) (hash.Hash, error) {
			return truncHash{
				Truncate: 8,
				Hash:     hmac.New(crypto.SHA256.New, key),
			}, nil
		})
	RegisterMacAlgorithm(HMac256, 128, newHMac(crypto.SHA256))
	RegisterMacAlgorithm(HMac384, 256, newHMac(crypto.SHA384))
	RegisterMacAlgorithm(HMac512, 256, newHMac(crypto.SHA512))
	RegisterMacAlgorithm(AesCbcMac128_64, 128, aesMac(64))
	RegisterMacAlgorithm(AesCbcMac256_64, 256, aesMac(64))
	RegisterMacAlgorithm(AesCbcMac128_128, 128, aesMac(128))
	RegisterMacAlgorithm(AesCbcMac256_128, 256, aesMac(128))
}

func newHMac(h crypto.Hash) func([]byte) (hash.Hash, error) {
	return func(key []byte) (hash.Hash, error) {
		return hmac.New(h.New, key), nil
	}
}

type truncHash struct {
	hash.Hash
	Truncate int
}

func (h truncHash) Size() int { return h.Truncate }

func (h truncHash) Sum(b []byte) []byte {
	bs := h.Hash.Sum(b)
	return bs[:h.Truncate]
}

func aesMac(tagBits int) func([]byte) (hash.Hash, error) {
	return func(key []byte) (hash.Hash, error) {
		return newAesCbcMac(key, tagBits)
	}
}

type aesCbcMac struct {
	Block   cipher.Block
	TagSize int

	tag []byte
	pos int
}

func newAesCbcMac(key []byte, tagBits int) (*aesCbcMac, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if tagBits/8 > b.BlockSize() {
		return nil, fmt.Errorf("tag size too large")
	}
	return &aesCbcMac{
		Block:   b,
		TagSize: tagBits / 8,
		tag:     make([]byte, b.BlockSize()),
	}, nil
}

func (m *aesCbcMac) Write(p []byte) (int, error) {
	// XOR each byte with the last block, encrypting each time it is filled
	for _, b := range p {
		m.tag[m.pos] ^= b
		m.pos++
		if m.pos == m.BlockSize() {
			m.Block.Encrypt(m.tag, m.tag)
			m.pos = 0
		}
	}
	return len(p), nil
}

func (m *aesCbcMac) Sum(prepend []byte) []byte {
	// Zero pad and encrypt last block, if any data
	if m.pos != 0 {
		copy(m.tag[m.pos:], make([]byte, len(m.tag[m.pos:])))
		m.Block.Encrypt(m.tag, m.tag)
	}
	return append(prepend, m.tag[:m.Size()]...)
}

func (m *aesCbcMac) Reset() { m.pos = 0; m.tag = make([]byte, m.BlockSize()) }

func (m *aesCbcMac) Size() int { return m.TagSize }

func (m *aesCbcMac) BlockSize() int { return aes.BlockSize }
