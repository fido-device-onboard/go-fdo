// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import (
	"crypto"
)

// SignatureAlgorithm is the ECDSA/RSASSA-PKCS1-v1_5/RSASSA-PKCS1-v1_5
// signature type and hash.
type SignatureAlgorithm int64

// HashFunc implements crypto.SignerOpts.
func (alg SignatureAlgorithm) HashFunc() crypto.Hash {
	newHash, ok := sigAlgorithms[alg]
	if !ok {
		panic("signature algorithm not registered")
	}
	return newHash()
}

var sigAlgorithms = make(map[SignatureAlgorithm]func() crypto.Hash)

// RegisterSignatureAlgorithm adds a new signature algorithm for use in this
// library. This function should be called in an init func.
func RegisterSignatureAlgorithm(alg SignatureAlgorithm, f func() crypto.Hash) {
	if _, ok := sigAlgorithms[alg]; ok {
		panic("sig algorithm already registered")
	}
	if f == nil {
		panic("cannot register nil func")
	}
	sigAlgorithms[alg] = f
}

func init() {
	RegisterSignatureAlgorithm(ES256Alg, crypto.SHA256.HashFunc)
	RegisterSignatureAlgorithm(RS256Alg, crypto.SHA256.HashFunc)
	RegisterSignatureAlgorithm(PS256Alg, crypto.SHA256.HashFunc)
	RegisterSignatureAlgorithm(ES384Alg, crypto.SHA384.HashFunc)
	RegisterSignatureAlgorithm(RS384Alg, crypto.SHA384.HashFunc)
	RegisterSignatureAlgorithm(PS384Alg, crypto.SHA384.HashFunc)
	RegisterSignatureAlgorithm(ES512Alg, crypto.SHA512.HashFunc)
	RegisterSignatureAlgorithm(RS512Alg, crypto.SHA512.HashFunc)
	RegisterSignatureAlgorithm(PS512Alg, crypto.SHA512.HashFunc)
}

/*
ECDSA Algorithm Values

	+-------+-------+---------+------------------+
	| Name  | Value | Hash    | Description      |
	+-------+-------+---------+------------------+
	| ES256 | -7    | SHA-256 | ECDSA w/ SHA-256 |
	| ES384 | -35   | SHA-384 | ECDSA w/ SHA-384 |
	| ES512 | -36   | SHA-512 | ECDSA w/ SHA-512 |
	+-------+-------+---------+------------------+
*/
const (
	ES256Alg SignatureAlgorithm = -7
	ES384Alg SignatureAlgorithm = -35
	ES512Alg SignatureAlgorithm = -36
)

/*
RSASSA-PKCS1-v1_5 Algorithm Values

	+-------+-------+---------+------------------------------+
	| Name  | Value | Hash    | Description                  |
	+-------+-------+---------+------------------------------+
	| RS256 | -257  | SHA-256 | RSASSA-PKCS1-v1_5 w/ SHA-256 |
	| RS384 | -258  | SHA-384 | RSASSA-PKCS1-v1_5 w/ SHA-384 |
	| RS512 | -259  | SHA-512 | RSASSA-PKCS1-v1_5 w/ SHA-512 |
	+-------+-------+---------+------------------------------+
*/
const (
	RS256Alg SignatureAlgorithm = -257
	RS384Alg SignatureAlgorithm = -258
	RS512Alg SignatureAlgorithm = -259
)

/*
RSASSA-PSS Algorithm Values from RFC 8230

	+-------+-------+---------+-------------+-----------------------+
	| Name  | Value | Hash    | Salt Length | Description           |
	+-------+-------+---------+-------------+-----------------------+
	| PS256 | -37   | SHA-256 | 32          | RSASSA-PSS w/ SHA-256 |
	| PS384 | -38   | SHA-384 | 48          | RSASSA-PSS w/ SHA-384 |
	| PS512 | -39   | SHA-512 | 64          | RSASSA-PSS w/ SHA-512 |
	+-------+-------+---------+-------------+-----------------------+
*/
const (
	PS256Alg SignatureAlgorithm = -37
	PS384Alg SignatureAlgorithm = -38
	PS512Alg SignatureAlgorithm = -39
)
