// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package cose implements CBOR Object Signing and Encryption (COSE) defined in
// RFC8152.
package cose

/*
COSE Tags

	+-------+---------------+---------------+---------------------------+
	| CBOR  | cose-type     | Data Item     | Semantics                 |
	| Tag   |               |               |                           |
	+-------+---------------+---------------+---------------------------+
	| 98    | cose-sign     | COSE_Sign     | COSE Signed Data Object   |
	| 18    | cose-sign1    | COSE_Sign1    | COSE Single Signer Data   |
	|       |               |               | Object                    |
	| 96    | cose-encrypt  | COSE_Encrypt  | COSE Encrypted Data       |
	|       |               |               | Object                    |
	| 16    | cose-encrypt0 | COSE_Encrypt0 | COSE Single Recipient     |
	|       |               |               | Encrypted Data Object     |
	| 97    | cose-mac      | COSE_Mac      | COSE MACed Data Object    |
	| 17    | cose-mac0     | COSE_Mac0     | COSE Mac w/o Recipients   |
	|       |               |               | Object                    |
	+-------+---------------+---------------+---------------------------+
*/
const (
	SignTagNum     uint64 = 98
	Sign1TagNum    uint64 = 18
	EncryptTagNum  uint64 = 96
	Encrypt0TagNum uint64 = 16
	MacTagNum      uint64 = 97
	Mac0TagNum     uint64 = 17
)
