// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package cose implements CBOR Object Signing and Encryption (COSE) defined in
// RFC8152.
package cose

import (
	"fmt"
	"strconv"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

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

// IntOrStr is either an int or a text string. Many values in COSE have this
// polymorphic type. For simplicity, it is implemented once and each type is an
// alias or embeds it.
type IntOrStr struct {
	Int64 int64
	Str   string
}

func (v IntOrStr) String() string {
	if v.Int64 != 0 {
		return strconv.FormatInt(v.Int64, 10)
	}
	return v.Str
}

// MarshalCBOR implements cbor.Marshaler.
func (v IntOrStr) MarshalCBOR() ([]byte, error) {
	// 0 is a reserved label
	if v.Int64 != 0 {
		return cbor.Marshal(v.Int64)
	}
	return cbor.Marshal(v.String)
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (v *IntOrStr) UnmarshalCBOR(b []byte) error {
	var a any
	if err := cbor.Unmarshal(b, &a); err != nil {
		return err
	}
	switch a := a.(type) {
	case int64:
		v.Int64 = a
		v.Str = ""
	case string:
		v.Int64 = 0
		v.Str = a
	default:
		return fmt.Errorf("unexpected label type: %T", a)
	}
	return nil
}
