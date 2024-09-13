// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// KeyLabel is an int or string, used in the Key structure map.
type KeyLabel = IntOrStr

// Commmon Parameters
//
// +---------+-------+----------------+------------+-------------------+
// | Name    | Label | CBOR Type      | Value      | Description       |
// |         |       |                | Registry   |                   |
// +---------+-------+----------------+------------+-------------------+
// | kty     | 1     | tstr / int     | COSE Key   | Identification of |
// |         |       |                | Common     | the key type      |
// |         |       |                | Parameters |                   |
// |         |       |                |            |                   |
// | kid     | 2     | bstr           |            | Key               |
// |         |       |                |            | identification    |
// |         |       |                |            | value -- match to |
// |         |       |                |            | kid in message    |
// |         |       |                |            |                   |
// | alg     | 3     | tstr / int     | COSE       | Key usage         |
// |         |       |                | Algorithms | restriction to    |
// |         |       |                |            | this algorithm    |
// |         |       |                |            |                   |
// | key_ops | 4     | [+ (tstr/int)] |            | Restrict set of   |
// |         |       |                |            | permissible       |
// |         |       |                |            | operations        |
// |         |       |                |            |                   |
// | Base IV | 5     | bstr           |            | Base IV to be     |
// |         |       |                |            | xor-ed with       |
// |         |       |                |            | Partial IVs       |
// +---------+-------+----------------+------------+-------------------+
var (
	KeyTypeKeyLabel = KeyLabel{Int64: 1}
	KeyIDKeyLabel   = KeyLabel{Int64: 2}
	AlgKeyLabel     = KeyLabel{Int64: 3}
	KeyOpsKeyLabel  = KeyLabel{Int64: 4}
	BaseIVKeyLabel  = KeyLabel{Int64: 5}
)

// KeyType is an int or string, used for the "kty" value in the Key structure
// map.
type KeyType = IntOrStr

// +-----------+-------+-----------------------------------------------+
// | Name      | Value | Description                                   |
// +-----------+-------+-----------------------------------------------+
// | OKP       | 1     | Octet Key Pair                                |
// | EC2       | 2     | Elliptic Curve Keys w/ x- and y-coordinate    |
// |           |       | pair                                          |
// | Symmetric | 4     | Symmetric Keys                                |
// | Reserved  | 0     | This value is reserved                        |
// +-----------+-------+-----------------------------------------------+
var (
	OKPKeyType       = KeyType{Int64: 1}
	EC2KeyType       = KeyType{Int64: 2}
	SymmetricKeyType = KeyType{Int64: 4}
)

// Key is a COSE structure built on a CBOR map object.
//
// The element "kty" is a required element in a COSE_Key map.
//
// CDDL:
//
//	COSE_Key = {
//	    1 => tstr / int,          ; kty
//	    ? 2 => bstr,              ; kid
//	    ? 3 => tstr / int,        ; alg
//	    ? 4 => [+ (tstr / int) ], ; key_ops
//	    ? 5 => bstr,              ; Base IV
//	    * label => values
//	}
type Key map[KeyLabel]any

// NewKey creates a key map structure with only the required fields.
func NewKey(k any) (Key, error) {
	switch key := k.(type) {
	case *ecdsa.PublicKey:
		var crv int
		switch key.Curve {
		case elliptic.P256():
			crv = 1
		case elliptic.P384():
			crv = 2
		case elliptic.P521():
			crv = 3
		default:
			return nil, fmt.Errorf("unsupported curve: %s", key.Curve.Params().Name)
		}
		return Key{
			IntOrStr{Int64: -1}: crv,
			IntOrStr{Int64: -2}: key.X.Bytes(),
			IntOrStr{Int64: -3}: key.Y.Bytes(),
			KeyTypeKeyLabel:     EC2KeyType,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", k)
	}
}

// MarshalCBOR implements cbor.Marshaler.
func (k Key) MarshalCBOR() ([]byte, error) {
	kty, ok := k[KeyTypeKeyLabel]
	if !ok {
		return nil, fmt.Errorf("key type is required and missing")
	}
	if ktyBytes, _ := cbor.Marshal(kty); bytes.Equal([]byte{0x00}, ktyBytes) {
		return nil, fmt.Errorf("key type 0 is reserved")
	}
	return cbor.Marshal(map[KeyLabel]any(k))
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (k *Key) UnmarshalCBOR(data []byte) error {
	k1 := make(map[KeyLabel]any)
	if err := cbor.Unmarshal(data, &k1); err != nil {
		return err
	}
	if kty, ok := k1[KeyTypeKeyLabel]; !ok {
		return fmt.Errorf("key type is required and missing")
	} else if ktyInt, ok := kty.(int64); ok && ktyInt == 0 {
		return fmt.Errorf("key type 0 is reserved")
	} else if ktyStr, ok := kty.(string); ok && ktyStr == "Reserved" {
		return fmt.Errorf("key type 0 is reserved")
	}
	*k = k1
	return nil
}

// Kty returns the key type value. It returns false if the value is missing or
// not a valid type.
func (k Key) Kty() (IntOrStr, bool) {
	v, ok := k[KeyTypeKeyLabel]
	if !ok {
		return IntOrStr{}, false
	}
	switch v := v.(type) {
	case int64:
		return IntOrStr{Int64: v}, true
	case string:
		return IntOrStr{Str: v}, true
	default:
		return IntOrStr{}, false
	}
}

// IsOctetKeyPair returns whether the key type is an octet key pair.
func (k Key) IsOctetKeyPair() bool {
	kty, ok := k.Kty()
	if !ok {
		return false
	}
	return kty == OKPKeyType || kty.Str == "OKP"
}

// IsEllipticCurveKey returns whether the key type is an elliptic curve key.
func (k Key) IsEllipticCurveKey() bool {
	kty, ok := k.Kty()
	if !ok {
		return false
	}
	return kty == EC2KeyType || kty.Str == "EC2"
}

// IsSymmetricKey returns whether the key type is a symmetric key..
func (k Key) IsSymmetricKey() bool {
	kty, ok := k.Kty()
	if !ok {
		return false
	}
	return kty == SymmetricKeyType || kty.Str == "Symmetric"
}

// Kid returns the key ID value. It returns false if the value is missing or
// not a valid type.
func (k Key) Kid() ([]byte, bool) {
	v, ok := k[KeyIDKeyLabel]
	if !ok {
		return nil, false
	}
	b, ok := v.([]byte)
	return b, ok
}

// Alg returns the algorithm value. It returns false if the value is missing or
// not a valid type.
func (k Key) Alg() (IntOrStr, bool) {
	v, ok := k[AlgKeyLabel]
	if !ok {
		return IntOrStr{}, false
	}
	switch v := v.(type) {
	case int64:
		return IntOrStr{Int64: v}, true
	case string:
		return IntOrStr{Str: v}, true
	default:
		return IntOrStr{}, false
	}
}

// KeyOps returns the key ops value. It returns false if the value is missing
// or not a valid type.
func (k Key) KeyOps() []IntOrStr {
	v, ok := k[KeyOpsKeyLabel]
	if !ok {
		return nil
	}
	anyOps, ok := v.([]any)
	if !ok {
		return nil
	}
	ops := make([]IntOrStr, len(anyOps))
	for i, op := range anyOps {
		switch op := op.(type) {
		case int64:
			ops[i].Int64 = op
		case string:
			ops[i].Str = op
		}
	}
	return ops
}

// BaseIV returns the base IV value. It returns false if the value is missing
// or not a valid type.
func (k Key) BaseIV() ([]byte, bool) {
	v, ok := k[BaseIVKeyLabel]
	if !ok {
		return nil, false
	}
	b, ok := v.([]byte)
	return b, ok
}

// Public returns the public portion of the key.
func (k Key) Public() (crypto.PublicKey, error) {
	if !k.IsEllipticCurveKey() {
		return nil, fmt.Errorf("only elliptic curve keys are currently supported")
	}
	priv, err := k.ec2()
	if err != nil {
		return nil, err
	}
	return priv.Public(), nil
}

// Curve Names
//
// +---------+-------+----------+------------------------------------+
// | Name    | Value | Key Type | Description                        |
// +---------+-------+----------+------------------------------------+
// | P-256   | 1     | EC2      | NIST P-256 also known as secp256r1 |
// | P-384   | 2     | EC2      | NIST P-384 also known as secp384r1 |
// | P-521   | 3     | EC2      | NIST P-521 also known as secp521r1 |
// | X25519  | 4     | OKP      | X25519 for use w/ ECDH only        |
// | X448    | 5     | OKP      | X448 for use w/ ECDH only          |
// | Ed25519 | 6     | OKP      | Ed25519 for use w/ EdDSA only      |
// | Ed448   | 7     | OKP      | Ed448 for use w/ EdDSA only        |
// +---------+-------+----------+------------------------------------+

// EC Key Parameters
//
// +-------+------+-------+--------+-----------------------------------+
// | Key   | Name | Label | CBOR   | Description                       |
// | Type  |      |       | Type   |                                   |
// +-------+------+-------+--------+-----------------------------------+
// | 2     | crv  | -1    | int /  | EC identifier - Taken from the    |
// |       |      |       | tstr   | "COSE Elliptic Curves" registry   |
// | 2     | x    | -2    | bstr   | x-coordinate                      |
// | 2     | y    | -3    | bstr / | y-coordinate                      |
// |       |      |       | bool   |                                   |
// | 2     | d    | -4    | bstr   | Private key                       |
// +-------+------+-------+--------+-----------------------------------+
func (k Key) ec2() (*ecdsa.PrivateKey, error) { //nolint:gocyclo
	if !k.IsEllipticCurveKey() {
		return nil, fmt.Errorf("not an elliptic curve key")
	}

	var key ecdsa.PrivateKey

	// Parse the curve
	crv, ok := k[KeyLabel{Int64: -1}]
	if !ok {
		return nil, fmt.Errorf("EC crv parameter is not present")
	}
	switch crv := crv.(type) {
	case int64:
		switch crv {
		case 1:
			key.Curve = elliptic.P256()
		case 2:
			key.Curve = elliptic.P384()
		case 3:
			key.Curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unknown EC key curve: %d", crv)
		}
	case string:
		return nil, fmt.Errorf("unknown EC key curve: %s", crv)
	default:
		return nil, fmt.Errorf("invalid EC crv type: %T", crv)
	}

	// Parse the (optional) private D coord
	d, isPrivate := k[KeyLabel{Int64: -4}]
	if isPrivate {
		db, ok := d.([]byte)
		if !ok {
			return nil, fmt.Errorf("invalid EC d type: %T", d)
		}
		key.D = new(big.Int).SetBytes(db)
		key.X, key.Y = key.ScalarBaseMult(db)
	}

	// Parse the public X coord
	x, ok := k[KeyLabel{Int64: -2}]
	if !ok {
		return nil, fmt.Errorf("EC x parameter is not present")
	}
	xb, ok := x.([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid EC x type: %T", x)
	}
	pubX := new(big.Int).SetBytes(xb)
	if isPrivate && pubX.Cmp(key.X) != 0 {
		return nil, fmt.Errorf("invalid EC key: X coord does not match D")
	}
	key.X = pubX

	// Parse the public Y coord
	y, ok := k[KeyLabel{Int64: -3}]
	if !ok {
		return nil, fmt.Errorf("EC y parameter is not present")
	}
	switch y := y.(type) {
	case []byte:
		pubY := new(big.Int).SetBytes(y)
		if isPrivate && pubY.Cmp(key.Y) != 0 {
			return nil, fmt.Errorf("invalid EC key: Y coord does not match D")
		}
		key.Y = pubY
	case bool:
		return nil, fmt.Errorf("EC y sign bit not supported")
	default:
		return nil, fmt.Errorf("invalid EC y type: %T", y)
	}

	return &key, nil
}
