// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import (
	"crypto"
	"fmt"

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
	signTag     uint64 = 98
	sign1Tag    uint64 = 18
	encryptTag  uint64 = 96
	encrypt0Tag uint64 = 16
	macTag      uint64 = 97
	mac0Tag     uint64 = 17
)

// SignTag encodes to a CBOR tag while ensuring the right tag number.
type SignTag[T any] Sign[T]

// Tag is a helper for accessing the tag value.
func (t *Sign[T]) Tag() *SignTag[T] { return (*SignTag[T])(t) }

// Untag is a helper for accessing the tag value.
func (t *SignTag[T]) Untag() *Sign[T] { return (*Sign[T])(t) }

func (t SignTag[T]) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(cbor.Tag[Sign[T]]{
		Num: signTag,
		Val: Sign[T](t),
	})
}

func (t *SignTag[T]) UnmarshalCBOR(data []byte) error {
	var tag cbor.Tag[Sign[T]]
	if err := cbor.Unmarshal(data, &tag); err != nil {
		return err
	}
	if tag.Num != signTag {
		return fmt.Errorf("mismatched tag number %d for Sign, expected %d", tag.Num, signTag)
	}
	*t = SignTag[T](tag.Val)
	return nil
}

// Sign1Tag encodes to a CBOR tag while ensuring the right tag number.
type Sign1Tag[T any] Sign1[T]

// Tag is a helper for accessing the tag value.
func (t *Sign1[T]) Tag() *Sign1Tag[T] { return (*Sign1Tag[T])(t) }

// Untag is a helper for accessing the tag value.
func (t *Sign1Tag[T]) Untag() *Sign1[T] { return (*Sign1[T])(t) }

func (t Sign1Tag[T]) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(cbor.Tag[Sign1[T]]{
		Num: sign1Tag,
		Val: Sign1[T](t),
	})
}

func (t *Sign1Tag[T]) UnmarshalCBOR(data []byte) error {
	var tag cbor.Tag[Sign1[T]]
	if err := cbor.Unmarshal(data, &tag); err != nil {
		return err
	}
	if tag.Num != sign1Tag {
		return fmt.Errorf("mismatched tag number %d for Sign1, expected %d", tag.Num, sign1Tag)
	}
	*t = Sign1Tag[T](tag.Val)
	return nil
}

// Sign using a single private key. Unless it was transported independently of
// the signature, payload may be nil.
func (s1 *Sign1Tag[T]) Sign(key crypto.PrivateKey, payload []byte, opts crypto.SignerOpts) error {
	return (*Sign1[T])(s1).Sign(key, payload, opts)
}

// Verify using a single public key. Unless it was transported independently of
// the signature, payload may be nil.
func (s1 *Sign1Tag[T]) Verify(key crypto.PublicKey, payload []byte) (bool, error) {
	return (*Sign1[T])(s1).Verify(key, payload)
}

// EncryptTag encodes to a CBOR tag while ensuring the right tag number.
type EncryptTag[T any] Encrypt[T]

// Tag is a helper for accessing the tag value.
func (t *Encrypt[T]) Tag() *EncryptTag[T] { return (*EncryptTag[T])(t) }

// Untag is a helper for accessing the tag value.
func (t *EncryptTag[T]) Untag() *Encrypt[T] { return (*Encrypt[T])(t) }

func (t EncryptTag[T]) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(cbor.Tag[Encrypt[T]]{
		Num: encryptTag,
		Val: Encrypt[T](t),
	})
}

func (t *EncryptTag[T]) UnmarshalCBOR(data []byte) error {
	var tag cbor.Tag[Encrypt[T]]
	if err := cbor.Unmarshal(data, &tag); err != nil {
		return err
	}
	if tag.Num != encryptTag {
		return fmt.Errorf("mismatched tag number %d for Encrypt, expected %d", tag.Num, encryptTag)
	}
	*t = EncryptTag[T](tag.Val)
	return nil
}

// Encrypt0Tag encodes to a CBOR tag while ensuring the right tag number.
type Encrypt0Tag[T any] Encrypt0[T]

// Tag is a helper for accessing the tag value.
func (t *Encrypt0[T]) Tag() *Encrypt0Tag[T] { return (*Encrypt0Tag[T])(t) }

// Untag is a helper for accessing the tag value.
func (t *Encrypt0Tag[T]) Untag() *Encrypt0[T] { return (*Encrypt0[T])(t) }

func (t Encrypt0Tag[T]) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(cbor.Tag[Encrypt0[T]]{
		Num: encrypt0Tag,
		Val: Encrypt0[T](t),
	})
}

func (t *Encrypt0Tag[T]) UnmarshalCBOR(data []byte) error {
	var tag cbor.Tag[Encrypt0[T]]
	if err := cbor.Unmarshal(data, &tag); err != nil {
		return err
	}
	if tag.Num != encrypt0Tag {
		return fmt.Errorf("mismatched tag number %d for Encrypt0, expected %d", tag.Num, encrypt0Tag)
	}
	*t = Encrypt0Tag[T](tag.Val)
	return nil
}

// MacTag encodes to a CBOR tag while ensuring the right tag number.
type MacTag[T any] Mac[T]

// Tag is a helper for accessing the tag value.
func (t *Mac[T]) Tag() *MacTag[T] { return (*MacTag[T])(t) }

// Untag is a helper for accessing the tag value.
func (t *MacTag[T]) Untag() *Mac[T] { return (*Mac[T])(t) }

func (t MacTag[T]) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(cbor.Tag[Mac[T]]{
		Num: macTag,
		Val: Mac[T](t),
	})
}

func (t *MacTag[T]) UnmarshalCBOR(data []byte) error {
	var tag cbor.Tag[Mac[T]]
	if err := cbor.Unmarshal(data, &tag); err != nil {
		return err
	}
	if tag.Num != macTag {
		return fmt.Errorf("mismatched tag number %d for Mac, expected %d", tag.Num, macTag)
	}
	*t = MacTag[T](tag.Val)
	return nil
}

// Mac0Tag encodes to a CBOR tag while ensuring the right tag number.
type Mac0Tag[T any] Mac0[T]

// Tag is a helper for accessing the tag value.
func (t *Mac0[T]) Tag() *Mac0Tag[T] { return (*Mac0Tag[T])(t) }

// Untag is a helper for accessing the tag value.
func (t *Mac0Tag[T]) Untag() *Mac0[T] { return (*Mac0[T])(t) }

func (t Mac0Tag[T]) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(cbor.Tag[Mac0[T]]{
		Num: mac0Tag,
		Val: Mac0[T](t),
	})
}

func (t *Mac0Tag[T]) UnmarshalCBOR(data []byte) error {
	var tag cbor.Tag[Mac0[T]]
	if err := cbor.Unmarshal(data, &tag); err != nil {
		return err
	}
	if tag.Num != mac0Tag {
		return fmt.Errorf("mismatched tag number %d for Mac0, expected %d", tag.Num, mac0Tag)
	}
	*t = Mac0Tag[T](tag.Val)
	return nil
}
