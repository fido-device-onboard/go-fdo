// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cbor

import (
	"crypto/x509"
	"errors"
	"fmt"
)

// Bstr marshals and unmarshals CBOR data that is a byte array of the CBOR
// encoding of its underlying value.
//
// This is a common convention in specifications like COSE and FDO and acts as
// a sort of type erasure. While a specification may wish to erase a type to
// allow for operating on arbitrary data (i.e. payloads in COSE signature
// structures), implementations sometimes _do_ want to specify the encoded
// type.
//
// This generic bstr structure conveys type information as well as handles
// automatically unmarshaling into the proper type. If type erasure is indeed
// desired, then use a type alias: `type bstr = cbor.Bstr[cbor.RawBytes]`.
type Bstr[T any] struct{ Val T }

// NewBstr is shorthand for struct initialization and is useful, because it
// often does not require writing the type parameter.
func NewBstr[T any](v T) Bstr[T] { return Bstr[T]{Val: v} }

// NewBstrPtr is shorthand for struct initialization and is useful, because it
// often does not require writing the type parameter.
func NewBstrPtr[T any](v T) *Bstr[T] { return &Bstr[T]{Val: v} }

// MarshalCBOR implements Marshaler.
func (b Bstr[T]) MarshalCBOR() ([]byte, error) {
	data, err := Marshal(b.Val)
	if err != nil {
		return nil, err
	}
	return Marshal(data)
}

// UnmarshalCBOR implements Unmarshaler.
func (b *Bstr[T]) UnmarshalCBOR(p []byte) error {
	var data []byte
	if err := Unmarshal(p, &data); err != nil {
		return err
	}
	return Unmarshal(data, &b.Val)
}

// X509Certificate is a newtype for x509.X509Certificate implementing proper CBOR
// encoding.
type X509Certificate x509.Certificate

// MarshalCBOR implements Marshaler interface.
func (c *X509Certificate) MarshalCBOR() ([]byte, error) {
	if c == nil {
		return Marshal(nil)
	}
	return Marshal(c.Raw)
}

// UnmarshalCBOR implements Unmarshaler interface.
func (c *X509Certificate) UnmarshalCBOR(data []byte) error {
	if c == nil {
		return errors.New("cannot unmarshal to a nil pointer")
	}
	var der []byte
	if err := Unmarshal(data, &der); err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("error parsing x509 certificate DER-encoded bytes: %w", err)
	}
	*c = X509Certificate(*cert)
	return nil
}
