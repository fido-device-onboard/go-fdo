// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cbor

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// Bstr marshals and unmarshals CBOR data that is a byte array of the CBOR
// encoding of its underlying value.
//
//	CDDL: bstr .cbor T
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
func NewBstr[T any](v T) *Bstr[T] { return &Bstr[T]{Val: v} }

// MarshalCBOR implements Marshaler.
func (b Bstr[T]) MarshalCBOR() ([]byte, error) {
	data, err := Marshal(b.Val)
	if err != nil {
		return nil, err
	}
	if data == nil { // possibly due to bad Marshaler implementation
		data = []byte{}
	}
	return Marshal(data)
}

// UnmarshalCBOR implements Unmarshaler.
func (b *Bstr[T]) UnmarshalCBOR(p []byte) error {
	var data []byte
	if err := Unmarshal(p, &data); err != nil {
		return err
	}
	if data == nil {
		return nil // decoded null or undefined
	}
	return Unmarshal(data, &b.Val)
}

// ByteWrap is a Bstr that treats Bstr[[]byte] as Bstr[cbor.RawBytes]. While
// Bstr guarantees that the inner bytes are valid CBOR, ByteWrap does not.
// ByteWrap only ensures that the marshaled type is a bytestring.
//
// In other words, it avoids double-encoding a byte string. This convention is
// used in COSE.
type ByteWrap[T any] struct{ Val T }

// NewByteWrap is shorthand for struct initialization and is useful, because
// it often does not require writing the type parameter.
func NewByteWrap[T any](v T) *ByteWrap[T] { return &ByteWrap[T]{Val: v} }

// MarshalCBOR implements Marshaler.
func (b ByteWrap[T]) MarshalCBOR() ([]byte, error) {
	if bs, ok := any(b.Val).([]byte); ok {
		return Marshal(bs)
	}
	return Marshal(Bstr[T](b))
}

// UnmarshalCBOR implements Unmarshaler.
func (b *ByteWrap[T]) UnmarshalCBOR(p []byte) error {
	var data []byte
	if err := Unmarshal(p, &data); err != nil {
		return err
	}
	if bs, ok := any(&b.Val).(*[]byte); ok {
		*bs = data
		return nil
	}
	return Unmarshal(data, &b.Val)
}

// X509Certificate is a newtype for x509.Certificate implementing proper CBOR
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

// X509CertificateRequest is a newtype for x509.CertificateRequest implementing
// proper CBOR encoding.
type X509CertificateRequest x509.CertificateRequest

// MarshalCBOR implements Marshaler interface.
func (c X509CertificateRequest) MarshalCBOR() ([]byte, error) { return Marshal(c.Raw) }

// UnmarshalCBOR implements Unmarshaler interface.
func (c *X509CertificateRequest) UnmarshalCBOR(data []byte) error {
	if c == nil {
		return errors.New("cannot unmarshal to a nil pointer")
	}
	var der []byte
	if err := Unmarshal(data, &der); err != nil {
		return err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return fmt.Errorf("error parsing x509 certificate request DER-encoded bytes: %w", err)
	}
	*c = X509CertificateRequest(*csr)
	return nil
}

// Timestamp implements the timestamp CBOR format used in the FDO error message
// type. The expected string format, if used, is RFC3339.
//
//	timestamp = null / UTCStr / UTCInt / TIME_T
//	UTCStr = #6.0(tstr)
//	UTCInt = #6.1(uint)
//	TIMET  = #6.1(uint)
type Timestamp time.Time

// MarshalCBOR implements Marshaler.
func (ts Timestamp) MarshalCBOR() ([]byte, error) {
	if time.Time(ts).IsZero() {
		return Marshal(nil)
	}
	return Marshal(Tag[int]{
		Num: 1,
		Val: time.Time(ts).UTC().Second(),
	})
}

// UnmarshalCBOR implements Unmarshaler.
func (ts *Timestamp) UnmarshalCBOR(data []byte) error {
	// Parse into a null or tag structure
	var tag *Tag[RawBytes]
	if err := Unmarshal(data, &tag); err != nil {
		return err
	}

	// If value is null, set timestamp to zero value
	if tag == nil {
		*ts = Timestamp(time.Time{})
		return nil
	}

	switch tag.Number() {
	// Tag 0: Parse string as RFC3339
	case 0:
		var value string
		if err := Unmarshal([]byte(tag.Val), &value); err != nil {
			return err
		}
		t, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return fmt.Errorf("invalid timestamp string, must be RFC3339 format: %w", err)
		}
		*ts = Timestamp(t)
		return nil

	// Tag 1: Parse uint as seconds
	case 1:
		var sec int64
		if err := Unmarshal([]byte(tag.Val), &sec); err != nil {
			return err
		}
		*ts = Timestamp(time.Unix(sec, 0))
		return nil
	}

	return fmt.Errorf("unknown tag number %d", tag.Number())
}
