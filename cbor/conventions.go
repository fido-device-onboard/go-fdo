// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cbor

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
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

// MarshalCBORStream implements StreamMarshaler.
func (b Bstr[T]) MarshalCBORStream(w io.Writer, o EncoderOptions, flattened int) error {
	data, err := Marshal(b.Val)
	if err != nil {
		return err
	}
	if data == nil { // possibly due to bad Marshaler implementation
		data = []byte{}
	}
	enc := NewEncoder(w)
	enc.EncoderOptions = o
	return enc.Encode(data)
}

// UnmarshalCBORStream implements StreamUnmarshaler.
func (b *Bstr[T]) UnmarshalCBORStream(r io.Reader, o DecoderOptions, flattened int) error {
	dec := NewDecoder(r)
	dec.DecoderOptions = o

	n, err := dec.UnwrapBytes()
	if errors.Is(err, ErrNullOrUndefined) {
		return nil
	}
	if err != nil {
		return err
	}
	if n > math.MaxInt64 {
		return fmt.Errorf("bstr too long to decode")
	}
	r = io.LimitReader(r, int64(n))

	dec = NewDecoder(r)
	dec.DecoderOptions = o
	return dec.Decode(&b.Val)
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

// MarshalCBORStream implements StreamMarshaler.
func (b ByteWrap[T]) MarshalCBORStream(w io.Writer, o EncoderOptions, flattened int) error {
	enc := NewEncoder(w)
	enc.EncoderOptions = o
	if bs, ok := any(b.Val).([]byte); ok {
		return enc.Encode(bs)
	}
	return enc.Encode(Bstr[T](b))
}

// UnmarshalCBORStream implements StreamUnmarshaler.
func (b *ByteWrap[T]) UnmarshalCBORStream(r io.Reader, o DecoderOptions, flattened int) error {
	dec := NewDecoder(r)
	dec.DecoderOptions = o

	n, err := dec.UnwrapBytes()
	if errors.Is(err, ErrNullOrUndefined) {
		return nil
	}
	if err != nil {
		return err
	}
	if n > math.MaxInt64 {
		return fmt.Errorf("bytewrap too long to decode")
	}
	r = io.LimitReader(r, int64(n))

	if bs, ok := any(&b.Val).(*[]byte); ok {
		*bs = make([]byte, n)
		_, err := io.ReadFull(r, *bs)
		return err
	}

	dec = NewDecoder(r)
	dec.DecoderOptions = o
	return dec.Decode(&b.Val)
}

// X509Certificate is a newtype for x509.Certificate implementing proper CBOR
// encoding.
type X509Certificate x509.Certificate

// MarshalCBORStream implements StreamMarshaler.
func (c *X509Certificate) MarshalCBORStream(w io.Writer, o EncoderOptions, flattened int) error {
	enc := NewEncoder(w)
	enc.EncoderOptions = o
	if c == nil {
		return enc.Encode(nil)
	}
	return enc.Encode(c.Raw)
}

// UnmarshalCBORStream implements StreamUnmarshaler.
func (c *X509Certificate) UnmarshalCBORStream(r io.Reader, o DecoderOptions, flattened int) error {
	if c == nil {
		return errors.New("cannot unmarshal to a nil pointer")
	}

	dec := NewDecoder(r)
	dec.DecoderOptions = o

	n, err := dec.UnwrapBytes()
	if errors.Is(err, ErrNullOrUndefined) {
		return nil
	}
	if err != nil {
		return err
	}

	der := make([]byte, n)
	if _, err := io.ReadFull(r, der); err != nil {
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

// MarshalCBORStream implements StreamMarshaler.
func (c X509CertificateRequest) MarshalCBORStream(w io.Writer, o EncoderOptions, flattened int) error {
	enc := NewEncoder(w)
	enc.EncoderOptions = o
	return enc.Encode(c.Raw)
}

// UnmarshalCBORStream implements StreamUnmarshaler.
func (c *X509CertificateRequest) UnmarshalCBORStream(r io.Reader, o DecoderOptions, flattened int) error {
	if c == nil {
		return errors.New("cannot unmarshal to a nil pointer")
	}

	dec := NewDecoder(r)
	dec.DecoderOptions = o

	n, err := dec.UnwrapBytes()
	if errors.Is(err, ErrNullOrUndefined) {
		return nil
	}
	if err != nil {
		return err
	}

	der := make([]byte, n)
	if _, err := io.ReadFull(r, der); err != nil {
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

// MarshalCBORStream implements StreamMarshaler.
func (ts Timestamp) MarshalCBORStream(w io.Writer, o EncoderOptions, flattened int) error {
	enc := NewEncoder(w)
	enc.EncoderOptions = o
	if time.Time(ts).IsZero() {
		return enc.Encode(nil)
	}
	return enc.Encode(Tag[int]{
		Num: 1,
		Val: time.Time(ts).UTC().Second(),
	})
}

// UnmarshalCBORStream implements StreamUnmarshaler.
func (ts *Timestamp) UnmarshalCBORStream(r io.Reader, o DecoderOptions, flattened int) error {
	dec := NewDecoder(r)
	dec.DecoderOptions = o

	tag, err := dec.Untag()
	if errors.Is(err, ErrNullOrUndefined) {
		// If value is null, set timestamp to zero value
		*ts = Timestamp(time.Time{})
		return nil
	}
	if err != nil {
		return err
	}

	switch tag {
	// Tag 0: Parse string as RFC3339
	case 0:
		var value string
		if err := dec.Decode(&value); err != nil {
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
		if err := dec.Decode(&sec); err != nil {
			return err
		}
		*ts = Timestamp(time.Unix(sec, 0))
		return nil
	}

	return fmt.Errorf("unknown tag number %d", tag)
}
