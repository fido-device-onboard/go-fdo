// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import (
	"fmt"
	"io"
	"strconv"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// Header is a type for embedding protected and unprotected headers into many
// COSE structures.
type Header struct {
	Protected   HeaderMap
	Unprotected HeaderMap
}

var _ cbor.FlatMarshaler = (*Header)(nil)
var _ cbor.FlatUnmarshaler = (*Header)(nil)

// FlatMarshalCBOR implements cbor.FlatMarshaler.
func (hdr Header) FlatMarshalCBOR(w io.Writer) error {
	protectedHeader, err := newEmptyOrSerializedMap(hdr.Protected)
	if err != nil {
		return err
	}
	unprotectedHeader, err := newRawHeaderMap(hdr.Unprotected)
	if err != nil {
		return err
	}

	enc := cbor.NewEncoder(w)
	if err := enc.Encode(protectedHeader); err != nil {
		return err
	}
	return enc.Encode(unprotectedHeader)
}

// FlatUnmarshalCBOR implements cbor.FlatUnmarshaler.
func (hdr *Header) FlatUnmarshalCBOR(r io.Reader) error {
	dec := cbor.NewDecoder(r)

	var protectedHeader emptyOrSerializedMap
	if err := dec.Decode(&protectedHeader); err != nil {
		return err
	}

	var unprotectedHeader rawHeaderMap
	if err := dec.Decode(&unprotectedHeader); err != nil {
		return err
	}

	hdr.Protected = make(map[Label]any)
	for k, raw := range protectedHeader.Val.Val {
		var v any
		if err := cbor.Unmarshal([]byte(raw), &v); err != nil {
			return fmt.Errorf("error decoding protected value for %s: %w", k, err)
		}
		hdr.Protected[k] = v
	}

	hdr.Unprotected = make(map[Label]any)
	for k, raw := range unprotectedHeader {
		var v any
		if err := cbor.Unmarshal([]byte(raw), &v); err != nil {
			return fmt.Errorf("error decoding unprotected value for %s: %w", k, err)
		}
		hdr.Unprotected[k] = v
	}

	return nil
}

// HeaderMap is used for protected and unprotected headers, which must have an
// int or string key and any value.
type HeaderMap map[Label]any

// Parse is a helper to get values from the header map as the expected type.
// Because a HeaderMap unmarshals values to an any interface, their type
// follows the rules of the CBOR unmarshaler. Parse marshals a value back to
// CBOR and then unmarshals it into the provided pointer type v.
func (hm HeaderMap) Parse(l Label, v any) (bool, error) {
	if hm == nil || hm[l] == nil {
		return false, nil
	}
	data, err := cbor.Marshal(hm[l])
	if err != nil {
		return true, err
	}
	return true, cbor.Unmarshal(data, v)
}

// HeaderParser decodes headers and is a read-only interface.
type HeaderParser interface {
	// Parse gets values from the header map as the expected type. v must be a
	// pointer type, where the underlying value will be set.
	Parse(l Label, v any) (bool, error)
}

/*
Common labels

	+-----------+-------+----------------+-------------+----------------+
	| Name      | Label | Value Type     | Value       | Description    |
	|           |       |                | Registry    |                |
	+-----------+-------+----------------+-------------+----------------+
	| alg       | 1     | int / tstr     | COSE        | Cryptographic  |
	|           |       |                | Algorithms  | algorithm to   |
	|           |       |                | registry    | use            |
	| --------- | ----- | -------------- | ----------- | -------------- |
	| crit      | 2     | [+ label]      | COSE Header | Critical       |
	|           |       |                | Parameters  | headers to be  |
	|           |       |                | registry    | understood     |
	| --------- | ----- | -------------- | ----------- | -------------- |
	| content   | 3     | tstr / uint    | CoAP        | Content type   |
	| type      |       |                | Content-    | of the payload |
	|           |       |                | Formats or  |                |
	|           |       |                | Media Types |                |
	|           |       |                | registries  |                |
	| --------- | ----- | -------------- | ----------- | -------------- |
	| kid       | 4     | bstr           |             | Key identifier |
	| --------- | ----- | -------------- | ----------- | -------------- |
	| IV        | 5     | bstr           |             | Full           |
	|           |       |                |             | Initialization |
	|           |       |                |             | Vector         |
	| --------- | ----- | -------------- | ----------- | -------------- |
	| Partial   | 6     | bstr           |             | Partial        |
	| IV        |       |                |             | Initialization |
	|           |       |                |             | Vector         |
	| --------- | ----- | -------------- | ----------- | -------------- |
	| counter   | 7     | COSE_Signature |             | CBOR-encoded   |
	| signature |       | / [+           |             | signature      |
	|           |       | COSE_Signature |             | structure      |
	|           |       | ]              |             |                |
	+-----------+-------+----------------+-------------+----------------+
*/
var (
	AlgLabel = Label{Int64: 1}
	IvLabel  = Label{Int64: 5}
)

// Label is used for [HeaderMap]s and can be either an int64 or a string.
type Label struct {
	Int64 int64
	Str   string
}

func (l Label) String() string {
	if l.Int64 != 0 {
		return strconv.FormatInt(l.Int64, 10)
	}
	return l.Str
}

// MarshalCBOR implements cbor.Marshaler.
func (l Label) MarshalCBOR() ([]byte, error) {
	// 0 is a reserved label
	if l.Int64 != 0 {
		return cbor.Marshal(l.Int64)
	}
	return cbor.Marshal(l.String)
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (l *Label) UnmarshalCBOR(b []byte) error {
	var v any
	if err := cbor.Unmarshal(b, &v); err != nil {
		return err
	}
	switch v := v.(type) {
	case int64:
		l.Int64 = v
		l.Str = ""
	case string:
		l.Int64 = 0
		l.Str = v
	default:
		return fmt.Errorf("unexpected label type: %T", v)
	}
	return nil
}

// rawHeaderMap contains protected or unprotected key-value pairs.
type rawHeaderMap map[Label]cbor.RawBytes

// newRawHeaderMap marhsals the values of a header map.
func newRawHeaderMap(unmarshaled map[Label]any) (rawHeaderMap, error) {
	marshaled := make(rawHeaderMap)
	for label, v := range unmarshaled {
		data, err := cbor.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("error serializing header value for label %s: %w", label, err)
		}
		marshaled[label] = data
	}
	return marshaled, nil
}

// emptyOrSerializedMap encodes to/from a CBOR byte string which either
// contains a serialized non-empty map or is empty itself.
type emptyOrSerializedMap = cbor.Bstr[omitEmpty[rawHeaderMap]]

// newEmptyOrSerializedMap marshals the values of a header map and wraps
// it in a SerializedOrEmptyHeaders type.
func newEmptyOrSerializedMap(unmarshaled map[Label]any) (emptyOrSerializedMap, error) {
	hmap, err := newRawHeaderMap(unmarshaled)
	return emptyOrSerializedMap{
		Val: omitEmpty[rawHeaderMap]{
			Val: hmap,
		},
	}, err
}

// omitEmpty encodes a zero value (zero, empty array, empty map) as zero bytes.
type omitEmpty[T any] struct{ Val T }

func (o omitEmpty[T]) MarshalCBOR() ([]byte, error) {
	b, err := cbor.Marshal(o.Val)
	if err != nil {
		return nil, err
	}
	if len(b) != 1 {
		return b, nil
	}
	switch b[0] {
	case 0x00, 0x40, 0x60, 0x80, 0xa0:
		return []byte{}, nil
	default:
		return b, nil
	}
}

func (o *omitEmpty[T]) UnmarshalCBOR(b []byte) error { return cbor.Unmarshal(b, &o.Val) }
