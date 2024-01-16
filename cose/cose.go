// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// CBOR Object Signing and Encryption (COSE) defined in RFC8152
package cose

import (
	"fmt"
	"strconv"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// Algorithm is the ECDSA/RSASSA-PKCS1-v1_5/RSASSA-PKCS1-v1_5 signature type
// and hash.
type Algorithm int16

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
	ES256Alg Algorithm = -7
	ES384Alg Algorithm = -35
	ES512Alg Algorithm = -36
)

var (
	es256AlgCbor cbor.RawBytes
	es384AlgCbor cbor.RawBytes
	es512AlgCbor cbor.RawBytes
)

func init() {
	var err error
	es256AlgCbor, err = cbor.Marshal(ES256Alg)
	if err != nil {
		panic("error marshaling ES256 algorithm ID: " + err.Error())
	}
	es384AlgCbor, err = cbor.Marshal(ES384Alg)
	if err != nil {
		panic("error marshaling ES384 algorithm ID: " + err.Error())
	}
	es512AlgCbor, err = cbor.Marshal(ES512Alg)
	if err != nil {
		panic("error marshaling ES512 algorithm ID: " + err.Error())
	}
}

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
	RS256Alg Algorithm = -257
	RS384Alg Algorithm = -258
	RS512Alg Algorithm = -259
)

var (
	rs256AlgCbor cbor.RawBytes
	rs384AlgCbor cbor.RawBytes
	rs512AlgCbor cbor.RawBytes
)

func init() {
	var err error
	rs256AlgCbor, err = cbor.Marshal(RS256Alg)
	if err != nil {
		panic("error marshaling RS256 algorithm ID: " + err.Error())
	}
	rs384AlgCbor, err = cbor.Marshal(RS384Alg)
	if err != nil {
		panic("error marshaling RS384 algorithm ID: " + err.Error())
	}
	rs512AlgCbor, err = cbor.Marshal(RS512Alg)
	if err != nil {
		panic("error marshaling RS512 algorithm ID: " + err.Error())
	}
}

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
	PS256Alg Algorithm = -37
	PS384Alg Algorithm = -38
	PS512Alg Algorithm = -39
)

var (
	ps256AlgCbor cbor.RawBytes
	ps384AlgCbor cbor.RawBytes
	ps512AlgCbor cbor.RawBytes
)

func init() {
	var err error
	ps256AlgCbor, err = cbor.Marshal(PS256Alg)
	if err != nil {
		panic("error marshaling PS256 algorithm ID: " + err.Error())
	}
	ps384AlgCbor, err = cbor.Marshal(PS384Alg)
	if err != nil {
		panic("error marshaling PS384 algorithm ID: " + err.Error())
	}
	ps512AlgCbor, err = cbor.Marshal(PS512Alg)
	if err != nil {
		panic("error marshaling PS512 algorithm ID: " + err.Error())
	}
}

// Header is a type for embedding protected and unprotected headers into many
// COSE structures.
type Header struct {
	Protected   serializedOrEmptyHeaderMap // wrapped in byte string, zero len if map is empty
	Unprotected headerMap                  // encoded like a normal map
}

// NewHeader takes protected and unprotected header maps and marshals their
// values and puts them in a Header for embedding into COSE structures.
func NewHeader(protected, unprotected map[Label]any) (Header, error) {
	protectedHeader, err := newSerializedOrEmptyHeaderMap(protected)
	if err != nil {
		return Header{}, err
	}
	unprotectedHeader, err := newHeaderMap(unprotected)
	if err != nil {
		return Header{}, err
	}
	return Header{
		Protected:   protectedHeader,
		Unprotected: unprotectedHeader,
	}, nil
}

// Algorithm returns the ID of the algorithm set in the protected headers. If
// no algorithm is set or the value is not a number, then 0 is returned.
func (hdr Header) Algorithm() Algorithm {
	data, ok := mapGet(hdr.Protected, AlgLabel)
	if !ok {
		return 0
	}
	var alg Algorithm
	if err := cbor.Unmarshal(data, &alg); err != nil {
		return 0
	}
	return alg
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
		| crit      | 2     | [+ label]      | COSE Header | Critical       |
		|           |       |                | Parameters  | headers to be  |
		|           |       |                | registry    | understood     |
		| content   | 3     | tstr / uint    | CoAP        | Content type   |
		| type      |       |                | Content-    | of the payload |
		|           |       |                | Formats or  |                |
		|           |       |                | Media Types |                |
		|           |       |                | registries  |                |
		| kid       | 4     | bstr           |             | Key identifier |
		| IV        | 5     | bstr           |             | Full           |
		|           |       |                |             | Initialization |
		|           |       |                |             | Vector         |
		| Partial   | 6     | bstr           |             | Partial        |
		| IV        |       |                |             | Initialization |
		|           |       |                |             | Vector         |
		| counter   | 7     | COSE_Signature |             | CBOR-encoded   |
		| signature |       | / [+           |             | signature      |
		|           |       | COSE_Signature |             | structure      |
		|           |       | ]              |             |                |
		+-----------+-------+----------------+-------------+----------------+
*/
var (
	AlgLabel = Label{Int64: 1}
)

// Label is used for [HeaderMap]s and can be either an int64 or a string.
type Label struct {
	Int64 int64
	Str   string
}

func (l Label) String() string {
	if l.Int64 > 0 {
		return strconv.FormatInt(l.Int64, 10)
	}
	return l.Str
}

func (l Label) MarshalCBOR() ([]byte, error) {
	// 0 is a reserved label
	if l.Int64 != 0 {
		return cbor.Marshal(l.Int64)
	}
	return cbor.Marshal(l.String)
}

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

// headerMap contains protected or unprotected key-value pairs.
type headerMap map[Label]cbor.RawBytes

// newHeaderMap marhsals the values of a header map.
func newHeaderMap(unmarshaled map[Label]any) (headerMap, error) {
	marshaled := make(headerMap)
	for label, v := range unmarshaled {
		data, err := cbor.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("error serializing header value for label %s: %w", label, err)
		}
		marshaled[label] = data
	}
	return marshaled, nil
}

// serializedOrEmptyHeaderMap encodes to/from a CBOR byte string which either
// contains a serialized non-empty map or is empty itself.
type serializedOrEmptyHeaderMap = cbor.Bstr[omitEmpty[headerMap]]

// newSerializedOrEmptyHeaderMap marshals the values of a header map and wraps
// it in a SerializedOrEmptyHeaders type.
func newSerializedOrEmptyHeaderMap(unmarshaled map[Label]any) (serializedOrEmptyHeaderMap, error) {
	hmap, err := newHeaderMap(unmarshaled)
	return serializedOrEmptyHeaderMap{
		Val: omitEmpty[headerMap]{
			Val: hmap,
		},
	}, err
}

func mapGet(m serializedOrEmptyHeaderMap, l Label) (val cbor.RawBytes, ok bool) {
	if m.Val.Val == nil {
		return nil, false
	}
	val, ok = m.Val.Val[l]
	return
}

func mapSet(m *serializedOrEmptyHeaderMap, l Label, b cbor.RawBytes) {
	if m.Val.Val == nil {
		m.Val.Val = make(headerMap)
	}
	m.Val.Val[l] = b
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
