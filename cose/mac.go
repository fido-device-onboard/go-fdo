// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import (
	"fmt"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// Mac0 is a message authentication code structure that is used when the
// recipient structure is not needed, because the key to be used is implicitly
// known.
type Mac0[T, E any] struct {
	Header
	Payload *cbor.ByteWrap[T] // null when transported separately
	Value   []byte            // non-empty byte string containing the MAC
}

// Tag is a helper for converting to a tag value.
func (m0 Mac0[T, E]) Tag() *Mac0Tag[T, E] { return &Mac0Tag[T, E]{m0} }

// Digest the payload and set the Value. Unless it was transported
// independently of the mac, payload may be nil. For empty AAD, the type should
// be []byte.
func (m0 *Mac0[T, E]) Digest(alg MacAlgorithm, key []byte, payload *T, aad E) error {
	// Set mac algorithm protected header
	if m0.Protected == nil {
		m0.Protected = make(HeaderMap)
	}
	m0.Protected[AlgLabel] = alg

	// Partially encode the protected header
	protected, err := newEmptyOrSerializedMap(m0.Protected)
	if err != nil {
		return fmt.Errorf("error marshaling protected header map: %w", err)
	}

	// Set payload
	if m0.Payload == nil && payload == nil {
		return fmt.Errorf("payload must be provided when independently transported")
	}
	macPayload := m0.Payload
	if macPayload == nil {
		macPayload = cbor.NewByteWrap(*payload)
	}

	// Encode and mac
	w, err := alg.NewMac(key)
	if err != nil {
		return err
	}
	if err := cbor.NewEncoder(w).Encode(mac[T, E]{
		Context:     mac0Context,
		Protected:   protected,
		ExternalAAD: *cbor.NewByteWrap(aad),
		Payload:     *macPayload,
	}); err != nil {
		return err
	}
	m0.Value = w.Sum(nil)

	return nil
}

const (
	macContext  = "MAC"
	mac0Context = "MAC0"
)

// Underlying message authentication code struct
type mac[T, E any] struct {
	Context     string
	Protected   emptyOrSerializedMap
	ExternalAAD cbor.ByteWrap[E]
	Payload     cbor.ByteWrap[T]
}

// Mac0Tag encodes to a CBOR tag while ensuring the right tag number.
type Mac0Tag[T, E any] struct {
	Mac0[T, E]
}

// Untag is a helper for accessing the tag value.
func (t Mac0Tag[T, E]) Untag() *Mac0[T, E] { return &t.Mac0 }

// MarshalCBOR implements cbor.Marshaler.
func (t Mac0Tag[T, E]) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(cbor.Tag[Mac0[T, E]]{
		Num: Mac0TagNum,
		Val: t.Mac0,
	})
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (t *Mac0Tag[T, E]) UnmarshalCBOR(data []byte) error {
	var tag cbor.Tag[Mac0[T, E]]
	if err := cbor.Unmarshal(data, &tag); err != nil {
		return err
	}
	if tag.Num != Mac0TagNum {
		return fmt.Errorf("mismatched tag number %d for Mac0, expected %d", tag.Num, Mac0TagNum)
	}
	*t = Mac0Tag[T, E]{tag.Val}
	return nil
}
