// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// Crypter uses a given key and cipher to encypt and decrypt data.
type Crypter interface {
	// Encrypt converts plaintext and additional authenticated data to
	// ciphertext using the implementer's key and cipher.
	//
	// The unprotected headers of the outgoing structure are returned in order
	// for data such as IVs for block mode ciphers to be added.
	//
	// The value of externalAAD will be nil if no AAD was provided and be
	// non-nil (and non-zero length, due to additional data COSE adds) if it
	// was provided.
	Encrypt(rand io.Reader, plaintext, externalAAD []byte) (ciphertext []byte, unprotected HeaderMap, err error)

	// Decrypt converts ciphertext and additional authenticated data to
	// plaintext using the implementer's key and cipher. the unprotected
	// headers of the incoming structure are provided for optionally reading in
	// unprotected data, such as an IV, which the cipher may need as input.
	//
	// The value of externalAAD will be nil if no AAD was provided and be
	// non-nil (and non-zero length, due to additional data COSE adds) if it
	// was provided.
	Decrypt(rand io.Reader, ciphertext, externalAAD []byte, unprotected HeaderParser) (plaintext []byte, err error)
}

// Encrypt0 holds the encrypted content of an enveloped structure. It assumes
// contains no recipient information and therefore assumes that the recipient
// of the object will already know the identity of the key to be used in order
// to decrypt the message.
type Encrypt0[T, E any] struct {
	Header     `cbor:",flat2"`
	Ciphertext *[]byte // byte string or null when transported separately
}

// Tag is a helper for converting to a tag value.
func (e0 Encrypt0[T, E]) Tag() *Encrypt0Tag[T, E] { return &Encrypt0Tag[T, E]{e0} }

// Encrypt a payload, setting the Chiphertext field value.
//
// The payload accepted is any type T, which will be marshaled to CBOR and if
// not already a CBOR byte string, then wrapped in one. The external AAD will
// be type E and the same marshaling rules apply.
//
// For encryption algorithms that do not take external additional authenticated
// data, aad must be nil. To pass no AAD to an AEAD, E should be []byte and aad
// should be either nil or a pointer to an empty byte slice.
func (e0 Encrypt0[T, E]) Encrypt(alg EncryptAlgorithm, key []byte, payload T, aad *E) error {
	// Get Crypter to perform encryption/decryption
	c, err := alg.NewCrypter(key)
	if err != nil {
		return fmt.Errorf("error intializing crypter for alg %d: %w", alg, err)
	}

	// Encode payload to plaintext
	plaintext, err := cbor.Marshal(cbor.NewByteWrap(payload))
	if err != nil {
		return fmt.Errorf("error marshaling payload to plaintext: %w", err)
	}

	// Encode additional authenticated data
	externalAAD, err := e0.externalAAD(aad)
	if err != nil {
		return err
	}

	// Perform encryption to ciphertext
	ciphertext, newUnprotected, err := c.Encrypt(rand.Reader, plaintext, externalAAD)
	if err != nil {
		return fmt.Errorf("error encrypting plaintext: %w", err)
	}
	if e0.Unprotected == nil {
		e0.Unprotected = make(HeaderMap)
	}
	for label, val := range newUnprotected {
		e0.Unprotected[label] = val
	}
	e0.Ciphertext = &ciphertext

	return nil
}

// Decrypt a payload from the Ciphertext field, automatically unmarshaling it
// to type T.
//
// For encryption algorithms that do not take external additional authenticated
// data, aad must be nil. To pass no AAD to an AEAD, E should be []byte and aad
// should be either nil or a pointer to an empty byte slice.
func (e0 Encrypt0[T, E]) Decrypt(alg EncryptAlgorithm, key []byte, aad *E) (*T, error) {
	// Get Crypter to perform encryption/decryption
	c, err := alg.NewCrypter(key)
	if err != nil {
		return nil, fmt.Errorf("error intializing crypter for alg %d: %w", alg, err)
	}

	// Add algorithm ID to protected header
	if e0.Protected == nil {
		e0.Protected = make(HeaderMap)
	}
	// TODO: Should this be done for non-AEAD?
	e0.Protected[AlgLabel] = alg

	// Encode additional authenticated data
	var externalAAD []byte
	if alg.SupportsAD() {
		var err error
		externalAAD, err = e0.externalAAD(aad)
		if err != nil {
			return nil, err
		}
	} else if aad != nil {
		return nil, fmt.Errorf("additional data provided, but the encryption algorithm does not support it")
	}

	// Perform decryption to plaintext
	if e0.Ciphertext == nil {
		return nil, fmt.Errorf("nil ciphertext")
	}
	plaintext, err := c.Decrypt(rand.Reader, *e0.Ciphertext, externalAAD, e0.Unprotected)
	if err != nil {
		return nil, fmt.Errorf("error decrypting ciphertext: %w", err)
	}

	// Decode plaintext into type T
	var val T
	if err := cbor.Unmarshal(plaintext, &val); err != nil {
		return nil, fmt.Errorf("error unmarshaling plaintext to %T: %w", val, err)
	}
	return &val, nil
}

// Build and encode Enc_structure
func (e0 Encrypt0[T, E]) externalAAD(aad *E) ([]byte, error) {
	protected, err := newEmptyOrSerializedMap(e0.Protected)
	if err != nil {
		return nil, fmt.Errorf("error marshaling protected header map: %w", err)
	}
	var eaad []byte
	if aad != nil {
		var err error
		eaad, err = cbor.Marshal(cbor.NewByteWrap(*aad))
		if err != nil {
			return nil, fmt.Errorf("error marshaling AAD: %w", err)
		}
	}
	enc, err := cbor.Marshal(encStruct{
		Context:     enc0Context,
		Protected:   protected,
		ExternalAAD: eaad,
	})
	if err != nil {
		return nil, fmt.Errorf("error marshaling Enc_structure: %w", err)
	}

	return enc, nil
}

const (
	encContext          = "Encrypt"
	enc0Context         = "Encrypt0"
	encRecipientContext = "Enc_Recipient"
	macRecipientContext = "Mac_Recipient"
	recRecipientContext = "Rec_Recipient"
)

// COSE Enc_structure
type encStruct struct {
	Context     string
	Protected   emptyOrSerializedMap
	ExternalAAD []byte
}

// Encrypt0Tag encodes to a CBOR tag while ensuring the right tag number.
type Encrypt0Tag[T, E any] struct {
	Encrypt0[T, E]
}

// Untag is a helper for accessing the tag value.
func (t Encrypt0Tag[T, E]) Untag() *Encrypt0[T, E] { return &t.Encrypt0 }

// MarshalCBOR implements cbor.Marshaler.
func (t Encrypt0Tag[T, E]) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(cbor.Tag[Encrypt0[T, E]]{
		Num: Encrypt0TagNum,
		Val: t.Encrypt0,
	})
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (t *Encrypt0Tag[T, E]) UnmarshalCBOR(data []byte) error {
	var tag cbor.Tag[Encrypt0[T, E]]
	if err := cbor.Unmarshal(data, &tag); err != nil {
		return err
	}
	if tag.Num != Encrypt0TagNum {
		return fmt.Errorf("mismatched tag number %d for Encrypt0, expected %d", tag.Num, Encrypt0TagNum)
	}
	*t = Encrypt0Tag[T, E]{tag.Val}
	return nil
}
