// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import (
	"github.com/fido-device-onboard/go-fdo/cbor"
)

// Encrypt holds the encrypted content of an enveloped structure. It contains a
// list of [Recipient]s to hold the encrypted keys for recipients.
//
// TODO: Implement Encrypt/Decrypt
type Encrypt[T any] struct {
	Header
	Ciphertext *cbor.Bstr[T] // byte string or null when transported separately
	Recipients []Recipient   // non-empty array of recipients
}

// Encrypt0 holds the encrypted content of an enveloped structure. It assumes
// contains no recipient information adn therefore assumes that the recipient
// of the object will already know the identity of the key to be used in order
// to decrypt the message
//
// TODO: Implement Encrypt/Decrypt
type Encrypt0[T any] struct {
	Header
	Ciphertext *cbor.Bstr[T] // byte string or null when transported separately
}

// Mac is a message authentication code structure that is used when the key to
// use is not implicitly known. These include a requirement for multiple
// recipients, the key being unknown, and a recipient algorithm of other than
// direct.
type Mac[T any] struct {
	Header
	Payload    *cbor.Bstr[T] // byte string or null when transported separately
	Tag        []byte        // non-empty byte string containing the MAC
	Recipients []Recipient   // non-empty array of recipients
}

// Mac0 is a message authentication code structure that is used when the
// recipient structure is not needed, because the key to be used is implicitly
// known.
type Mac0[T any] struct {
	Header
	Payload *cbor.Bstr[T] // byte string or null when transported separately
	Tag     []byte        // non-empty byte string containing the MAC
}

const (
	macContext  = "MAC"
	mac0Context = "MAC0"
)

// Underlying message authentication code struct
type mac struct {
	Context     string
	Protected   serializedOrEmptyHeaderMap
	ExternalAad []byte
	Payload     []byte
}

// Recipient contains the recipient information for use when the key to be used
// for encryption is not implicitly known.
type Recipient struct {
	Header
	Ciphertext *[]byte     // byte string or null
	Recipients []Recipient `cbor:",omitempty"` // array of one or more recipients
}
