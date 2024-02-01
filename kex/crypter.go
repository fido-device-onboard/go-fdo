// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package kex

import (
	"io"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// SessionCrypter implements Encrypt/Decrypt methods and can be used (via
// struct embedding) to implement the Session interface.
type SessionCrypter struct {
	ID     CipherSuiteID
	Cipher *CipherSuite

	SEK []byte
	SVK []byte
}

// Encrypt uses a session key to encrypt a payload. Depending on the suite,
// the result may be a plain COSE_Encrypt0 or one wrapped by COSE_Mac0.
func (s SessionCrypter) Encrypt(rand io.Reader, payload any) (cbor.TagData, error) {
	// FIXME: Implement
	panic("unimplemented")
}

// Decrypt a tagged COSE Encrypt0 or Mac0 object.
func (s SessionCrypter) Decrypt(rand io.Reader, data cbor.Tag[cbor.RawBytes]) ([]byte, error) {
	// FIXME: Implement
	panic("unimplemented")
}
