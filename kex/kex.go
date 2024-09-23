// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package kex implements the Key Exchange subprotocol of FDO.
package kex

import (
	"io"
)

// Session implements encryption/decryption for a single session. It is
// suggested that Session implementations also implement binary.Marshaler and
// binary.Unmarshaler so that owner service implementations can load balance on
// a per-message basis without any affinity.
//
// All Sessions from Suites in this package implement encoding.BinaryMarshaler
// and encoding.BinaryUnmarshaler.
type Session interface {
	// Parameter generates the exchange parameter to send to its peer. This
	// function will generate a new parameter every time it is called. This
	// method is used by both the client and server.
	Parameter(rand io.Reader) ([]byte, error)

	// SetParameter sets the received parameter from the client. This method is
	// only called by a server.
	SetParameter([]byte) error

	// Encrypt uses a session key to encrypt a payload. Depending on the suite,
	// the result may be a plain COSE_Encrypt0 or one wrapped by COSE_Mac0.
	Encrypt(rand io.Reader, payload any) (any, error)

	// Decrypt a tagged COSE Encrypt0 or Mac0 object.
	Decrypt(rand io.Reader, r io.Reader) ([]byte, error)
}

// DecryptOnly is a session that only performs decryption and key exchange
// functions.
type DecryptOnly struct {
	Session
}

// Encrypt uses a session key to encrypt a payload. Depending on the suite,
// the result may be a plain COSE_Encrypt0 or one wrapped by COSE_Mac0.
func (s DecryptOnly) Encrypt(_ io.Reader, payload any) (any, error) { return payload, nil }
