// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package kex

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

// SessionCrypter implements Encrypt/Decrypt methods and can be used (via
// struct embedding) to implement the Session interface.
type SessionCrypter struct {
	ID     CipherSuiteID
	Cipher CipherSuite

	SEK []byte
	SVK []byte
}

func (s SessionCrypter) String() string {
	return fmt.Sprintf(`SessionCrypter[
  ID   %d
  %s
  SEK  %x
  SVK  %x
]`,
		s.ID,
		strings.ReplaceAll(s.Cipher.String(), "\n", "\n  "),
		s.SEK,
		s.SVK,
	)
}

// Encrypt uses a session key to encrypt a payload. Depending on the suite,
// the result may be a plain COSE_Encrypt0 or one wrapped by COSE_Mac0.
func (s SessionCrypter) Encrypt(rand io.Reader, payload any) (any, error) {
	var enc0 cose.Encrypt0[any, []byte]
	if err := enc0.Encrypt(s.Cipher.EncryptAlg, s.SEK, payload, nil); err != nil {
		return nil, err
	}
	if s.Cipher.MacAlg == 0 {
		return enc0.Tag(), nil
	}

	mac0 := cose.Mac0[cose.Encrypt0[any, []byte], []byte]{
		Payload: cbor.NewByteWrap(enc0),
	}
	if err := mac0.Digest(s.Cipher.MacAlg, s.SVK, nil, nil); err != nil {
		return nil, err
	}
	return mac0.Tag(), nil
}

// Decrypt a tagged COSE Encrypt0 or Mac0 object.
func (s SessionCrypter) Decrypt(rand io.Reader, r io.Reader) ([]byte, error) {
	// Unmarshal a raw CBOR tag
	var tag cbor.Tag[cbor.RawBytes]
	if err := cbor.NewDecoder(r).Decode(&tag); err != nil {
		return nil, err
	}

	// Unmarshal either a COSE_Encrypt0 or COSE_Mac0, verifying if the latter
	var enc0 cose.Encrypt0[cbor.RawBytes, []byte]
	switch tag.Num {
	case cose.Encrypt0TagNum:
		if err := cbor.Unmarshal([]byte(tag.Val), &enc0); err != nil {
			return nil, fmt.Errorf("error decoding COSE_Encrypt0: %w", err)
		}

	case cose.Mac0TagNum:
		var mac0 cose.Mac0[cose.Encrypt0[cbor.RawBytes, []byte], []byte]
		if err := cbor.Unmarshal([]byte(tag.Val), &mac0); err != nil {
			return nil, fmt.Errorf("error decoding COSE_Mac0: %w", err)
		}
		expectedDigest := mac0.Value
		if err := mac0.Digest(s.Cipher.MacAlg, s.SVK, nil, nil); err != nil {
			return nil, fmt.Errorf("error computing COSE_Mac0 tag for comparison: %w", err)
		}
		if !bytes.Equal(mac0.Value, expectedDigest) {
			return nil, fmt.Errorf("value of COSE_Mac0 tag did not match expected")
		}
		enc0 = mac0.Payload.Val

	default:
		return nil, fmt.Errorf("decrypted value must be a COSE_Encrypt0 or COSE_Mac0")
	}

	// Decrypt contents
	raw, err := enc0.Decrypt(s.Cipher.EncryptAlg, s.SEK, nil)
	if err != nil {
		return nil, err
	}
	return []byte(*raw), nil
}

// Destroy zeroes secrets that last until the end of the session. This means SEK/SVK, but not
// exchanged parameters, which can be destroyed automatically when SEK/SVK are derived.
func (s *SessionCrypter) Destroy() {
	clear(s.SEK)
	clear(s.SVK)
}
