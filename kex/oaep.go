// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package kex

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding"
	"fmt"
	"io"
	"strings"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/internal/nistkdf"
)

func init() {
	RegisterKeyExchangeSuite(
		string(ASYMKEX2048Suite),
		func(xA []byte, cipher CipherSuiteID) Session {
			return &OAEPSession{
				paramSize: 32,

				xA: xA,
				xB: []byte{},

				SessionCrypter: SessionCrypter{
					ID:     cipher,
					Cipher: cipher.Suite(),
					SEK:    []byte{},
					SVK:    []byte{},
				},
			}
		},
	)
	RegisterKeyExchangeSuite(
		string(ASYMKEX3072Suite),
		func(xA []byte, cipher CipherSuiteID) Session {
			return &OAEPSession{
				paramSize: 96,

				xA: xA,
				xB: []byte{},

				SessionCrypter: SessionCrypter{
					ID:     cipher,
					Cipher: cipher.Suite(),
					SEK:    []byte{},
					SVK:    []byte{},
				},
			}
		},
	)
}

// OAEPSession implements a Session using RSA keys directly with OAEP
// encryption. Sessions are created using [Suite.New].
type OAEPSession struct {
	// Static configuration
	paramSize int

	// Key exchange data
	xA []byte
	xB []byte

	// Session encrypt/decrypt data
	SessionCrypter
}

func (s OAEPSession) String() string {
	return fmt.Sprintf(`OAEP[
  size  %d
  xA    %x
  xB    %x
  %s
]`, s.paramSize, s.xA, s.xB,
		strings.ReplaceAll(s.SessionCrypter.String(), "\n", "\n  "),
	)
}

// Parameter generates the exchange parameter to send to its peer. This
// function will generate a new parameter every time it is called. This
// method is used by both the client and server.
func (s *OAEPSession) Parameter(rand io.Reader, ownerKey *rsa.PublicKey) ([]byte, error) {
	// Create a random parameter
	x := make([]byte, s.paramSize)
	if _, err := rand.Read(x); err != nil {
		return nil, err
	}

	// Store the parameter unencrypted
	if s.xA == nil {
		s.xA = x

		// Owner random is only signed, not encrypted
		return x, nil
	}
	s.xB = x

	// Compute session key
	sek, svk, err := oaepSymmetricKey(s.xB, s.xA, s.Cipher)
	if err != nil {
		return nil, fmt.Errorf("error computing symmetric keys: %w", err)
	}
	s.SEK, s.SVK = sek, svk

	// Encrypt the parameter (device random only) before sending
	if ownerKey == nil {
		return nil, fmt.Errorf("owner key must be an in-memory RSA private key (i.e. not a TPM)")
	}
	return rsa.EncryptOAEP(sha256.New(), rand, ownerKey, x, nil)
}

// SetParameter sets the received parameter from the client. This method is
// only called by a server.
func (s *OAEPSession) SetParameter(xB []byte, ownerKey *rsa.PrivateKey) (err error) {
	if ownerKey == nil {
		return fmt.Errorf("owner key must be an in-memory RSA private key (i.e. not a TPM)")
	}

	// Decrypt xB
	s.xB, err = rsa.DecryptOAEP(sha256.New(), nil, ownerKey, xB, nil)
	if err != nil {
		return fmt.Errorf("error decrypting device parameter: %w", err)
	}

	// Compute session key
	sek, svk, err := oaepSymmetricKey(s.xB, s.xA, s.Cipher)
	if err != nil {
		return fmt.Errorf("error computing symmetric keys: %w", err)
	}
	s.SEK, s.SVK = sek, svk

	return nil
}

func oaepSymmetricKey(deviceRandom, ownerRandom []byte, cipher CipherSuite) (sek, svk []byte, err error) {
	shSe := deviceRandom
	contextRand := ownerRandom

	// Derive a symmetric key
	sekSize, svkSize := cipher.EncryptAlg.KeySize(), uint16(0)
	if cipher.MacAlg != 0 {
		svkSize = cipher.MacAlg.KeySize()
	}
	symKey := nistkdf.KDF(cipher.PRFHash, shSe, contextRand, (sekSize+svkSize)*8)

	return symKey[:sekSize], symKey[sekSize:], nil
}

type oaepPersist struct {
	ParamSize int
	ParamXA   []byte
	ParamXB   []byte

	Cipher CipherSuiteID
	SEK    []byte
	SVK    []byte
}

// MarshalCBOR implements [cbor.Marshaler].
func (s *OAEPSession) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(oaepPersist{
		ParamSize: s.paramSize,
		ParamXA:   s.xA,
		ParamXB:   s.xB,

		Cipher: s.ID,
		SEK:    s.SEK,
		SVK:    s.SVK,
	})
}

// UnmarshalCBOR implements [cbor.Unmarshaler].
func (s *OAEPSession) UnmarshalCBOR(data []byte) error {
	var persist oaepPersist
	if err := cbor.Unmarshal(data, &persist); err != nil {
		return err
	}

	*s = OAEPSession{
		paramSize: persist.ParamSize,
		xA:        persist.ParamXA,
		xB:        persist.ParamXB,

		SessionCrypter: SessionCrypter{
			ID:     persist.Cipher,
			Cipher: persist.Cipher.Suite(),
			SEK:    persist.SEK,
			SVK:    persist.SVK,
		},
	}

	return nil
}

var _ encoding.BinaryMarshaler = (*OAEPSession)(nil)
var _ encoding.BinaryUnmarshaler = (*OAEPSession)(nil)

// MarshalBinary implements encoding.BinaryMarshaler
func (s *OAEPSession) MarshalBinary() ([]byte, error) { return s.MarshalCBOR() }

// UnmarshalBinary implements encoding.BinaryUnmarshaler
func (s *OAEPSession) UnmarshalBinary(data []byte) error { return s.UnmarshalCBOR(data) }
