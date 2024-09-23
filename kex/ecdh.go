// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package kex

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/big"
	"strings"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

func init() {
	RegisterKeyExchangeSuite(
		string(ECDH256Suite),
		func(xA []byte, cipher CipherSuiteID) Session {
			return &ECDHSession{
				curve:    elliptic.P256(),
				randSize: 16,

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
		string(ECDH384Suite),
		func(xA []byte, cipher CipherSuiteID) Session {
			return &ECDHSession{
				curve:    elliptic.P384(),
				randSize: 48,

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

// ECDHSession implements a Session using elliptic curve cryptography. Sessions
// are created using [Suite.New].
type ECDHSession struct {
	// Static configuration
	curve    elliptic.Curve
	randSize int

	// Key exchange data
	xA   []byte
	xB   []byte
	priv *ecdsa.PrivateKey

	// Session encrypt/decrypt data
	SessionCrypter
}

func (s ECDHSession) String() string {
	return fmt.Sprintf(`ECDH[
  curve     %s
  randSize  %d
  xA        %x
  xB        %x
  %s
]`,
		s.curve.Params().Name,
		s.randSize,
		s.xA,
		s.xB,
		strings.ReplaceAll(s.SessionCrypter.String(), "\n", "\n  "),
	)
}

// Parameter generates the exchange parameter to send to its peer. This
// function will generate a new parameter every time it is called. This
// method is used by both the client and server.
func (s *ECDHSession) Parameter(rand io.Reader) ([]byte, error) {
	// Generate a new key
	ecKey, err := ecdsa.GenerateKey(s.curve, rand)
	if err != nil {
		return nil, err
	}
	s.priv = ecKey

	// Generate random bytes for a length that is curve-dependent
	r := make([]byte, s.randSize)
	if _, err := rand.Read(r); err != nil {
		return nil, err
	}

	// Marshal and store param
	xX, err := ecdhParam{
		X:    ecKey.PublicKey.X,
		Y:    ecKey.PublicKey.Y,
		Rand: r,
	}.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if s.xA == nil {
		s.xA = xX
		return xX, nil
	}
	s.xB = xX

	// Compute session key
	sek, svk, err := ecSymmetricKey(ecKey, s.xA, s.xB, s.Cipher)
	if err != nil {
		return nil, fmt.Errorf("error computing symmetric keys: %w", err)
	}
	s.SEK, s.SVK = sek, svk

	return xX, nil
}

// SetParameter sets the received parameter from the client. This method is
// only called by a server.
func (s *ECDHSession) SetParameter(xB []byte) error {
	s.xB = xB

	// Compute session key
	sek, svk, err := ecSymmetricKey(s.priv, s.xA, s.xB, s.Cipher)
	if err != nil {
		return fmt.Errorf("error computing symmetric keys: %w", err)
	}
	s.SEK, s.SVK = sek, svk

	return nil
}

type ecdhParam struct {
	X, Y *big.Int
	Rand []byte
}

func (p ecdhParam) MarshalBinary() ([]byte, error) {
	xb, yb := p.X.Bytes(), p.Y.Bytes()
	xbLen := len(xb)
	if xbLen > math.MaxUint16 {
		return nil, fmt.Errorf("x contains too many bytes")
	}
	ybLen := len(yb)
	if ybLen > math.MaxUint16 {
		return nil, fmt.Errorf("y contains too many bytes")
	}
	randLen := len(p.Rand)
	if randLen > math.MaxUint16 {
		return nil, fmt.Errorf("rand contains too many bytes")
	}

	var b []byte
	b = binary.BigEndian.AppendUint16(b, uint16(xbLen))
	b = append(b, xb...)
	b = binary.BigEndian.AppendUint16(b, uint16(ybLen))
	b = append(b, yb...)
	b = binary.BigEndian.AppendUint16(b, uint16(randLen))
	b = append(b, p.Rand...)
	return b, nil
}

func (p *ecdhParam) UnmarshalBinary(b []byte) error {
	var xb, yb, rb []byte
	for _, bb := range []*[]byte{&xb, &yb, &rb} {
		if len(b) < 2 {
			return io.ErrUnexpectedEOF
		}
		bLen := binary.BigEndian.Uint16(b)
		b = b[2:]
		if len(b) < int(bLen) {
			return io.ErrUnexpectedEOF
		}
		*bb = b[:bLen]
		b = b[bLen:]
	}

	p.X = new(big.Int).SetBytes(xb)
	p.Y = new(big.Int).SetBytes(yb)
	p.Rand = rb

	return nil
}

func ecSymmetricKey(ecKey *ecdsa.PrivateKey, xA, xB []byte, cipher CipherSuite) (sek, svk []byte, err error) {
	// Decode parameters
	var paramA, paramB ecdhParam
	if err := paramA.UnmarshalBinary(xA); err != nil {
		return nil, nil, fmt.Errorf("error parsing xA param: %w", err)
	}
	if err := paramB.UnmarshalBinary(xB); err != nil {
		return nil, nil, fmt.Errorf("error parsing xB param: %w", err)
	}

	// Compute shared secret
	shSe, err := ecSharedSecret(ecKey, paramA, paramB)
	if err != nil {
		return nil, nil, fmt.Errorf("error computing shared secret: %w", err)
	}

	// Derive a symmetric key
	sekSize, svkSize := cipher.EncryptAlg.KeySize(), uint16(0)
	if cipher.MacAlg != 0 {
		svkSize = cipher.MacAlg.KeySize()
	}
	symKey, err := kdf(cipher.PRFHash, shSe, []byte{}, (sekSize+svkSize)*8)
	if err != nil {
		return nil, nil, fmt.Errorf("kdf: %w", err)
	}

	return symKey[:sekSize], symKey[sekSize:], nil
}

// Compute the ECDH shared secret
func ecSharedSecret(key *ecdsa.PrivateKey, paramA, paramB ecdhParam) ([]byte, error) {
	// Determine which param is "other"
	var other ecdhParam
	switch {
	case paramA.X.Cmp(key.PublicKey.X) == 0 &&
		paramA.Y.Cmp(key.PublicKey.Y) == 0:
		other = paramB
	case paramB.X.Cmp(key.PublicKey.X) == 0 &&
		paramB.Y.Cmp(key.PublicKey.Y) == 0:
		other = paramA
	default:
		return nil, fmt.Errorf("neither parameter for the shared secret matched the session private key")
	}

	// Create ECDH public key from parameter
	ecdhPub, err := (&ecdsa.PublicKey{
		Curve: key.Curve,
		X:     other.X,
		Y:     other.Y,
	}).ECDH()
	if err != nil {
		return nil, fmt.Errorf("error converting public key from param to ECDH (mismatched curves?): %w", err)
	}

	// Perform ECDH to get shared secret
	ecdhKey, err := key.ECDH()
	if err != nil {
		return nil, err
	}
	shx, err := ecdhKey.ECDH(ecdhPub)
	if err != nil {
		return nil, err
	}

	// Combine ECDH shared secret with rand from parameters
	return append(append(shx, paramB.Rand...), paramA.Rand...), nil
}

type ecdhPersist struct {
	RandSize int
	ParamA   []byte
	ParamB   []byte
	Key      []byte

	Cipher CipherSuiteID
	SEK    []byte
	SVK    []byte
}

// MarshalCBOR implements [cbor.Marshaler].
func (s *ECDHSession) MarshalCBOR() ([]byte, error) {
	var keyBytes []byte
	if s.priv != nil {
		key, err := x509.MarshalECPrivateKey(s.priv)
		if err != nil {
			return nil, err
		}
		keyBytes = key
	}
	return cbor.Marshal(ecdhPersist{
		RandSize: s.randSize,
		ParamA:   s.xA,
		ParamB:   s.xB,
		Key:      keyBytes,
		Cipher:   s.ID,
		SEK:      s.SEK,
		SVK:      s.SVK,
	})
}

// UnmarshalCBOR implements [cbor.Unmarshaler].
func (s *ECDHSession) UnmarshalCBOR(data []byte) error {
	var persist ecdhPersist
	if err := cbor.Unmarshal(data, &persist); err != nil {
		return err
	}

	curve := elliptic.P256()
	if persist.RandSize == 48 {
		curve = elliptic.P384()
	}

	key, err := x509.ParseECPrivateKey(persist.Key)
	if err != nil && len(persist.Key) > 0 {
		return fmt.Errorf("error parsing EC key: %w", err)
	}

	*s = ECDHSession{
		curve:    curve,
		randSize: persist.RandSize,
		xA:       persist.ParamA,
		xB:       persist.ParamB,
		priv:     key,

		SessionCrypter: SessionCrypter{
			ID:     persist.Cipher,
			Cipher: persist.Cipher.Suite(),
			SEK:    persist.SEK,
			SVK:    persist.SVK,
		},
	}
	return nil
}

var _ encoding.BinaryMarshaler = (*ECDHSession)(nil)
var _ encoding.BinaryUnmarshaler = (*ECDHSession)(nil)

// MarshalBinary implements encoding.BinaryMarshaler
func (s *ECDHSession) MarshalBinary() ([]byte, error) { return s.MarshalCBOR() }

// UnmarshalBinary implements encoding.BinaryUnmarshaler
func (s *ECDHSession) UnmarshalBinary(data []byte) error { return s.UnmarshalCBOR(data) }
