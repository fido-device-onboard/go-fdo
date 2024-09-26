// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package kex

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rsa"
	"encoding"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/big"
	"reflect"
	"strings"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/internal/nistkdf"
)

func init() {
	RegisterKeyExchangeSuite(
		string(ECDH256Suite),
		func(xA []byte, cipher CipherSuiteID) Session {
			return &ECDHSession{
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
	randSize int

	// Key exchange data
	xA   []byte
	xB   []byte
	priv *ecdh.PrivateKey

	// Session encrypt/decrypt data
	SessionCrypter
}

func (s ECDHSession) String() string {
	var keyBytes []byte
	if s.priv != nil {
		keyBytes = s.priv.Bytes()
	}
	return fmt.Sprintf(`ECDH[
  randSize  %d
  xA        %x
  xB        %x
  key       %x
  %s
]`,
		s.randSize,
		s.xA,
		s.xB,
		keyBytes,
		strings.ReplaceAll(s.SessionCrypter.String(), "\n", "\n  "),
	)
}

// Equal compares two key exchange sessions. If an Equal method is not
// implemented, the sessions can be compared with reflect.DeepEqual.
func (s *ECDHSession) Equal(other Session) bool {
	s1, ok := other.(*ECDHSession)
	if !ok || s1 == nil {
		return false
	}
	sCopy, s1Copy := *s, *s1

	// ECDH private keys have a random component, so they will not be deeply
	// equal after constructing from the marshaled form
	switch {
	case sCopy.priv != nil && s1Copy.priv != nil:
		// Both have private keys, so compare
		if !bytes.Equal(sCopy.priv.Bytes(), s1Copy.priv.Bytes()) {
			return false
		}
	case sCopy.priv == nil && s1Copy.priv == nil:
		// Both do not have a private key
	default:
		// One has a private key and the other does not
		return false
	}
	sCopy.priv = nil
	s1Copy.priv = nil

	return reflect.DeepEqual(sCopy, s1Copy)
}

// Parameter generates the exchange parameter to send to its peer. This
// function will generate a new parameter every time it is called. This
// method is used by both the client and server.
func (s *ECDHSession) Parameter(rand io.Reader, _ *rsa.PublicKey) ([]byte, error) {
	// Generate a new key
	var curve ecdh.Curve
	switch s.randSize {
	case 16:
		curve = ecdh.P256()
	case 48:
		curve = ecdh.P384()
	}
	ecKey, err := curve.GenerateKey(rand)
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
		Pub:  ecKey.PublicKey().Bytes(),
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
func (s *ECDHSession) SetParameter(xB []byte, _ *rsa.PrivateKey) error {
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
	Pub  []byte // Encoded following SEC 1, Version 2.0, Section 2.3.3
	Rand []byte
}

func (p ecdhParam) MarshalBinary() ([]byte, error) {
	pointLen := (len(p.Pub) - 1) / 2
	if pointLen < 0 || pointLen > math.MaxUint16 {
		panic("invalid public key - too large")
	}
	pointLen16 := uint16(pointLen) // needed to satisfy gosec

	randLen := len(p.Rand)
	if randLen > math.MaxUint16 {
		return nil, fmt.Errorf("rand contains too many bytes")
	}

	var b []byte
	b = binary.BigEndian.AppendUint16(b, pointLen16)
	b = append(b, p.Pub[1:1+pointLen]...)
	b = binary.BigEndian.AppendUint16(b, pointLen16)
	b = append(b, p.Pub[1+pointLen:1+2*pointLen]...)
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

	pointLen := max(len(xb), len(yb))
	p.Pub = make([]byte, 1+2*pointLen)
	p.Pub[0] = 4 // Uncompressed form marker
	new(big.Int).SetBytes(xb).FillBytes(p.Pub[1 : 1+pointLen])
	new(big.Int).SetBytes(yb).FillBytes(p.Pub[1+pointLen : 1+2*pointLen])
	p.Rand = rb

	return nil
}

func ecSymmetricKey(ecKey *ecdh.PrivateKey, xA, xB []byte, cipher CipherSuite) (sek, svk []byte, err error) {
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
	symKey := nistkdf.KDF(cipher.PRFHash, shSe, []byte{}, (sekSize+svkSize)*8)

	return symKey[:sekSize], symKey[sekSize:], nil
}

// Compute the ECDH shared secret
func ecSharedSecret(key *ecdh.PrivateKey, paramA, paramB ecdhParam) ([]byte, error) {
	// Determine which param is "other"
	var other ecdhParam
	switch {
	case bytes.Equal(paramA.Pub, key.PublicKey().Bytes()):
		other = paramB
	case bytes.Equal(paramB.Pub, key.PublicKey().Bytes()):
		other = paramA
	default:
		return nil, fmt.Errorf("neither parameter for the shared secret matched the session private key")
	}

	// Create ECDH public key from parameter
	ecdhPub, err := key.Curve().NewPublicKey(other.Pub)
	if err != nil {
		return nil, fmt.Errorf("error converting public key from param to ECDH (mismatched curves?): %w", err)
	}

	// Perform ECDH to get shared secret
	shx, err := key.ECDH(ecdhPub)
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
		keyBytes = s.priv.Bytes()
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

	var curve ecdh.Curve
	switch s.randSize {
	case 16:
		curve = ecdh.P256()
	case 48:
		curve = ecdh.P384()
	}
	key, err := curve.NewPrivateKey(persist.Key)
	if err != nil && len(persist.Key) > 0 {
		return fmt.Errorf("error parsing EC key: %w", err)
	}

	*s = ECDHSession{
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
