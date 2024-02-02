// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package kex

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

const (
	ec256RandomLength = 16
	ec384RandomLength = 48
)

func init() {
	RegisterKeyExchangeSuite(
		string(ECDH256Suite),
		(&ECDHSession{Curve: elliptic.P256()}).new,
	)
	RegisterKeyExchangeSuite(
		string(ECDH384Suite),
		(&ECDHSession{Curve: elliptic.P384()}).new,
	)
}

// ECDHSession implements a Session using elliptic curve cryptography. Sessions
// are created using [Suite.New].
type ECDHSession struct {
	// Key exchange data
	Curve elliptic.Curve
	xA    []byte
	xB    []byte
	priv  *ecdsa.PrivateKey

	// Session encrypt/decrypt data
	SessionCrypter
}

func (s *ECDHSession) new(xA []byte, cipher CipherSuiteID) Session {
	s.xA = xA
	s.ID = cipher
	s.Cipher = cipher.New()
	return s
}

// Parameter generates the private key and exchange parameter to send to
// its peer. This function will generate a new key every time it is called.
// This method is used by both the client and server.
func (s *ECDHSession) Parameter(rand io.Reader) ([]byte, error) {
	// Generate a new key
	ecKey, err := ecdsa.GenerateKey(s.Curve, rand)
	if err != nil {
		return nil, err
	}
	s.priv = ecKey

	// Generate random bytes for a length that is curve-dependent
	var r []byte
	switch s.Curve {
	case elliptic.P256():
		r = make([]byte, ec256RandomLength)
	case elliptic.P384():
		r = make([]byte, ec384RandomLength)
	}
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

	// Compute session keys
	sek, svk, err := computeSymmetricKeys(ecKey, s.xA, s.xB, s.Cipher)
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

	// Compute session keys
	sek, svk, err := computeSymmetricKeys(s.priv, s.xA, s.xB, s.Cipher)
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

	var b []byte
	b = binary.BigEndian.AppendUint16(b, uint16(len(xb)))
	b = append(b, xb...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(yb)))
	b = append(b, yb...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(p.Rand)))
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

func computeSymmetricKeys(ecKey *ecdsa.PrivateKey, xA, xB []byte, cipher *CipherSuite) (sek, svk []byte, err error) {
	// Decode parameters
	var paramA, paramB ecdhParam
	if err := paramA.UnmarshalBinary(xA); err != nil {
		return nil, nil, fmt.Errorf("error parsing xA param: %w", err)
	}
	if err := paramB.UnmarshalBinary(xB); err != nil {
		return nil, nil, fmt.Errorf("error parsing xB param: %w", err)
	}

	// Compute shared secret
	shse, err := sharedSecret(ecKey, paramA, paramB)
	if err != nil {
		return nil, nil, fmt.Errorf("error computing shared secret: %w", err)
	}

	// Derive a symmetric key
	sekSize, svkSize := cipher.EncryptAlg.KeySize(), uint16(0)
	if cipher.MacAlg != 0 {
		svkSize = cipher.MacAlg.KeySize()
	}
	symKey, err := kdf(cipher.PRFHash, shse, []byte{}, (sekSize+svkSize)*8)
	if err != nil {
		return nil, nil, fmt.Errorf("error deriving symmetric key: %w", err)
	}

	return symKey[:sekSize], symKey[sekSize:], nil
}

// Compute the ECDH shared secret
func sharedSecret(key *ecdsa.PrivateKey, paramA, paramB ecdhParam) ([]byte, error) {
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
	return append(append(shx, paramA.Rand...), paramB.Rand...), nil
}

type ecdhPersist struct {
	Is384  bool
	ParamA []byte
	ParamB []byte
	Key    []byte

	Cipher CipherSuiteID
	SEK    []byte
	SVK    []byte
}

// MarshalBinary implements [encoding.BinaryMarshaler].
func (s *ECDHSession) MarshalBinary() ([]byte, error) {
	key, err := x509.MarshalECPrivateKey(s.priv)
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(ecdhPersist{
		Is384:  s.Curve == elliptic.P384(),
		ParamA: s.xA,
		ParamB: s.xB,
		Key:    key,
		Cipher: s.ID,
		SEK:    s.SEK,
		SVK:    s.SVK,
	})
}

// UnmarshalBinary implements [encoding.BinaryUnmarshaler].
func (s *ECDHSession) UnmarshalBinary(data []byte) error {
	var persist ecdhPersist
	if err := cbor.Unmarshal(data, &persist); err != nil {
		return err
	}

	curve := elliptic.P256()
	if persist.Is384 {
		curve = elliptic.P384()
	}

	key, err := x509.ParseECPrivateKey(persist.Key)
	if err != nil && len(persist.Key) > 0 {
		return fmt.Errorf("error parsing EC key: %w", err)
	}

	*s = ECDHSession{
		Curve: curve,
		xA:    persist.ParamA,
		xB:    persist.ParamB,
		priv:  key,

		SessionCrypter: SessionCrypter{
			ID:     persist.Cipher,
			Cipher: persist.Cipher.New(),
			SEK:    persist.SEK,
			SVK:    persist.SVK,
		},
	}
	return nil
}
