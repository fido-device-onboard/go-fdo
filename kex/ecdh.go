// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package kex

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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
	RegisterNewSuite(
		string(ECDH256Suite),
		(&ecdhSession{Curve: elliptic.P256()}).new,
	)
	RegisterNewSuite(
		string(ECDH384Suite),
		(&ecdhSession{Curve: elliptic.P384()}).new,
	)
}

type ecdhSession struct {
	Curve  elliptic.Curve
	Cipher CipherSuite

	// Key exchange data
	xA   []byte
	xB   []byte
	priv *ecdsa.PrivateKey

	// Session encrypt/decrypt data
	sek []byte
	svk []byte
}

func (s *ecdhSession) new(xA []byte, cipher CipherSuite) Session {
	s.xA = xA
	s.Cipher = cipher
	return s
}

// Parameter generates the private key and exchange parameter to send to
// its peer. This function will generate a new key every time it is called.
// This method is used by both the client and server.
func (s *ecdhSession) Parameter(rand io.Reader) ([]byte, error) {
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

	// Compute shared secret
	param := ecdhParam{
		X:    ecKey.PublicKey.X,
		Y:    ecKey.PublicKey.Y,
		Rand: r,
	}
	shse, err := sharedSecret(ecKey, param)
	if err != nil {
		return nil, fmt.Errorf("error computing shared secret: %w", err)
	}

	// Derive a symmetric key
	keySize, macSize := s.Cipher.KeySize(), s.Cipher.MacSize()
	symKey, err := kdf(s.Cipher.HashFunc(), shse, []byte{}, (keySize+macSize)*8)
	if err != nil {
		return nil, fmt.Errorf("error deriving symmetric key: %w", err)
	}
	s.sek, s.svk = symKey[:keySize], symKey[keySize:]

	// Marshal and store param
	xX, err := param.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if s.xA == nil {
		s.xA = xX
		return xX, nil
	}
	s.xB = xX

	return xX, nil
}

// SetParameter sets the received parameter from the client. This method is
// only called by a server.
func (s *ecdhSession) SetParameter(xA []byte) error {
	s.xA = xA

	var param ecdhParam
	if err := new(ecdhParam).UnmarshalBinary(xA); err != nil {
		return fmt.Errorf("error parsing xA param: %w", err)
	}

	shse, err := sharedSecret(s.priv, param)
	if err != nil {
		return fmt.Errorf("error computing shared secret: %w", err)
	}

	keySize, macSize := s.Cipher.KeySize(), s.Cipher.MacSize()
	symKey, err := kdf(s.Cipher.HashFunc(), shse, []byte{}, (keySize+macSize)*8)
	if err != nil {
		return fmt.Errorf("error deriving symmetric key: %w", err)
	}
	s.sek, s.svk = symKey[:keySize], symKey[keySize:]

	return nil
}

// Compute the ECDH shared secret
func sharedSecret(key *ecdsa.PrivateKey, p ecdhParam) ([]byte, error) {
	// Create ECDH public key from parameter
	ecdhPub, err := (&ecdsa.PublicKey{
		Curve: key.Curve,
		X:     p.X,
		Y:     p.Y,
	}).ECDH()
	if err != nil {
		return nil, fmt.Errorf("error converting public key from param to ECDH: %w", err)
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

	// Combine ECDH shared secret with rand from parameter
	return append(shx, p.Rand...), nil
}

// Encrypt uses a session key to encrypt a payload. Depending on the suite,
// the result may be a plain COSE_Encrypt0 or one wrapped by COSE_Mac0.
func (s *ecdhSession) Encrypt(rand io.Reader, payload any) (cbor.TagData, error) {
	panic("unimplemented")
}

// Decrypt a tagged COSE Encrypt0 or Mac0 object.
func (s *ecdhSession) Decrypt(rand io.Reader, data cbor.Tag[cbor.RawBytes]) ([]byte, error) {
	panic("unimplemented")
}

func (s *ecdhSession) MarshalBinary() ([]byte, error) {
	panic("unimplemented")
}

func (s *ecdhSession) UnmarshalBinary(data []byte) error {
	panic("unimplemented")
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
