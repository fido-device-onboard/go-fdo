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
	// Key exchange data
	Curve elliptic.Curve
	xA    []byte
	xB    []byte
	priv  *ecdsa.PrivateKey

	// Session encrypt/decrypt data
	Cipher CipherSuite
	sek    []byte
	svk    []byte
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
	s.sek, s.svk = sek, svk

	return xX, nil
}

// SetParameter sets the received parameter from the client. This method is
// only called by a server.
func (s *ecdhSession) SetParameter(xB []byte) error {
	s.xB = xB

	// Compute session keys
	sek, svk, err := computeSymmetricKeys(s.priv, s.xA, s.xB, s.Cipher)
	if err != nil {
		return fmt.Errorf("error computing symmetric keys: %w", err)
	}
	s.sek, s.svk = sek, svk

	return nil
}

func computeSymmetricKeys(ecKey *ecdsa.PrivateKey, xA, xB []byte, cipher CipherSuite) (sek, svk []byte, err error) {
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
	keySize, macSize := cipher.KeySize(), cipher.MacSize()
	symKey, err := kdf(cipher.HashFunc(), shse, []byte{}, (keySize+macSize)*8)
	if err != nil {
		return nil, nil, fmt.Errorf("error deriving symmetric key: %w", err)
	}

	return symKey[:keySize], symKey[keySize:], nil
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

	// Combine ECDH shared secret with rand from parameters
	return append(append(shx, paramA.Rand...), paramB.Rand...), nil
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

// Only persist encrypt/decrypt-related data. Key exchange requires server
// affinity.
type ecdhPersist struct {
	Cipher CipherSuite
	SEK    []byte
	SVK    []byte
}

func (s *ecdhSession) MarshalBinary() ([]byte, error) {
	return cbor.Marshal(ecdhPersist{
		Cipher: s.Cipher,
		SEK:    s.sek,
		SVK:    s.svk,
	})
}

func (s *ecdhSession) UnmarshalBinary(data []byte) error {
	var persist ecdhPersist
	if err := cbor.Unmarshal(data, &persist); err != nil {
		return err
	}

	*s = ecdhSession{
		Cipher: persist.Cipher,
		sek:    persist.SEK,
		svk:    persist.SVK,
	}
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
