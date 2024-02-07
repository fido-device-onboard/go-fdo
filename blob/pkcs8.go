// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package blob

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"io"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

// Pkcs8Key CBOR-encodes a private key to a byte string of PKCS8 DER content.
type Pkcs8Key struct {
	PrivateKey crypto.Signer
}

// IsValid checks whether the key is valid for FDO Device Credential use.
func (p Pkcs8Key) IsValid() bool {
	switch key := p.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		switch key.Curve {
		case elliptic.P256(), elliptic.P384():
			return true
		}
	case *rsa.PrivateKey:
		switch key.Size() {
		case 2048 / 8, 3072 / 8:
			return true
		}
	}
	return false
}

// Public returns the corresponding public key.
func (p Pkcs8Key) Public() crypto.PublicKey { return p.PrivateKey.Public() }

// Sign signs digest with the private key.
func (p Pkcs8Key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// When an *ecdsa.PrivateKey is used, override its Sign implementation
	// to use RFC8152 signature encoding rather than ASN1.
	if eckey, ok := p.PrivateKey.(*ecdsa.PrivateKey); ok {
		return cose.RFC8152Signer{PrivateKey: eckey}.Sign(rand, digest, opts)
	}
	return p.PrivateKey.Sign(rand, digest, opts)
}

// MarshalCBOR implements cbor.Marshaler interface.
func (p Pkcs8Key) MarshalCBOR() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(p.PrivateKey)
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(der)
}

// UnmarshalCBOR implements cbor.Unmarshaler interface.
func (p *Pkcs8Key) UnmarshalCBOR(data []byte) error {
	var der []byte
	if err := cbor.Unmarshal(data, &der); err != nil {
		return err
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return err
	}
	p.PrivateKey = key.(crypto.Signer)
	return nil
}
