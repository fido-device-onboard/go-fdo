// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package blob

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// Pkcs8Key CBOR-encodes a private key to a byte string of PKCS8 DER content.
type Pkcs8Key struct {
	crypto.Signer
}

// IsValid checks whether the key is valid for FDO Device Credential use.
func (p Pkcs8Key) IsValid() bool {
	switch key := p.Signer.(type) {
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

// MarshalCBOR implements cbor.Marshaler interface.
func (p Pkcs8Key) MarshalCBOR() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(p.Signer)
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
	p.Signer = key.(crypto.Signer)
	return nil
}

// UnwrapSigner implements fdo.SignerUnwrapper interface.
// This allows extractRSAPrivateKey to access the underlying key without reflection.
func (p Pkcs8Key) UnwrapSigner() crypto.Signer {
	return p.Signer
}
