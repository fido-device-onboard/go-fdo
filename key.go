// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// KeyType is an FDO pkType enum.
//
//	pkType = (
//	    RSA2048RESTR: 1, ;; RSA 2048 with restricted key/exponent (PKCS1 1.5 encoding)
//	    RSAPKCS:      5, ;; RSA key, PKCS1, v1.5
//	    RSAPSS:       6, ;; RSA key, PSS
//	    SECP256R1:    10, ;; ECDSA secp256r1 = NIST-P-256 = prime256v1
//	    SECP384R1:    11, ;; ECDSA secp384r1 = NIST-P-384
//	)
//	;; These are identical
//	SECP256R1 = (
//	    NIST-P-256,
//	    PRIME256V1
//	)
//	;; These are identical
//	SECP384R1 = (
//	    NIST-P-384
//	)
type KeyType uint8

func (typ KeyType) String() string {
	switch typ {
	case Rsa2048RestrKeyType:
		return "RSA 2048 with restricted key/exponent (PKCS1 1.5 encoding)"
	case RsaPkcsKeyType:
		return "RSA key, PKCS1, v1.5"
	case RsaPssKeyType:
		return "RSA key, PSS"
	case Secp256r1KeyType:
		return "ECDSA secp256r1 = NIST-P-256 = prime256v1"
	case Secp384r1KeyType:
		return "ECDSA secp384r1 = NIST-P-384"
	default:
		return "unknown"
	}
}

// Public key types
const (
	// RSA 2048 with restricted key/exponent (PKCS1 1.5 encoding)
	Rsa2048RestrKeyType KeyType = 1
	// RSA key, PKCS1, v1.5
	RsaPkcsKeyType KeyType = 5
	// RSA key, PSS
	RsaPssKeyType KeyType = 6
	// ECDSA secp256r1 = NIST-P-256 = prime256v1
	Secp256r1KeyType KeyType = 10
	// ECDSA secp384r1 = NIST-P-384
	Secp384r1KeyType KeyType = 11
)

// PublicKeyOrChain is a constraint for supported FDO PublicKey types.
type PublicKeyOrChain interface {
	*ecdsa.PublicKey | *rsa.PublicKey | []*x509.Certificate
}

// KeyEncoding is an FDO pkEnc enum.
//
//	pkEnc = (
//	    Crypto:       0      ;; applies to crypto with its own encoding (e.g., Intel® EPID)
//	    X509:         1,     ;; X509 DER encoding, applies to RSA and ECDSA
//	    X5CHAIN:      2,     ;; COSE x5chain, an ordered chain of X.509 certificates
//	    COSEKEY:      3      ;; COSE key encoding
//	)
type KeyEncoding uint8

func (enc KeyEncoding) String() string {
	switch enc {
	case CryptoKeyEnc:
		return "Intel EPID/non-standard"
	case X509KeyEnc:
		return "x.509 DER encoding"
	case X5ChainKeyEnc:
		return "COSE x5chain"
	case CoseKeyEnc:
		return "COSE key"
	default:
		return "unknown"
	}
}

// Public key encodings
const (
	// Applies to crypto with its own encoding (e.g., Intel® EPID)
	CryptoKeyEnc KeyEncoding = 0
	// X509 DER encoding, applies to RSA and ECDSA
	X509KeyEnc KeyEncoding = 1
	// COSE x5chain, an ordered chain of X.509 certificates
	X5ChainKeyEnc KeyEncoding = 2
	// COSE key encoding
	CoseKeyEnc KeyEncoding = 3
)

// PublicKey encodes public key information in FDO messages and vouchers.
type PublicKey struct {
	Type     KeyType
	Encoding KeyEncoding
	Body     cbor.RawBytes

	key   crypto.PublicKey
	chain []*x509.Certificate
	err   error
}

func newPublicKey(typ KeyType, pub any) (*PublicKey, error) {
	switch pub := pub.(type) {
	case []*x509.Certificate:
		chain := make([]*cbor.X509Certificate, len(pub))
		for i, cert := range pub {
			chain[i] = (*cbor.X509Certificate)(cert)
		}
		body, err := cbor.Marshal(chain)
		if err != nil {
			return nil, fmt.Errorf("X5Chain encoding: %w", err)
		}
		return &PublicKey{
			Type:     typ,
			Encoding: X5ChainKeyEnc,
			Body:     body,
		}, nil

	case *ecdsa.PublicKey, *rsa.PublicKey:
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, fmt.Errorf("X509 encoding: %w", err)
		}
		body, err := cbor.Marshal(der)
		if err != nil {
			return nil, fmt.Errorf("X509 encoding: %w", err)
		}
		return &PublicKey{
			Type:     typ,
			Encoding: X509KeyEnc,
			Body:     body,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported public key: must be *ecdsa.PublicKey, *rsa.PublicKey, or []*x509.Certificate")
	}
}

// Public returns the public key parsed from the X509 or X5CHAIN encoding.
func (pub *PublicKey) Public() (crypto.PublicKey, error) {
	if pub.key == nil && pub.err == nil {
		pub.err = pub.parse()
	}
	return pub.key, pub.err
}

// Chain returns the certificate chain of the public key. If the key encoding
// is not X5CHAIN then the certificate slice will be nil.
func (pub *PublicKey) Chain() ([]*x509.Certificate, error) {
	if pub.key == nil && pub.err == nil {
		pub.err = pub.parse()
	}
	return pub.chain, pub.err
}

func (pub *PublicKey) parse() error {
	switch pub.Encoding {
	case X509KeyEnc:
		return pub.parseX509()

	case X5ChainKeyEnc:
		return pub.parseX5Chain()

	default:
		return fmt.Errorf("unsupported key encoding: %s", pub.Encoding)
	}
}

func (pub *PublicKey) parseX509() error {
	var der []byte
	if err := cbor.Unmarshal([]byte(pub.Body), &der); err != nil {
		return err
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return err
	}

	switch pub.Type {
	case Secp256r1KeyType, Secp384r1KeyType:
		eckey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("public key must be an ECDSA public key")
		}
		pub.key = eckey
		return nil
	case RsaPssKeyType, RsaPkcsKeyType, Rsa2048RestrKeyType:
		rsakey, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("public key must be an RSA public key")
		}
		pub.key = rsakey
		return nil
	default:
		return fmt.Errorf("unsupported key type: %s", pub.Type)
	}
}

func (pub *PublicKey) parseX5Chain() error {
	var certs []*cbor.X509Certificate
	if err := cbor.Unmarshal([]byte(pub.Body), &certs); err != nil {
		return err
	}
	if len(certs) == 0 {
		return errors.New("X5CHAIN key cannot be an empty certificate chain")
	}
	pub.chain = make([]*x509.Certificate, len(certs))
	for i, cert := range certs {
		cert := cert
		pub.chain[i] = (*x509.Certificate)(cert)
	}

	switch pub.Type {
	case Secp256r1KeyType, Secp384r1KeyType:
		eckey, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("public key must be an ECDSA public key")
		}
		pub.key = eckey
		return nil
	case RsaPssKeyType, RsaPkcsKeyType, Rsa2048RestrKeyType:
		rsakey, ok := certs[0].PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("public key must be an RSA public key")
		}
		pub.key = rsakey
		return nil
	default:
		return fmt.Errorf("unsupported key type: %s", pub.Type)
	}
}
