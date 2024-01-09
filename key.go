// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"crypto"
	"crypto/ecdsa"
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

type PublicKey struct {
	Type     KeyType
	Encoding KeyEncoding
	Public   crypto.PublicKey

	x5chain []*Certificate
}

func (pub PublicKey) MarshalCBOR() ([]byte, error) {
	switch pub.Encoding {
	case X509KeyEnc:
		subjectPubKeyInfo, err := x509.MarshalPKIXPublicKey(pub.Public)
		if err != nil {
			return nil, err
		}
		return cbor.Marshal(struct {
			Type KeyType
			Enc  KeyEncoding
			Body []byte
		}{
			Type: pub.Type,
			Enc:  pub.Encoding,
			Body: subjectPubKeyInfo,
		})

	case X5ChainKeyEnc:
		return cbor.Marshal(struct {
			Type  KeyType
			Enc   KeyEncoding
			Certs []*Certificate
		}{
			Type:  pub.Type,
			Enc:   pub.Encoding,
			Certs: pub.x5chain,
		})

	default:
		return nil, fmt.Errorf("unsupported key encoding: %s", pub.Encoding)
	}
}

func (pub *PublicKey) UnmarshalCBOR(data []byte) error {
	var raw struct {
		Type KeyType
		Enc  KeyEncoding
		Body []byte
	}
	if err := cbor.Unmarshal(data, &raw); err != nil {
		return err
	}

	switch raw.Enc {
	case X509KeyEnc:
		switch raw.Type {
		case Secp256r1KeyType, Secp384r1KeyType:
			key, err := x509.ParsePKIXPublicKey(raw.Body)
			if err != nil {
				return err
			}
			eckey, ok := key.(*ecdsa.PublicKey)
			if !ok {
				return errors.New("public key must be an ECDSA public key")
			}
			*pub = PublicKey{
				Type:     raw.Type,
				Encoding: raw.Enc,
				Public:   eckey,
			}
			return nil

		default:
			return fmt.Errorf("unsupported key type: %s", raw.Type)
		}

	case X5ChainKeyEnc:
		switch raw.Type {
		case Secp256r1KeyType, Secp384r1KeyType:
			var certs []*Certificate
			if err := cbor.Unmarshal(raw.Body, &certs); err != nil {
				return err
			}
			if len(certs) == 0 {
				return errors.New("X5CHAIN key cannot be an empty certificate chain")
			}
			eckey, ok := certs[len(certs)-1].PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return errors.New("public key must be an ECDSA public key")
			}
			*pub = PublicKey{
				Type:     raw.Type,
				Encoding: raw.Enc,
				Public:   eckey,
				x5chain:  certs,
			}
			return nil

		default:
			return fmt.Errorf("unsupported key type: %s", raw.Type)
		}

	default:
		return fmt.Errorf("unsupported key encoding: %s", raw.Enc)
	}
}
