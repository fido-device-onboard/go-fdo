// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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

// Certificate is a newtype for x509.Certificate implementing proper CBOR
// encoding.
type Certificate x509.Certificate

// MarshalCBOR implements cbor.Marshaler interface.
func (c *Certificate) MarshalCBOR() ([]byte, error) {
	if c == nil {
		return cbor.Marshal(nil)
	}
	return cbor.Marshal(c.Raw)
}

// UnmarshalCBOR implements cbor.Unmarshaler interface.
func (c *Certificate) UnmarshalCBOR(data []byte) error {
	if c == nil {
		return errors.New("cannot unmarshal to a nil pointer")
	}
	var der []byte
	if err := cbor.Unmarshal(data, &der); err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("error parsing x509 certificate DER-encoded bytes: %w", err)
	}
	*c = Certificate(*cert)
	return nil
}

func verifyCertChain(chain []*x509.Certificate, roots *x509.CertPool) error {
	// All all intermediates (if any) to a pool
	intermediates := x509.NewCertPool()
	if len(chain) > 2 {
		for _, cert := range chain[1 : len(chain)-1] {
			intermediates.AddCert(cert)
		}
	}

	// Trust last certificate in chain if roots is nil
	if roots == nil {
		roots = x509.NewCertPool()
		roots.AddCert(chain[len(chain)-1])
	}

	// Return the result of (*x509.Certificate).Verify
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}); err != nil {
		return fmt.Errorf("%w: %w", ErrCryptoVerifyFailed, err)
	}

	return nil
}

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

// PublicKey encodes public key information in FDO messages and vouchers.
type PublicKey struct {
	Type     KeyType
	Encoding KeyEncoding
	Body     []byte

	key   crypto.PublicKey
	chain []*x509.Certificate
	err   error
}

func newPublicKey(typ KeyType, pub any) (*PublicKey, error) {
	switch pub := pub.(type) {
	case []*x509.Certificate:
		chain := make([]*Certificate, len(pub))
		for i, cert := range pub {
			chain[i] = (*Certificate)(cert)
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
		body, err := x509.MarshalPKIXPublicKey(pub)
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
		key, err := x509.ParsePKIXPublicKey(pub.Body)
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

	case X5ChainKeyEnc:
		var certs []*Certificate
		if err := cbor.Unmarshal(pub.Body, &certs); err != nil {
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
			eckey, ok := certs[len(certs)-1].PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return errors.New("public key must be an ECDSA public key")
			}
			pub.key = eckey
			return nil
		case RsaPssKeyType, RsaPkcsKeyType, Rsa2048RestrKeyType:
			rsakey, ok := certs[len(certs)-1].PublicKey.(*rsa.PublicKey)
			if !ok {
				return errors.New("public key must be an RSA public key")
			}
			pub.key = rsakey
			return nil
		default:
			return fmt.Errorf("unsupported key type: %s", pub.Type)
		}

	default:
		return fmt.Errorf("unsupported key encoding: %s", pub.Encoding)
	}
}
