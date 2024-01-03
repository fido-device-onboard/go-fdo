// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// Hash is a crypto hash, with length in bytes preceding. Hashes are computed
// in accordance with FIPS-180-4. See COSE assigned numbers for hash types.
//
//	Hash = [
//	    hashtype: int, ;; negative values possible
//	    hash: bstr
//	]
type Hash struct {
	Algorithm HashAlg
	Value     []byte
}

// An HMAC - RFC2104 - is encoded as a hash.
//
//	HMac = Hash
type Hmac = Hash

// HashAlg is an FDO hashtype enum.
//
//	hashtype = (
//	    SHA256: -16,
//	    SHA384: -43,
//	    HMAC-SHA256: 5,
//	    HMAC-SHA384: 6
//	)
type HashAlg int64

// Hash algorithms
const (
	Sha256Hash     HashAlg = -16
	Sha384Hash     HashAlg = -43
	HmacSha256Hash HashAlg = 5
	HmacSha384Hash HashAlg = 6
)

// SigInfo is used to encode parameters for the device attestation signature.
//
// SigInfo flows in both directions, initially from the protocol client
// (eASigInfo), then to the protocol client (eBSigInfo). The types eASigInfo and
// eBSigInfo are intended to clarify these two cases in the protocol message
// descriptions.
//
//	SigInfo = [
//	    sgType: DeviceSgType,
//	    Info: bstr
//	]
//	eASigInfo = SigInfo  ;; from Device to Rendezvous/Owner
//	eBSigInfo = SigInfo  ;; from Owner/Rendezvous to Device
//
//	DeviceSgType //= (
//	    StSECP256R1: ES256,  ;; ECDSA secp256r1 = NIST-P-256 = prime256v1
//	    StSECP384R1: ES384,  ;; ECDSA secp384r1 = NIST-P-384
//	    StRSA2048:   RS256,  ;; RSA 2048 bit
//	    StRSA3072:   RS384,  ;; RSA 3072 bit
//	    StEPID10:    90,     ;; Intel® EPID 1.0 signature
//	    StEPID11:    91      ;; Intel® EPID 1.1 signature
//	)
//
//	COSECompatibleSignatureTypes = (
//	    ES256: -7,  ;; From COSE spec, table 5
//	    ES384: -35, ;; From COSE spec, table 5
//	    ES512: -36  ;; From COSE spec, table 5
//	    RS256: -257,;; From https://datatracker.ietf.org/doc/html/draft-ietf-cose-webauthn-algorithms-05
//	    RS384: -258 ;; From https://datatracker.ietf.org/doc/html/draft-ietf-cose-webauthn-algorithms-05
//	)
type SigInfo struct {
	Type int64
	Info []byte
}

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

// rawPubKey is an FDO PublicKey structure.
//
//	PublicKey = [
//	    pkType,
//	    pkEnc,
//	    pkBody
//	]
type rawPubKey struct {
	Type  KeyType
	Enc   KeyEncoding
	Bytes cbor.RawBytes
}

// PublicKey can be any supported underlying key type and handles marshaling.
// For unmarshaling from an FDO PublicKey structure, use [ParsePublicKey].
type PublicKey interface {
	// Marshal to an FDO PublicKey structure
	cbor.Marshaler
	// Unmarshal from an FDO PublicKey.pkBody element
	cbor.Unmarshaler

	// Return the FDO pkType
	Type() KeyType
	// Return the FDO pkEnc
	Encoding() KeyEncoding
	// Return a standard Go public key
	PublicKey() crypto.PublicKey
}

// ParsePublicKey unmarshals any supported key type from an FDO PublicKey
// structure.
func ParsePublicKey(data []byte) (PublicKey, error) {
	var raw rawPubKey
	if err := cbor.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	switch raw.Enc {
	case X509KeyEnc:
		switch raw.Type {
		case Secp256r1KeyType, Secp384r1KeyType:
			var pub ecdsaX509PubKey
			if err := pub.UnmarshalCBOR(raw.Bytes); err != nil {
				return nil, err
			}
			return &pub, nil
		default:
			return nil, fmt.Errorf("unsupported key type: %s", raw.Type)
		}

	case X5ChainKeyEnc:
		switch raw.Type {
		case Secp256r1KeyType, Secp384r1KeyType:
			var pub ecdsaX5Chain
			if err := pub.UnmarshalCBOR(raw.Bytes); err != nil {
				return nil, err
			}
			return &pub, nil
		default:
			return nil, fmt.Errorf("unsupported key type: %s", raw.Type)
		}

	default:
		return nil, fmt.Errorf("unsupported key encoding: %s", raw.Enc)
	}
}

type ecdsaX509PubKey ecdsa.PublicKey

var _ PublicKey = (*ecdsaX509PubKey)(nil)

func (pub ecdsaX509PubKey) Type() KeyType {
	switch pub.Curve {
	case elliptic.P256():
		return Secp256r1KeyType
	case elliptic.P384():
		return Secp384r1KeyType
	default:
		panic("unsupported curve: " + pub.Params().Name)
	}
}

func (pub ecdsaX509PubKey) Encoding() KeyEncoding { return X509KeyEnc }

func (pub ecdsaX509PubKey) PublicKey() crypto.PublicKey { return &pub }

func (pub ecdsaX509PubKey) MarshalCBOR() ([]byte, error) {
	key, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	raw, err := cbor.Marshal(key)
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(rawPubKey{
		Type:  pub.Type(),
		Enc:   pub.Encoding(),
		Bytes: raw,
	})
}

func (pub *ecdsaX509PubKey) UnmarshalCBOR(data []byte) error {
	var b []byte
	if err := cbor.Unmarshal(data, &b); err != nil {
		return err
	}
	key, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return err
	}
	eckey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("public key must be an ECDSA public key")
	}
	*pub = ecdsaX509PubKey(*eckey)
	return nil
}

type ecdsaX5Chain []*x509.Certificate

var _ PublicKey = (*ecdsaX5Chain)(nil)

func (pub ecdsaX5Chain) Type() KeyType {
	eckey, ok := pub.PublicKey().(*ecdsa.PublicKey)
	if !ok {
		panic("public key of leaf certificate (last cert in chain) must be an ECDSA public key")
	}
	switch eckey.Curve {
	case elliptic.P256():
		return Secp256r1KeyType
	case elliptic.P384():
		return Secp384r1KeyType
	default:
		panic("unsupported curve: " + eckey.Params().Name)
	}

}

func (pub ecdsaX5Chain) Encoding() KeyEncoding { return X5ChainKeyEnc }

func (pub ecdsaX5Chain) PublicKey() crypto.PublicKey {
	if len(pub) == 0 {
		return nil
	}
	return pub[len(pub)-1].PublicKey
}

func (pub ecdsaX5Chain) MarshalCBOR() ([]byte, error) {
	rawCerts := make([][]byte, len(pub))
	for i, cert := range pub {
		rawCerts[i] = cert.Raw
	}
	return cbor.Marshal(struct {
		Type  KeyType
		Enc   KeyEncoding
		Certs [][]byte
	}{
		Type:  pub.Type(),
		Enc:   pub.Encoding(),
		Certs: rawCerts,
	})
}

func (pub *ecdsaX5Chain) UnmarshalCBOR(data []byte) error {
	var rawCerts [][]byte
	if err := cbor.Unmarshal(data, &rawCerts); err != nil {
		return err
	}
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("error parsing certificate [i=%d] of X5CHAIN: %w", i, err)
		}
		certs[i] = cert
	}
	*pub = ecdsaX5Chain(certs)
	return nil
}
