// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package did

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// Document is a W3C DID Document (https://www.w3.org/TR/did-core/).
type Document struct {
	Context            []string             `json:"@context"`
	ID                 string               `json:"id"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Authentication     []string             `json:"authentication,omitempty"`
	AssertionMethod    []string             `json:"assertionMethod,omitempty"`
	Service            []Service            `json:"service,omitempty"`
}

// VerificationMethod is a public key entry in a DID Document.
type VerificationMethod struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Controller   string `json:"controller"`
	PublicKeyJwk *JWK   `json:"publicKeyJwk,omitempty"`
}

// JWK is a JSON Web Key (RFC 7517) for embedding in DID Documents.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
}

// Service is a service endpoint entry in a DID Document.
type Service struct {
	ID                      string `json:"id"`
	Type                    string `json:"type"`
	ServiceEndpoint         string `json:"serviceEndpoint"`
	TLSCertificateAuthority string `json:"tlsCertificateAuthority,omitempty"`
}

// FDOContextURL is the JSON-LD context URL for FDO-specific DID document terms.
// This context defines FDOVoucherRecipient, FDOVoucherHolder, tlsCertificateAuthority,
// and fido-device-onboarding. See https://fidoalliance.org/ns/fdo/v1.
const FDOContextURL = "https://fidoalliance.org/ns/fdo/v1"

// FDOVoucherRecipientServiceType is the service type for FDO voucher recipient endpoints (push).
const FDOVoucherRecipientServiceType = "FDOVoucherRecipient"

// FDOVoucherHolderServiceType is the service type for FDO voucher holder endpoints (pull).
const FDOVoucherHolderServiceType = "FDOVoucherHolder"

// NewDocument creates a DID Document for the given public key and DID URI.
// If voucherRecipientURL is non-empty, an FDOVoucherRecipient service entry is added.
// If voucherHolderURL is non-empty, an FDOVoucherHolder service entry is added.
func NewDocument(didURI string, pub crypto.PublicKey, voucherRecipientURL string, voucherHolderURL string) (*Document, error) {
	jwk, err := PublicKeyToJWK(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key to JWK: %w", err)
	}

	keyID := didURI + "#key-1"
	jwk.Kid = keyID

	doc := &Document{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
			FDOContextURL,
		},
		ID: didURI,
		VerificationMethod: []VerificationMethod{
			{
				ID:           keyID,
				Type:         "JsonWebKey2020",
				Controller:   didURI,
				PublicKeyJwk: jwk,
			},
		},
		Authentication:  []string{keyID},
		AssertionMethod: []string{keyID},
	}

	if voucherRecipientURL != "" {
		doc.Service = append(doc.Service, Service{
			ID:              didURI + "#voucher-recipient",
			Type:            FDOVoucherRecipientServiceType,
			ServiceEndpoint: voucherRecipientURL,
		})
	}

	if voucherHolderURL != "" {
		doc.Service = append(doc.Service, Service{
			ID:              didURI + "#voucher-holder",
			Type:            FDOVoucherHolderServiceType,
			ServiceEndpoint: voucherHolderURL,
		})
	}

	return doc, nil
}

// JSON returns the DID Document as pretty-printed JSON.
func (d *Document) JSON() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

// PublicKeyToJWK converts a crypto.PublicKey to a JWK.
func PublicKeyToJWK(pub crypto.PublicKey) (*JWK, error) {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		return ecPublicKeyToJWK(key)
	case *rsa.PublicKey:
		return rsaPublicKeyToJWK(key)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", pub)
	}
}

func ecPublicKeyToJWK(key *ecdsa.PublicKey) (*JWK, error) {
	var crv string
	var size int
	switch key.Curve {
	case elliptic.P256():
		crv = "P-256"
		size = 32
	case elliptic.P384():
		crv = "P-384"
		size = 48
	default:
		return nil, fmt.Errorf("unsupported EC curve: %v", key.Curve.Params().Name)
	}

	xBytes := key.X.Bytes()
	yBytes := key.Y.Bytes()

	// Pad to fixed size
	xPadded := make([]byte, size)
	yPadded := make([]byte, size)
	copy(xPadded[size-len(xBytes):], xBytes)
	copy(yPadded[size-len(yBytes):], yBytes)

	return &JWK{
		Kty: "EC",
		Crv: crv,
		X:   base64.RawURLEncoding.EncodeToString(xPadded),
		Y:   base64.RawURLEncoding.EncodeToString(yPadded),
		Use: "sig",
	}, nil
}

func rsaPublicKeyToJWK(key *rsa.PublicKey) (*JWK, error) {
	return &JWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		Use: "sig",
	}, nil
}

// FingerprintFDO computes the spec-correct FDO OwnerKeyFingerprint: SHA-256 of the
// CBOR-encoded protocol.PublicKey (spec §9.8). This is used for PullAuth token
// scoping, partner trust store lookups, and voucher pipeline routing.
func FingerprintFDO(pub crypto.PublicKey) ([]byte, error) {
	keyType, err := protocol.KeyTypeFromPublicKey(pub)
	if err != nil {
		return nil, err
	}

	var protoKey *protocol.PublicKey
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		protoKey, err = protocol.NewPublicKey(keyType, key, false)
	case *rsa.PublicKey:
		protoKey, err = protocol.NewPublicKey(keyType, key, false)
	default:
		return nil, fmt.Errorf("unsupported key type for FDO fingerprint: %T", pub)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create protocol key: %w", err)
	}

	data, err := cbor.Marshal(protoKey)
	if err != nil {
		return nil, fmt.Errorf("failed to CBOR-encode protocol key: %w", err)
	}
	h := sha256.Sum256(data)
	return h[:], nil
}

// FingerprintProtocolKey computes the FDO OwnerKeyFingerprint directly from a
// protocol.PublicKey. Use this when you already have a protocol key (e.g., from
// PullAuth). For crypto.PublicKey, use FingerprintFDO instead.
func FingerprintProtocolKey(pub protocol.PublicKey) ([]byte, error) {
	data, err := cbor.Marshal(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to CBOR-encode protocol key: %w", err)
	}
	h := sha256.Sum256(data)
	return h[:], nil
}

// FingerprintFDOHex returns the hex-encoded FDO OwnerKeyFingerprint.
func FingerprintFDOHex(pub crypto.PublicKey) string {
	fp, err := FingerprintFDO(pub)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(fp)
}

// FingerprintJWK computes a SHA-256 fingerprint of the public key's JWK thumbprint (RFC 7638).
// Note: For FDO spec-correct fingerprinting, use FingerprintFDO instead.
func FingerprintJWK(pub crypto.PublicKey) ([]byte, error) {
	jwk, err := PublicKeyToJWK(pub)
	if err != nil {
		return nil, err
	}

	// JWK Thumbprint: canonical JSON of required members, sorted alphabetically
	var thumbprint string
	switch jwk.Kty {
	case "EC":
		thumbprint = fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`, jwk.Crv, jwk.X, jwk.Y)
	case "RSA":
		thumbprint = fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, jwk.E, jwk.N)
	default:
		return nil, fmt.Errorf("unsupported key type for thumbprint: %s", jwk.Kty)
	}

	hash := sha256.Sum256([]byte(thumbprint))
	return hash[:], nil
}
