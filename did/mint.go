// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package did

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
)

// KeyConfig specifies the type of key to generate.
type KeyConfig struct {
	// Type is "EC" or "RSA".
	Type string
	// Curve is the EC curve name (e.g., "P-256", "P-384"). Ignored for RSA.
	Curve string
	// Bits is the RSA key size in bits (e.g., 2048, 3072). Ignored for EC.
	Bits int
}

// DefaultKeyConfig returns a sensible default: ECDSA P-384.
func DefaultKeyConfig() KeyConfig {
	return KeyConfig{Type: "EC", Curve: "P-384"}
}

// MintResult contains the output of a key minting operation.
type MintResult struct {
	// PrivateKey is the generated private key.
	PrivateKey crypto.Signer
	// PublicKey is the corresponding public key.
	PublicKey crypto.PublicKey
	// DIDDocument is the generated DID Document.
	DIDDocument *Document
	// DIDURI is the did:web URI for this key.
	DIDURI string
}

// Mint generates a new owner key pair, creates a DID Document, and returns
// everything needed to serve and share the DID.
//
// Parameters:
//   - host: the hostname (and optional port) for the did:web URI (e.g., "example.com:8080")
//   - path: optional path segments for the did:web URI (e.g., "" for root, "owner1" for sub-path)
//   - voucherRecipientURL: optional URL where vouchers can be pushed to this owner
//   - keyCfg: key generation configuration
func Mint(host string, path string, voucherRecipientURL string, keyCfg KeyConfig) (*MintResult, error) {
	// Generate key pair
	privKey, err := generateKey(keyCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Build did:web URI
	didURI := WebDID(host, path)

	// Create DID Document
	doc, err := NewDocument(didURI, privKey.Public(), voucherRecipientURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create DID document: %w", err)
	}

	return &MintResult{
		PrivateKey:  privKey,
		PublicKey:   privKey.Public(),
		DIDDocument: doc,
		DIDURI:      didURI,
	}, nil
}

// WebDID constructs a did:web URI from a host and optional path.
//
// Examples:
//
//	WebDID("example.com", "")       → "did:web:example.com"
//	WebDID("example.com:8080", "")  → "did:web:example.com%3A8080"
//	WebDID("example.com", "owner1") → "did:web:example.com:owner1"
func WebDID(host string, path string) string {
	// Percent-encode the host: colons must become %3A per did:web spec.
	// url.PathEscape does NOT encode colons, so we do it manually.
	encoded := strings.ReplaceAll(url.PathEscape(host), ":", "%3A")
	did := "did:web:" + encoded
	if path != "" {
		// Path segments are separated by ':'
		segments := strings.Split(strings.Trim(path, "/"), "/")
		for _, seg := range segments {
			if seg != "" {
				did += ":" + seg
			}
		}
	}
	return did
}

// WebDIDToURL converts a did:web URI to the HTTPS URL where the DID Document
// should be served.
//
// Examples:
//
//	"did:web:example.com"           → "https://example.com/.well-known/did.json"
//	"did:web:example.com%3A8080"    → "https://example.com:8080/.well-known/did.json"
//	"did:web:example.com:owner1"    → "https://example.com/owner1/did.json"
func WebDIDToURL(didURI string) (string, error) {
	if !strings.HasPrefix(didURI, "did:web:") {
		return "", fmt.Errorf("not a did:web URI: %s", didURI)
	}

	specific := strings.TrimPrefix(didURI, "did:web:")
	parts := strings.Split(specific, ":")

	// First part is the host (percent-decoded)
	host, err := url.PathUnescape(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid did:web host: %w", err)
	}

	if len(parts) == 1 {
		return "https://" + host + "/.well-known/did.json", nil
	}

	// Additional parts form the path
	path := strings.Join(parts[1:], "/")
	return "https://" + host + "/" + path + "/did.json", nil
}

// ExportPrivateKeyPEM encodes a private key as PEM.
func ExportPrivateKeyPEM(key crypto.Signer) ([]byte, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
	case *rsa.PrivateKey:
		der := x509.MarshalPKCS1PrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

// ExportPublicKeyPEM encodes a public key as PEM.
func ExportPublicKeyPEM(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// LoadPrivateKeyPEM loads a private key from PEM-encoded bytes.
func LoadPrivateKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("parsed key does not implement crypto.Signer")
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

func generateKey(cfg KeyConfig) (crypto.Signer, error) {
	switch strings.ToUpper(cfg.Type) {
	case "EC", "ECDSA", "":
		curve := curveFromName(cfg.Curve)
		if curve == nil {
			return nil, fmt.Errorf("unsupported EC curve: %s", cfg.Curve)
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	case "RSA":
		bits := cfg.Bits
		if bits == 0 {
			bits = 3072
		}
		return rsa.GenerateKey(rand.Reader, bits)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", cfg.Type)
	}
}

func curveFromName(name string) elliptic.Curve {
	switch strings.ToUpper(name) {
	case "P-256", "P256", "SECP256R1", "PRIME256V1", "":
		if name == "" {
			return elliptic.P384() // default
		}
		return elliptic.P256()
	case "P-384", "P384", "SECP384R1":
		return elliptic.P384()
	default:
		return nil
	}
}
