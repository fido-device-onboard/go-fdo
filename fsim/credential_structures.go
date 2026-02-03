// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"fmt"
)

// PasswordCredential represents a username/password credential
// Uses negative CBOR keys as per fdo.credentials.md specification
type PasswordCredential struct {
	Username  string `cbor:"-1,keyasint"`           // Username for authentication
	Password  string `cbor:"-2,keyasint"`           // Password (hashed or plaintext)
	HashAlgo  string `cbor:"-3,keyasint,omitempty"` // bcrypt, pbkdf2, scrypt, argon2
	Scope     string `cbor:"-4,keyasint,omitempty"` // Usage scope (e.g., "sudoers", "api.example.com")
	ExpiresAt string `cbor:"-5,keyasint,omitempty"` // ISO 8601 expiration timestamp
}

// SecretCredential represents a unified secret credential
// Consolidates API keys, OAuth secrets, bearer tokens, etc.
type SecretCredential struct {
	ClientID string `cbor:"-1,keyasint,omitempty"` // Client identifier (optional)
	Secret   string `cbor:"-2,keyasint"`           // Opaque secret string
	Type     string `cbor:"-3,keyasint,omitempty"` // api_key, oauth2_client_secret, bootstrap_token, bearer_token, basic_auth
	Endpoint string `cbor:"-4,keyasint,omitempty"` // Service endpoint URL (optional)
}

// X509CertRequest represents an X.509 certificate signing request
type X509CertRequest struct {
	CSR string `cbor:"-1,keyasint"` // PEM-encoded PKCS#10 Certificate Signing Request
}

// X509CertResponse represents an X.509 certificate response
type X509CertResponse struct {
	Certificate string   `cbor:"-1,keyasint"`           // PEM or DER encoded X.509 certificate
	CABundle    []string `cbor:"-2,keyasint,omitempty"` // Array of CA certificates (optional)
	CertFormat  string   `cbor:"-3,keyasint,omitempty"` // pem, der
}

// ServerKeyRequest represents a server-generated key request
type ServerKeyRequest struct {
	SubjectDN    string `cbor:"-1,keyasint"`           // Certificate Subject Distinguished Name
	KeyAlgorithm string `cbor:"-2,keyasint,omitempty"` // rsa, ecdsa, ed25519, ed448
	KeySize      uint   `cbor:"-3,keyasint,omitempty"` // Key size in bits (e.g., 2048, 4096)
}

// ServerKeyResponse represents a server-generated key response
type ServerKeyResponse struct {
	PrivateKey  string   `cbor:"-1,keyasint"`           // PKCS#8 encoded private key
	Certificate string   `cbor:"-2,keyasint"`           // PEM or DER encoded X.509 certificate
	CABundle    []string `cbor:"-3,keyasint,omitempty"` // Array of CA certificates (optional)
	KeyFormat   string   `cbor:"-4,keyasint,omitempty"` // pkcs1, pkcs8
}

// SSHPublicKey represents an SSH public key for registration
// Uses negative CBOR keys as per fdo.credentials.md specification
type SSHPublicKey struct {
	PublicKey string `cbor:"-1,keyasint"`           // OpenSSH or RFC 4716 format public key
	Username  string `cbor:"-2,keyasint,omitempty"` // Username account for SSH access
	KeyType   string `cbor:"-3,keyasint,omitempty"` // rsa, ed25519, ecdsa, dsa
	Comment   string `cbor:"-4,keyasint,omitempty"` // Key comment/description
}

// Validate validates the credential structure based on its type
func (pc *PasswordCredential) Validate() error {
	if pc.Username == "" {
		return fmt.Errorf("username is required")
	}
	if pc.Password == "" {
		return fmt.Errorf("password is required")
	}
	return nil
}

// Validate checks if the SecretCredential is valid
func (sc *SecretCredential) Validate() error {
	if sc.Secret == "" {
		return fmt.Errorf("secret is required")
	}
	return nil
}

// Validate checks if the X509CertRequest is valid
func (xcr *X509CertRequest) Validate() error {
	if xcr.CSR == "" {
		return fmt.Errorf("CSR is required")
	}
	return nil
}

// Validate checks if the ServerKeyRequest is valid
func (skr *ServerKeyRequest) Validate() error {
	if skr.SubjectDN == "" {
		return fmt.Errorf("subject_dn is required")
	}
	return nil
}

// Validate checks if the SSHPublicKey is valid
func (spk *SSHPublicKey) Validate() error {
	if spk.PublicKey == "" {
		return fmt.Errorf("public_key is required")
	}
	return nil
}
