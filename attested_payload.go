// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"time"
)

// DecryptPayload decrypts an encrypted attested payload using the device's RSA private key.
// The wrappedKey is the symmetric key encrypted with RSA-OAEP using the device's public key.
// The iv is the initialization vector for AES-CTR mode.
// The ciphertext is the encrypted payload.
func DecryptPayload(deviceKey *rsa.PrivateKey, wrappedKey, iv, ciphertext []byte) ([]byte, error) {
	if deviceKey == nil {
		return nil, fmt.Errorf("device private key is required for decryption")
	}
	if len(wrappedKey) == 0 {
		return nil, fmt.Errorf("wrapped encryption key is required")
	}
	if len(iv) == 0 {
		return nil, fmt.Errorf("IV is required")
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext is required")
	}

	// Unwrap the symmetric key using RSA-OAEP
	symmetricKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, deviceKey, wrappedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap encryption key: %w", err)
	}

	// Validate key size for AES-256
	if len(symmetricKey) != 32 {
		return nil, fmt.Errorf("invalid symmetric key size: expected 32 bytes for AES-256, got %d", len(symmetricKey))
	}

	// Validate IV size for AES
	if len(iv) != 16 {
		return nil, fmt.Errorf("invalid IV size: expected 16 bytes, got %d", len(iv))
	}

	// Decrypt using AES-256-CTR
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	decrypted := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(decrypted, ciphertext)

	return decrypted, nil
}

// EncryptPayload encrypts a payload for a device using its RSA public key.
// Returns the wrapped symmetric key, IV, and ciphertext.
// This is useful for testing and for creating encrypted attested payloads.
func EncryptPayload(devicePubKey *rsa.PublicKey, payload []byte) (wrappedKey, iv, ciphertext []byte, err error) {
	if devicePubKey == nil {
		return nil, nil, nil, fmt.Errorf("device public key is required for encryption")
	}

	// Generate random symmetric key (AES-256)
	symmetricKey := make([]byte, 32)
	if _, err := rand.Read(symmetricKey); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate symmetric key: %w", err)
	}

	// Generate random IV
	iv = make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Encrypt the payload using AES-256-CTR
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	ciphertext = make([]byte, len(payload))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, payload)

	// Wrap the symmetric key using RSA-OAEP
	wrappedKey, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, devicePubKey, symmetricKey, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to wrap encryption key: %w", err)
	}

	return wrappedKey, iv, ciphertext, nil
}

// PayloadValidity represents optional validity constraints for an attested payload
type PayloadValidity struct {
	// Expires is the ISO 8601 datetime after which the payload is no longer valid
	Expires string `json:"expires,omitempty"`
	// ID is an identifier for grouping related payloads
	ID string `json:"id,omitempty"`
	// Gen is the generation number for supersession (higher supersedes lower)
	Gen int `json:"gen,omitempty"`
}

// IsEmpty returns true if no validity fields are set
func (v *PayloadValidity) IsEmpty() bool {
	return v == nil || (v.Expires == "" && v.ID == "" && v.Gen == 0)
}

// ToJSON returns the JSON representation of the validity, or empty string if empty
func (v *PayloadValidity) ToJSON() string {
	if v.IsEmpty() {
		return ""
	}
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(data)
}

// ParseValidity parses a JSON string into a PayloadValidity
func ParseValidity(jsonStr string) (*PayloadValidity, error) {
	if jsonStr == "" {
		return nil, nil
	}
	var v PayloadValidity
	if err := json.Unmarshal([]byte(jsonStr), &v); err != nil {
		return nil, fmt.Errorf("invalid validity JSON: %w", err)
	}
	return &v, nil
}

// CheckExpiration returns an error if the payload has expired
func (v *PayloadValidity) CheckExpiration() error {
	if v == nil || v.Expires == "" {
		return nil
	}
	expTime, err := time.Parse(time.RFC3339, v.Expires)
	if err != nil {
		return fmt.Errorf("invalid expiration format: %w", err)
	}
	if time.Now().After(expTime) {
		return fmt.Errorf("payload expired at %s", v.Expires)
	}
	return nil
}

// BuildSignedData constructs the length-prefixed signed data for signature
// computation and verification. The format is:
// len(PayloadType) || PayloadType || len(Validity) || Validity || PayloadData
//
// Length prefixes are 4-byte big-endian unsigned integers. This format prevents
// type confusion attacks where an attacker might shift bytes between fields.
func BuildSignedData(payloadType string, validity *PayloadValidity, payloadData []byte) []byte {
	var result []byte

	// PayloadType length prefix (4 bytes big-endian)
	typeBytes := []byte(payloadType)
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(typeBytes)))
	result = append(result, lenBuf...)
	result = append(result, typeBytes...)

	// Validity length prefix (4 bytes big-endian)
	var validityBytes []byte
	if validity != nil && !validity.IsEmpty() {
		validityBytes = []byte(validity.ToJSON())
	}
	binary.BigEndian.PutUint32(lenBuf, uint32(len(validityBytes)))
	result = append(result, lenBuf...)
	result = append(result, validityBytes...)

	// PayloadData (no length prefix - remainder of data)
	result = append(result, payloadData...)

	return result
}

// AttestedPayload represents the components of an attested payload
type AttestedPayload struct {
	// Payload is the plaintext payload (or ciphertext if encrypted)
	Payload []byte
	// Signature is the signature over the payload (or ciphertext if encrypted)
	Signature []byte
	// DelegateChain is the optional delegate certificate chain
	DelegateChain []*x509.Certificate
	// IV is the initialization vector for encrypted payloads
	IV []byte
	// Ciphertext is the encrypted payload data
	Ciphertext []byte
	// WrappedKey is the RSA-OAEP wrapped symmetric key for encrypted payloads
	WrappedKey []byte
	// PayloadType is the optional MIME type indicating payload content type
	PayloadType string
	// Validity is the optional validity constraints (expiration, id, generation)
	Validity *PayloadValidity
}

// IsEncrypted returns true if the payload is encrypted
func (ap *AttestedPayload) IsEncrypted() bool {
	return len(ap.IV) > 0 && len(ap.Ciphertext) > 0 && len(ap.WrappedKey) > 0
}

// ecdsaSignature is used for ASN.1 unmarshaling of ECDSA signatures
type ecdsaSignature struct {
	R, S *big.Int
}

// VerifyAttestedPayload verifies an attested payload and returns the decrypted payload.
// It performs the following steps:
// 1. If delegateChain is provided, verifies it against ownerKey with provision permission
// 2. Verifies the signature against the owner key (or delegate leaf key)
// 3. If encrypted, decrypts the payload using the device's private key
// 4. Returns the final plaintext payload
//
// Parameters:
//   - ap: The attested payload to verify
//   - ownerKey: The owner's public key from the voucher
//   - deviceKey: The device's private key for decryption (only needed for encrypted payloads)
//
// Returns the decrypted/verified payload or an error
func VerifyAttestedPayload(ap *AttestedPayload, ownerKey crypto.PublicKey, deviceKey crypto.Signer) ([]byte, error) {
	if ap == nil {
		return nil, fmt.Errorf("attested payload is nil")
	}
	if ownerKey == nil {
		return nil, fmt.Errorf("owner key is required")
	}

	// Determine what data was signed (ciphertext if encrypted, payload otherwise)
	var payloadData []byte
	if ap.IsEncrypted() {
		payloadData = ap.Ciphertext
	} else {
		payloadData = ap.Payload
	}

	if len(payloadData) == 0 {
		return nil, fmt.Errorf("no payload data to verify")
	}
	if len(ap.Signature) == 0 {
		return nil, fmt.Errorf("signature is required")
	}

	// Build signed data with length prefixes: len(PayloadType) || PayloadType || len(Validity) || Validity || PayloadData
	signedData := BuildSignedData(ap.PayloadType, ap.Validity, payloadData)

	// Determine the signing key (delegate leaf or owner)
	signingKey := ownerKey
	if len(ap.DelegateChain) > 0 {
		// Verify delegate chain has provision permission
		err := VerifyDelegateChain(ap.DelegateChain, &ownerKey, &OIDDelegateProvision)
		if err != nil {
			return nil, fmt.Errorf("delegate chain verification failed: %w", err)
		}
		// Use delegate leaf's public key for signature verification
		signingKey = ap.DelegateChain[0].PublicKey
	}

	// Verify signature
	hashed := sha512.Sum384(signedData)
	if err := verifySignature(signingKey, hashed[:], ap.Signature); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Check expiration if validity is present
	if ap.Validity != nil {
		if err := ap.Validity.CheckExpiration(); err != nil {
			return nil, err
		}
	}

	// If encrypted, decrypt the payload
	if ap.IsEncrypted() {
		// Try to get RSA private key - handle both direct *rsa.PrivateKey and wrapper types
		rsaKey := extractRSAPrivateKey(deviceKey)
		if rsaKey == nil {
			return nil, fmt.Errorf("encrypted payloads require RSA device key, got %T", deviceKey)
		}
		decrypted, err := DecryptPayload(rsaKey, ap.WrappedKey, ap.IV, ap.Ciphertext)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: %w", err)
		}
		return decrypted, nil
	}

	// Return plaintext payload
	return ap.Payload, nil
}

// extractRSAPrivateKey extracts an *rsa.PrivateKey from various wrapper types
func extractRSAPrivateKey(key crypto.Signer) *rsa.PrivateKey {
	if key == nil {
		return nil
	}
	// Direct RSA key
	if rsaKey, ok := key.(*rsa.PrivateKey); ok {
		return rsaKey
	}
	// Use reflection to extract embedded Signer field (for blob.Pkcs8Key and similar)
	v := reflect.ValueOf(key)
	if v.Kind() == reflect.Struct {
		// Look for embedded crypto.Signer field
		signerField := v.FieldByName("Signer")
		if signerField.IsValid() && !signerField.IsNil() {
			if signer, ok := signerField.Interface().(crypto.Signer); ok {
				if rsaKey, ok := signer.(*rsa.PrivateKey); ok {
					return rsaKey
				}
			}
		}
	}
	return nil
}

// decryptWithKey decrypts ciphertext using a raw symmetric key and IV
func decryptWithKey(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid IV size: expected %d, got %d", aes.BlockSize, len(iv))
	}

	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// verifySignature verifies a signature using the appropriate algorithm based on key type
func verifySignature(pubKey crypto.PublicKey, hash, signature []byte) error {
	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(pub, crypto.SHA384, hash, signature)
		if err != nil {
			return fmt.Errorf("RSA signature verification failed: %w", err)
		}
		return nil

	case *ecdsa.PublicKey:
		sig := new(ecdsaSignature)
		if _, err := asn1.Unmarshal(signature, sig); err != nil {
			return fmt.Errorf("failed to unmarshal ECDSA signature: %w", err)
		}
		if !ecdsa.Verify(pub, hash, sig.R, sig.S) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil

	default:
		return fmt.Errorf("unsupported key type: %T", pubKey)
	}
}
