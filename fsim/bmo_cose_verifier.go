// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"fmt"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

// CoseSign1Verifier is the default MetaPayloadVerifier implementation.
// It verifies COSE Sign1 signatures on meta-payloads using the signer key
// provided by the owner during the FSIM exchange.
//
// The signerKey parameter is a CBOR-encoded COSE_Key (RFC 8152 Section 7).
// The signedPayload is a CBOR-encoded COSE_Sign1 structure (tag 18).
// On success, the inner payload (the MetaPayload CBOR) is returned.
//
// This verifier supports EC2 keys (P-256, P-384, P-521) with ECDSA
// signature algorithms (ES256, ES384, ES512).
type CoseSign1Verifier struct{}

// Verify checks the COSE Sign1 signature on a meta-payload.
// signerKey is a CBOR-encoded COSE_Key used for verification.
// signedPayload is a CBOR-encoded COSE_Sign1 (tagged) structure.
// Returns the inner payload (MetaPayload CBOR) if signature is valid.
func (v *CoseSign1Verifier) Verify(signedPayload []byte, signerKey []byte) ([]byte, error) {
	// Parse the COSE_Key from the signer key bytes
	var key cose.Key
	if err := cbor.Unmarshal(signerKey, &key); err != nil {
		return nil, fmt.Errorf("failed to parse COSE_Key: %w", err)
	}

	// Extract the public key for verification
	pubKey, err := key.Public()
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key from COSE_Key: %w", err)
	}

	// Parse the COSE_Sign1 tagged structure
	// Payload type is []byte (raw CBOR bytes = the MetaPayload)
	// External AAD type is []byte (nil = no external AAD)
	var sign1Tag cose.Sign1Tag[[]byte, []byte]
	if err := cbor.Unmarshal(signedPayload, &sign1Tag); err != nil {
		return nil, fmt.Errorf("failed to parse COSE_Sign1: %w", err)
	}

	// Verify the signature (no external AAD for meta-payloads)
	valid, err := sign1Tag.Verify(pubKey, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("signature verification error: %w", err)
	}
	if !valid {
		return nil, fmt.Errorf("signature verification failed: invalid signature")
	}

	// Extract and return the inner payload
	if sign1Tag.Payload == nil {
		return nil, fmt.Errorf("COSE_Sign1 has no payload")
	}

	return sign1Tag.Payload.Val, nil
}

// NewCoseSign1Verifier creates a new CoseSign1Verifier instance.
func NewCoseSign1Verifier() *CoseSign1Verifier {
	return &CoseSign1Verifier{}
}
