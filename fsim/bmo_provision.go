// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	fdo "github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

// BMO Authenticated Provisioning (see fdo.bmo.md §"Authenticated Provisioning").
//
// Every security-sensitive BMO message (image-begin-signed, set-signed) is
// transmitted as a tagged COSE_Sign1 (CBOR tag 18). The inner payload is the
// original CBOR (ImageBegin map or set array). The signer is either the Owner
// (signature verifies with the TO2-proven Owner public key directly) or a
// Delegate whose certificate chain is placed in the unprotected x5chain header
// (COSE label 33, RFC 9360); the chain MUST chain back to the Owner key and
// the leaf MUST carry OIDPermitProvision.

// BMO provisioning message content types.
const (
	// BMOContentTypeImageBegin is the COSE content-type for a signed image-begin payload.
	BMOContentTypeImageBegin = "application/cbor+fdo.bmo.image-begin"
	// BMOContentTypeSet is the COSE content-type for a signed BIOS set payload.
	BMOContentTypeSet = "application/cbor+fdo.bmo.set"
)

// Per fdo.bmo.md §"Authorization of Provisioning Messages", the signed wire-
// level message keys are unchanged: `fdo.bmo:image-begin` and `fdo.bmo:set`.
// The distinction between "legacy unsigned" and "spec-compliant signed" is
// carried in the message BODY: a conforming signed message is a tagged
// COSE_Sign1 (CBOR tag 18); an unsigned message is a raw CBOR map/array.
// No separate "-signed" wire key is defined by the specification.

// BMOErrorProvisionNotAuthorized is error code 15 per fdo.bmo.md.
const BMOErrorProvisionNotAuthorized = 15

// x5chainLabel is the COSE header label 33 (RFC 9360) carrying an array of
// DER-encoded X.509 certificates, leaf first.
var x5chainLabel = cose.Label{Int64: 33}

// contentTypeLabel is the COSE "content type" protected-header label (3).
var contentTypeLabel = cose.Label{Int64: 3}

// ProvisioningSigner signs BMO provisioning payloads (image-begin / set) as a
// tagged COSE_Sign1 using the Owner key directly, or a Delegate key with the
// delegate certificate chain embedded in the unprotected x5chain header.
type ProvisioningSigner interface {
	// Sign wraps payload in a tagged COSE_Sign1 with the given content type
	// (BMOContentTypeImageBegin or BMOContentTypeSet). Returns CBOR-encoded
	// tagged COSE_Sign1 bytes suitable for emission as the FSIM message body.
	Sign(payload []byte, contentType string) ([]byte, error)
}

// OwnerSigner is a ProvisioningSigner that signs directly with the Owner key.
// No x5chain is emitted; devices verify with the TO2-proven Owner public key.
type OwnerSigner struct {
	Key crypto.Signer
}

// Sign implements ProvisioningSigner.
func (s *OwnerSigner) Sign(payload []byte, contentType string) ([]byte, error) {
	if s == nil || s.Key == nil {
		return nil, fmt.Errorf("bmo: OwnerSigner has no key")
	}
	return signBmo(s.Key, nil, payload, contentType)
}

// DelegateSigner is a ProvisioningSigner that signs with a delegate private
// key and embeds the delegate certificate chain (leaf first, DER) in the
// unprotected x5chain header.
//
// The leaf MUST carry OIDPermitProvision and the top-most certificate's
// signature MUST be verifiable by the Owner key (the device enforces both).
type DelegateSigner struct {
	Key   crypto.Signer
	Chain []*x509.Certificate // leaf first
}

// Sign implements ProvisioningSigner.
func (s *DelegateSigner) Sign(payload []byte, contentType string) ([]byte, error) {
	if s == nil || s.Key == nil {
		return nil, fmt.Errorf("bmo: DelegateSigner has no key")
	}
	if len(s.Chain) == 0 {
		return nil, fmt.Errorf("bmo: DelegateSigner has empty certificate chain")
	}
	if !fdo.CertHasPermissionOID(s.Chain[0], fdo.OIDPermitProvision) {
		return nil, fmt.Errorf("bmo: delegate leaf certificate lacks OIDPermitProvision")
	}
	derChain := make([][]byte, len(s.Chain))
	for i, c := range s.Chain {
		derChain[i] = c.Raw
	}
	return signBmo(s.Key, derChain, payload, contentType)
}

// signBmo builds a tagged COSE_Sign1 with the BMO domain-separation AAD.
func signBmo(key crypto.Signer, x5chain [][]byte, payload []byte, contentType string) ([]byte, error) {
	s1 := cose.Sign1[[]byte, []byte]{
		Header: cose.Header{
			Protected: cose.HeaderMap{
				contentTypeLabel: contentType,
			},
			Unprotected: cose.HeaderMap{},
		},
		Payload: cbor.NewByteWrap(payload),
	}
	if len(x5chain) > 0 {
		s1.Unprotected[x5chainLabel] = x5chain
	}
	opts := signOptsForKey(key)
	if err := s1.Sign(key, nil, cose.AADBmoProvision, opts); err != nil {
		return nil, fmt.Errorf("bmo: COSE_Sign1 signing failed: %w", err)
	}
	return cbor.Marshal(s1.Tag())
}

// signOptsForKey picks appropriate crypto.SignerOpts for a key. ECDSA/Ed25519
// keys need nil; RSA keys need a SHA-256 hash hint for PKCS1v15.
func signOptsForKey(key crypto.Signer) crypto.SignerOpts {
	if _, ok := key.Public().(*rsa.PublicKey); ok {
		return crypto.SHA256
	}
	return nil
}

// VerifyBmoSigned verifies a tagged COSE_Sign1 BMO provisioning message.
//
//   - raw is the CBOR bytes of the tagged COSE_Sign1.
//   - ownerKey is the Owner public key proven during TO2 (trust anchor).
//   - expectedContentType is BMOContentTypeImageBegin or BMOContentTypeSet.
//
// Returns the verified inner payload bytes (original ImageBegin or set CBOR)
// on success. On any failure, the returned error is suitable for mapping to
// BMOErrorProvisionNotAuthorized.
func VerifyBmoSigned(raw []byte, ownerKey crypto.PublicKey, expectedContentType string) ([]byte, error) {
	if ownerKey == nil {
		return nil, fmt.Errorf("bmo: owner public key required for provisioning verification")
	}

	var s1t cose.Sign1Tag[[]byte, []byte]
	if err := cbor.Unmarshal(raw, &s1t); err != nil {
		return nil, fmt.Errorf("bmo: decode COSE_Sign1: %w", err)
	}

	// Check content type in protected header.
	var contentType string
	if found, err := s1t.Protected.Parse(contentTypeLabel, &contentType); err != nil {
		return nil, fmt.Errorf("bmo: parse content-type: %w", err)
	} else if !found {
		return nil, fmt.Errorf("bmo: missing content-type protected header")
	}
	if contentType != expectedContentType {
		return nil, fmt.Errorf("bmo: content-type mismatch: got %q, expected %q", contentType, expectedContentType)
	}

	// Determine signer: delegate chain (if x5chain present) or Owner directly.
	signerKey := ownerKey
	var chainDER [][]byte
	if found, err := s1t.Unprotected.Parse(x5chainLabel, &chainDER); err != nil {
		return nil, fmt.Errorf("bmo: parse x5chain: %w", err)
	} else if found && len(chainDER) > 0 {
		chain := make([]*x509.Certificate, len(chainDER))
		for i, der := range chainDER {
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("bmo: parse x5chain[%d]: %w", i, err)
			}
			chain[i] = c
		}
		// Chain MUST validate up to the Owner key, AND leaf MUST carry OIDPermitProvision.
		oid := fdo.OIDPermitProvision
		if err := fdo.VerifyDelegateChain(chain, &ownerKey, &oid); err != nil {
			return nil, fmt.Errorf("bmo: delegate chain invalid: %w", err)
		}
		signerKey = chain[0].PublicKey
	}

	// Verify the COSE_Sign1 signature with domain-separation AAD.
	ok, err := s1t.Verify(signerKey, nil, cose.AADBmoProvision)
	if err != nil {
		return nil, fmt.Errorf("bmo: signature verification error: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("bmo: signature verification failed")
	}

	if s1t.Payload == nil {
		return nil, fmt.Errorf("bmo: COSE_Sign1 has no payload")
	}
	return s1t.Payload.Val, nil
}
