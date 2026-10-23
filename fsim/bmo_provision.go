// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

// BMO provisioning artifact signing and verification per fdo.bmo.md
// §Authorization of Provisioning Messages.

package fsim

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"time"

	fdo "github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/fsim/chunking"
)

// Content-type values per fdo.bmo.md §Content-Type Registry.
const (
	BMOContentTypeImageBegin = "application/cbor+fdo.bmo.image-begin"
	BMOContentTypeSet        = "application/cbor+fdo.bmo.set"
)

// BMOErrorProvisionNotAuthorized is the BMO error code for provisioning not authorized.
const BMOErrorProvisionNotAuthorized = 15

// BmoScopeLabel is the legacy fdo.bmo scope label, still accepted by devices.
//
// Deprecated: senders emit the generic label chunking.ScopeLabel ("fdo.scope").
const BmoScopeLabel = "fdo.bmo.scope"

// COSE header labels.
var (
	contentTypeLabel = cose.Label{Int64: 3}
	x5chainLabel     = cose.Label{Int64: 33} // RFC 9360: x5chain unprotected header
)

// BmoScope defines the scope constraints for a BMO provisioning artifact.
// All fields are optional; an absent field is an absent constraint.
type BmoScope struct {
	GUID       []byte   // 16-byte FDO GUID, or nil
	GUIDs      [][]byte // Multiple GUIDs (array of bstr), or nil
	NotBefore  uint64   // Seconds since Unix epoch (0 = absent)
	NotAfter   uint64   // Seconds since Unix epoch (0 = absent)
	Generation uint64   // Monotonic supersession counter (0 = absent)
}

// MarshalCBOR encodes BmoScope as a CBOR map with text-string keys.
func (s *BmoScope) MarshalCBOR() ([]byte, error) {
	m := make(map[string]interface{})
	if len(s.GUIDs) > 0 {
		m["guid"] = s.GUIDs
	} else if len(s.GUID) > 0 {
		m["guid"] = s.GUID
	}
	if s.NotBefore > 0 {
		m["not_before"] = s.NotBefore
	}
	if s.NotAfter > 0 {
		m["not_after"] = s.NotAfter
	}
	if s.Generation > 0 {
		m["generation"] = s.Generation
	}
	return cbor.Marshal(m)
}

// fdoBmoProvisionAAD returns the CBOR encoding of ["FDO-FSIM-BmoProvision-v1"],
// the external AAD for all BMO provisioning signatures per fdo.bmo.md.
func fdoBmoProvisionAAD() []byte {
	data, err := cbor.Marshal([]string{"FDO-FSIM-BmoProvision-v1"})
	if err != nil {
		panic("failed to marshal FdoBmoProvisionAAD: " + err.Error())
	}
	return data
}

// ProvisioningSigner is the interface used by BMOOwner to wrap image-begin
// and set messages in a tagged COSE_Sign1.
type ProvisioningSigner interface {
	// Sign wraps payloadCBOR in a COSE_Sign1 (tag 18) with the given
	// content_type and the FdoBmoProvisionAAD. Returns the tagged COSE_Sign1 bytes.
	Sign(payloadCBOR []byte, contentType string) ([]byte, error)
}

// ArtifactSigner signs an authorization artifact for any FSIM: the caller
// supplies the FSIM's registered content type and external_aad
// (chunking-strategy.md "FSIM Declarations"). OwnerSigner and DelegateSigner
// implement it.
type ArtifactSigner interface {
	SignArtifact(payloadCBOR []byte, contentType string, aad []byte) ([]byte, error)
}

// OwnerSigner signs provisioning artifacts directly with the Owner key.
// No x5chain is included in the unprotected header (Owner-direct mode).
type OwnerSigner struct {
	Key   *ecdsa.PrivateKey
	Scope *BmoScope // Optional scope constraints
}

var (
	_ ProvisioningSigner = (*OwnerSigner)(nil)
	_ ArtifactSigner     = (*OwnerSigner)(nil)
)

// Sign implements ProvisioningSigner.
func (s *OwnerSigner) Sign(payloadCBOR []byte, contentType string) ([]byte, error) {
	return s.SignArtifact(payloadCBOR, contentType, fdoBmoProvisionAAD())
}

// SignArtifact implements ArtifactSigner.
func (s *OwnerSigner) SignArtifact(payloadCBOR []byte, contentType string, aad []byte) ([]byte, error) {
	return signProvisioningArtifact(payloadCBOR, contentType, aad, s.Scope, s.Key, nil)
}

// DelegateSigner signs provisioning artifacts with a Delegate key and includes
// the x5chain (leaf-first certificate chain) in the unprotected header.
// The leaf certificate MUST carry OIDPermitProvision (PERM.7).
type DelegateSigner struct {
	Key   *ecdsa.PrivateKey
	Chain []*x509.Certificate // Leaf first, as per RFC 9360
	Scope *BmoScope           // Optional scope constraints
}

var (
	_ ProvisioningSigner = (*DelegateSigner)(nil)
	_ ArtifactSigner     = (*DelegateSigner)(nil)
)

// Sign implements ProvisioningSigner.
func (s *DelegateSigner) Sign(payloadCBOR []byte, contentType string) ([]byte, error) {
	return s.SignArtifact(payloadCBOR, contentType, fdoBmoProvisionAAD())
}

// SignArtifact implements ArtifactSigner.
func (s *DelegateSigner) SignArtifact(payloadCBOR []byte, contentType string, aad []byte) ([]byte, error) {
	if len(s.Chain) == 0 {
		return nil, fmt.Errorf("DelegateSigner requires at least one certificate in Chain")
	}
	// The chain must grant OIDPermitProvision: present in every certificate.
	if !fdo.DelegateHasPermission(s.Chain, fdo.OIDPermitProvision) {
		return nil, fmt.Errorf("delegate chain does not grant OIDPermitProvision (PERM.7) in every certificate")
	}
	return signProvisioningArtifact(payloadCBOR, contentType, aad, s.Scope, s.Key, s.Chain)
}

// signProvisioningArtifact is the shared implementation for OwnerSigner and DelegateSigner.
func signProvisioningArtifact(payloadCBOR []byte, contentType string, aad []byte, scope *BmoScope, signer *ecdsa.PrivateKey, chain []*x509.Certificate) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("signer is required")
	}

	opts, err := signerOptsFor(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("unsupported signer key type: %w", err)
	}

	var sign1 cose.Sign1[[]byte, []byte]
	sign1.Payload = cbor.NewByteWrap(payloadCBOR)

	// Protected header: { 1: alg, 3: contentType, ?"fdo.scope": scope }
	sign1.Protected = make(cose.HeaderMap)
	sign1.Protected[contentTypeLabel] = contentType
	if scope != nil {
		scopeCBOR, err := scope.MarshalCBOR()
		if err != nil {
			return nil, fmt.Errorf("marshaling scope: %w", err)
		}
		sign1.Protected[chunking.ScopeLabel] = cbor.RawBytes(scopeCBOR)
	}

	// Unprotected header: { ?33: x5chain }
	if len(chain) > 0 {
		derCerts := make([][]byte, len(chain))
		for i, cert := range chain {
			derCerts[i] = cert.Raw
		}
		sign1.Unprotected = cose.HeaderMap{
			x5chainLabel: derCerts,
		}
	}

	// Sign with the FSIM's registered external AAD.
	if err := sign1.Sign(signer, nil, aad, opts); err != nil {
		return nil, fmt.Errorf("COSE Sign1 signing failed: %w", err)
	}

	return sign1.Tag().MarshalCBOR()
}

// VerifyBmoSigned verifies a COSE_Sign1-wrapped provisioning artifact against
// the TO2-proven Owner public key, using the generic verifier
// (chunking.VerifyArtifact) with the BMO provisioning AAD. Scope is evaluated
// with the system clock and no device GUID or generation storage, so an
// artifact carrying a "guid" or "generation" constraint is rejected; devices
// should use VerifyBmoSignedScoped.
//
// Returns the inner payload CBOR on success.
func VerifyBmoSigned(signedData []byte, ownerKey crypto.PublicKey, expectedContentType string) ([]byte, error) {
	return VerifyBmoSignedScoped(signedData, ownerKey, expectedContentType, chunking.ScopeContext{Now: time.Now})
}

// VerifyBmoSignedScoped is VerifyBmoSigned with an explicit scope context
// (device GUID, trusted clock, generation storage).
func VerifyBmoSignedScoped(signedData []byte, ownerKey crypto.PublicKey, expectedContentType string, sc chunking.ScopeContext) ([]byte, error) {
	return chunking.VerifyArtifact(signedData, ownerKey, expectedContentType, fdoBmoProvisionAAD(), sc)
}
