// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

// BMO provisioning artifact signing and verification per fdo.bmo.md
// §Authorization of Provisioning Messages.

package fsim

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	fdo "github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

// Content-type values per fdo.bmo.md §Content-Type Registry.
const (
	BMOContentTypeImageBegin = "application/cbor+fdo.bmo.image-begin"
	BMOContentTypeSet        = "application/cbor+fdo.bmo.set"
)

// BMO error code for provisioning not authorized.
const BMOErrorProvisionNotAuthorized = 15

// BmoScopeLabel is the protected header label for fdo.bmo.scope.
const BmoScopeLabel = "fdo.bmo.scope"

// COSE header labels.
var (
	contentTypeLabel    = cose.Label{Int64: 3}
	bmoScopeLabel       = cose.Label{Str: BmoScopeLabel}
	x5chainLabel        = cose.Label{Int64: 33} // RFC 9360: x5chain unprotected header
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

// OwnerSigner signs provisioning artifacts directly with the Owner key.
// No x5chain is included in the unprotected header (Owner-direct mode).
type OwnerSigner struct {
	Key   *ecdsa.PrivateKey
	Scope *BmoScope // Optional scope constraints
}

var _ ProvisioningSigner = (*OwnerSigner)(nil)

// Sign implements ProvisioningSigner.
func (s *OwnerSigner) Sign(payloadCBOR []byte, contentType string) ([]byte, error) {
	return signProvisioningArtifact(payloadCBOR, contentType, s.Scope, s.Key, nil)
}

// DelegateSigner signs provisioning artifacts with a Delegate key and includes
// the x5chain (leaf-first certificate chain) in the unprotected header.
// The leaf certificate MUST carry OIDPermitProvision (PERM.7).
type DelegateSigner struct {
	Key   *ecdsa.PrivateKey
	Chain []*x509.Certificate // Leaf first, as per RFC 9360
	Scope *BmoScope           // Optional scope constraints
}

var _ ProvisioningSigner = (*DelegateSigner)(nil)

// Sign implements ProvisioningSigner.
func (s *DelegateSigner) Sign(payloadCBOR []byte, contentType string) ([]byte, error) {
	if len(s.Chain) == 0 {
		return nil, fmt.Errorf("DelegateSigner requires at least one certificate in Chain")
	}
	// Verify the leaf carries OIDPermitProvision before signing.
	leaf := s.Chain[0]
	if !hasOID(leaf, fdo.OIDPermitProvision) {
		return nil, fmt.Errorf("delegate leaf certificate does not carry OIDPermitProvision (PERM.7)")
	}
	return signProvisioningArtifact(payloadCBOR, contentType, s.Scope, s.Key, s.Chain)
}

// hasOID checks whether a certificate carries a given OID in its
// ExtKeyUsage or UnhandledCriticalExtensions / ExtraExtensions.
func hasOID(cert *x509.Certificate, target asn1.ObjectIdentifier) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(target) {
			return true
		}
	}
	// Also check parsed ExtKeyUsage OIDs (Go may parse some into enums).
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(target) {
			return true
		}
	}
	return false
}

// signProvisioningArtifact is the shared implementation for OwnerSigner and DelegateSigner.
func signProvisioningArtifact(payloadCBOR []byte, contentType string, scope *BmoScope, signer *ecdsa.PrivateKey, chain []*x509.Certificate) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("signer is required")
	}

	opts, err := signerOptsFor(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("unsupported signer key type: %w", err)
	}

	var sign1 cose.Sign1[[]byte, []byte]
	sign1.Payload = cbor.NewByteWrap(payloadCBOR)

	// Protected header: { 1: alg, 3: contentType, ?"fdo.bmo.scope": scope }
	sign1.Protected = make(cose.HeaderMap)
	sign1.Protected[contentTypeLabel] = contentType
	if scope != nil {
		scopeCBOR, err := scope.MarshalCBOR()
		if err != nil {
			return nil, fmt.Errorf("marshaling scope: %w", err)
		}
		sign1.Protected[bmoScopeLabel] = cbor.RawBytes(scopeCBOR)
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

	// Sign with external AAD = CBOR(["FDO-FSIM-BmoProvision-v1"])
	aad := fdoBmoProvisionAAD()
	if err := sign1.Sign(signer, nil, aad, opts); err != nil {
		return nil, fmt.Errorf("COSE Sign1 signing failed: %w", err)
	}

	return sign1.Tag().MarshalCBOR()
}

// VerifyBmoSigned verifies a COSE_Sign1-wrapped provisioning artifact against
// the TO2-proven Owner public key. It checks content_type, verifies the
// signature using the BMO provisioning AAD, and validates delegate x5chain
// when present.
//
// Returns the inner payload CBOR on success.
func VerifyBmoSigned(signedData []byte, ownerKey crypto.PublicKey, expectedContentType string) ([]byte, error) {
	if ownerKey == nil {
		return nil, fmt.Errorf("ownerKey is required for provisioning verification")
	}

	var sign1Tag cose.Sign1Tag[[]byte, []byte]
	if err := cbor.Unmarshal(signedData, &sign1Tag); err != nil {
		return nil, fmt.Errorf("failed to parse COSE_Sign1: %w", err)
	}

	// Check content_type in protected header
	var ct string
	if ok, err := sign1Tag.Protected.Parse(contentTypeLabel, &ct); err != nil {
		return nil, fmt.Errorf("failed to parse content_type: %w", err)
	} else if !ok {
		return nil, fmt.Errorf("missing content_type in protected header")
	}
	if ct != expectedContentType {
		return nil, fmt.Errorf("content_type mismatch: expected %q, got %q", expectedContentType, ct)
	}

	// Determine verification key: Owner-direct or Delegate x5chain.
	verifyKey := ownerKey
	if sign1Tag.Unprotected != nil && sign1Tag.Unprotected[x5chainLabel] != nil {
		// Delegate mode: x5chain present.
		delegateKey, err := verifyDelegateChain(sign1Tag.Unprotected[x5chainLabel], ownerKey)
		if err != nil {
			return nil, fmt.Errorf("delegate chain verification failed: %w", err)
		}
		verifyKey = delegateKey
	}

	// Verify signature with external AAD
	aad := fdoBmoProvisionAAD()
	valid, err := sign1Tag.Verify(verifyKey, nil, aad)
	if err != nil {
		return nil, fmt.Errorf("signature verification error: %w", err)
	}
	if !valid {
		return nil, fmt.Errorf("signature verification failed")
	}

	if sign1Tag.Payload == nil {
		return nil, fmt.Errorf("COSE_Sign1 has no payload")
	}

	return sign1Tag.Payload.Val, nil
}

// verifyDelegateChain validates the x5chain from the unprotected header.
// The chain must be leaf-first, the leaf must carry OIDPermitProvision,
// and the root must be signed by (or be) the Owner key.
// Returns the leaf's public key on success.
func verifyDelegateChain(x5chainRaw interface{}, ownerKey crypto.PublicKey) (crypto.PublicKey, error) {
	// x5chain is an array of bstr (DER certs), leaf first.
	var derCerts [][]byte

	// The CBOR library may decode as []interface{} or [][]byte.
	switch v := x5chainRaw.(type) {
	case []interface{}:
		for _, item := range v {
			b, ok := item.([]byte)
			if !ok {
				return nil, fmt.Errorf("x5chain entry is not a byte string")
			}
			derCerts = append(derCerts, b)
		}
	case [][]byte:
		derCerts = v
	default:
		return nil, fmt.Errorf("x5chain has unexpected type %T", x5chainRaw)
	}

	if len(derCerts) == 0 {
		return nil, fmt.Errorf("x5chain is empty")
	}

	// Parse all certificates.
	certs := make([]*x509.Certificate, len(derCerts))
	for i, der := range derCerts {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing x5chain cert %d: %w", i, err)
		}
		certs[i] = cert
	}

	// Leaf must carry OIDPermitProvision.
	leaf := certs[0]
	if !hasOID(leaf, fdo.OIDPermitProvision) {
		return nil, fmt.Errorf("delegate leaf certificate does not carry OIDPermitProvision (PERM.7)")
	}

	// Verify chain: each cert must be signed by the next, and the last must
	// be signed by the Owner key.
	for i := 0; i < len(certs)-1; i++ {
		if err := certs[i].CheckSignatureFrom(certs[i+1]); err != nil {
			return nil, fmt.Errorf("delegate chain: cert %d not signed by cert %d: %w", i, i+1, err)
		}
	}

	// The last cert must be signed by the Owner key.
	lastCert := certs[len(certs)-1]
	ownerECKey, ok := ownerKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Owner key is %T, expected *ecdsa.PublicKey", ownerKey)
	}

	// Build a synthetic self-signed cert-like structure to verify the last cert
	// against the Owner key. We check if the last cert's issuer key matches the
	// Owner key, or if it's a self-referencing chain.
	//
	// For a single-cert chain (self-signed delegate issued by Owner):
	// the cert was signed by the Owner key directly.
	if err := lastCert.CheckSignature(lastCert.SignatureAlgorithm, lastCert.RawTBSCertificate, lastCert.Signature); err != nil {
		// The cert is not self-signed; check if it was signed by the Owner.
		_ = ownerECKey // We need to verify using the Owner key.
	}

	// More direct approach: use ecdsa.VerifyASN1 on the raw TBS.
	if !verifyWithOwnerKey(lastCert, ownerECKey) {
		return nil, fmt.Errorf("delegate chain: root certificate not signed by Owner key")
	}

	return leaf.PublicKey, nil
}

// verifyWithOwnerKey checks that a certificate was signed by the Owner key.
func verifyWithOwnerKey(cert *x509.Certificate, ownerKey *ecdsa.PublicKey) bool {
	return ecdsa.VerifyASN1(ownerKey, hashForSignature(cert), cert.Signature)
}

// hashForSignature computes the hash of the TBS certificate using the
// algorithm indicated by the certificate's signature algorithm.
func hashForSignature(cert *x509.Certificate) []byte {
	var hash crypto.Hash
	switch cert.SignatureAlgorithm {
	case x509.ECDSAWithSHA256:
		hash = crypto.SHA256
	case x509.ECDSAWithSHA384:
		hash = crypto.SHA384
	case x509.ECDSAWithSHA512:
		hash = crypto.SHA512
	default:
		hash = crypto.SHA256
	}
	h := hash.New()
	h.Write(cert.RawTBSCertificate)
	return h.Sum(nil)
}
