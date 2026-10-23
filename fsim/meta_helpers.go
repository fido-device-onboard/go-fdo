// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	fdo "github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

// MetaPayloadOption is a functional option for CreateMetaPayload.
type MetaPayloadOption func(*MetaPayload)

// WithTLSCA sets the optional TLS CA cert (DER-encoded) for the image URL.
func WithTLSCA(tlsCA []byte) MetaPayloadOption {
	return func(m *MetaPayload) { m.TLSCA = tlsCA }
}

// WithBootArgs sets optional kernel/boot arguments.
func WithBootArgs(args string) MetaPayloadOption {
	return func(m *MetaPayload) { m.BootArgs = args }
}

// WithVersion sets an optional version string.
func WithVersion(version string) MetaPayloadOption {
	return func(m *MetaPayload) { m.Version = version }
}

// WithDescription sets an optional description.
func WithDescription(desc string) MetaPayloadOption {
	return func(m *MetaPayload) { m.Description = desc }
}

// CreateMetaPayload builds a MetaPayload CBOR byte slice from the given parameters.
// mimeType and imageURL are required. name, hashAlg, and expectedHash are optional
// (pass empty string / nil to omit). Additional fields can be set via options.
func CreateMetaPayload(mimeType, imageURL, name, hashAlg string, expectedHash []byte, opts ...MetaPayloadOption) ([]byte, error) {
	if mimeType == "" {
		return nil, fmt.Errorf("mimeType is required")
	}
	if imageURL == "" {
		return nil, fmt.Errorf("imageURL is required")
	}

	meta := &MetaPayload{
		MIMEType:     mimeType,
		URL:          imageURL,
		Name:         name,
		HashAlg:      hashAlg,
		ExpectedHash: expectedHash,
	}

	for _, opt := range opts {
		opt(meta)
	}

	return meta.MarshalCBOR()
}

// ComputeSHA256 computes the SHA-256 hash of the given data.
// This is a convenience function for computing the hash to pass as expectedHash
// to CreateMetaPayload.
func ComputeSHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// SignMetaPayload wraps a MetaPayload CBOR byte slice in a COSE Sign1 envelope,
// signed with the provided key. The returned bytes are the CBOR-encoded
// COSE_Sign1_Tagged structure that can be served as a signed meta-payload file.
//
// Use this for a third-party publisher whose public key the Owner names in
// image-begin (meta_signer, key 9), or for the Owner key itself. For a
// provisioning Delegate, use SignMetaPayloadWithChain.
//
// The signer must be an ECDSA key (P-256 or P-384). RSA keys are not currently
// supported for meta-payload signing because cose.NewKey only supports EC keys.
func SignMetaPayload(metaPayloadCBOR []byte, signer crypto.Signer) ([]byte, error) {
	return SignMetaPayloadWithChain(metaPayloadCBOR, signer, nil)
}

// SignMetaPayloadWithChain signs a meta-payload as a provisioning Delegate:
// chain (leaf first, up to but not including the Owner key) is carried in the
// unprotected x5chain header (label 33). The device verifies it against the
// TO2-proven Owner key when image-begin names no meta_signer; the chain must
// grant fdo-ekt-permit-provision (PERM.7) in every certificate, and the leaf
// must certify signer's public key.
func SignMetaPayloadWithChain(metaPayloadCBOR []byte, signer crypto.Signer, chain []*x509.Certificate) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("signer is required")
	}

	// Determine signer opts based on key type
	opts, err := signerOptsFor(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("unsupported signer key type: %w", err)
	}

	var sign1 cose.Sign1[[]byte, []byte]
	sign1.Payload = cbor.NewByteWrap(metaPayloadCBOR)

	if len(chain) > 0 {
		if !fdo.DelegateHasPermission(chain, fdo.OIDPermitProvision) {
			return nil, fmt.Errorf("delegate chain does not grant fdo-ekt-permit-provision (PERM.7) in every certificate")
		}
		leafPub, ok := chain[0].PublicKey.(interface{ Equal(crypto.PublicKey) bool })
		if !ok || !leafPub.Equal(signer.Public()) {
			return nil, fmt.Errorf("signing key does not match the leaf certificate of the delegate chain")
		}
		ders := make([][]byte, len(chain))
		for i, c := range chain {
			ders[i] = c.Raw
		}
		sign1.Unprotected = cose.HeaderMap{x5chainLabel: ders}
	}

	if err := sign1.Sign(signer, nil, cose.AADMetaPayload, opts); err != nil {
		return nil, fmt.Errorf("COSE Sign1 signing failed: %w", err)
	}

	return sign1.Tag().MarshalCBOR()
}

// MarshalSignerPublicKey returns the COSE_Key (CBOR) encoding of the signer's
// public key. This is the value that gets sent as the meta_signer field (-10)
// in the BMO image-begin message, and is used by the device to verify the
// COSE Sign1 signature on the meta-payload.
func MarshalSignerPublicKey(pub crypto.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("public key is required")
	}

	coseKey, err := cose.NewKey(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to create COSE_Key: %w", err)
	}

	data, err := coseKey.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal COSE_Key: %w", err)
	}

	return data, nil
}

// signerOptsFor returns the appropriate crypto.SignerOpts for the given public key.
func signerOptsFor(pub crypto.PublicKey) (crypto.SignerOpts, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		// ECDSA keys don't need explicit opts — the cose package determines
		// the algorithm from the curve.
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported key type %T; only ECDSA keys are supported for meta-payload signing", pub)
	}
}
