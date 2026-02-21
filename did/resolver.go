// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package did

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// ResolveResult contains the result of resolving a DID URI.
type ResolveResult struct {
	// PublicKey is the resolved public key.
	PublicKey crypto.PublicKey
	// VoucherRecipientURL is the FDOVoucherRecipient service endpoint, if present.
	VoucherRecipientURL string
	// Document is the full DID Document, if available.
	Document *Document
}

// Resolver resolves DID URIs to public keys and service endpoints.
type Resolver struct {
	HTTPClient *http.Client
}

// NewResolver creates a DID resolver with sensible defaults.
func NewResolver() *Resolver {
	return &Resolver{
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Resolve resolves a DID URI to a public key and optional service endpoints.
func (r *Resolver) Resolve(ctx context.Context, didURI string) (*ResolveResult, error) {
	if strings.HasPrefix(didURI, "did:web:") {
		return r.resolveWeb(ctx, didURI)
	}
	if strings.HasPrefix(didURI, "did:key:") {
		return r.resolveKey(ctx, didURI)
	}
	return nil, fmt.Errorf("unsupported DID method in %q", didURI)
}

// resolveWeb resolves a did:web URI by fetching the DID Document over HTTPS.
func (r *Resolver) resolveWeb(ctx context.Context, didURI string) (*ResolveResult, error) {
	docURL, err := WebDIDToURL(didURI)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, docURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s: %w", docURL, err)
	}
	req.Header.Set("Accept", "application/did+ld+json, application/json")

	client := r.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch DID document from %s: %w", docURL, err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d fetching DID document from %s", resp.StatusCode, docURL)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read DID document: %w", err)
	}

	var doc Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse DID document: %w", err)
	}

	// Verify the document ID matches the requested DID
	if doc.ID != didURI {
		return nil, fmt.Errorf("DID document ID %q does not match requested %q", doc.ID, didURI)
	}

	return r.extractFromDocument(&doc)
}

// resolveKey resolves a did:key URI (multicodec-encoded public key).
// Currently supports P-256 and P-384 keys.
func (r *Resolver) resolveKey(_ context.Context, didURI string) (*ResolveResult, error) {
	// did:key format: did:key:<multibase-encoded-multicodec-key>
	// For now, return an error with guidance
	return nil, fmt.Errorf("did:key resolution not yet implemented for %q; use did:web instead", didURI)
}

// extractFromDocument extracts the public key and service endpoints from a DID Document.
func (r *Resolver) extractFromDocument(doc *Document) (*ResolveResult, error) {
	if len(doc.VerificationMethod) == 0 {
		return nil, fmt.Errorf("DID document has no verification methods")
	}

	// Use the first verification method
	vm := doc.VerificationMethod[0]
	if vm.PublicKeyJwk == nil {
		return nil, fmt.Errorf("verification method %q has no publicKeyJwk", vm.ID)
	}

	pub, err := JWKToPublicKey(vm.PublicKeyJwk)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK from verification method %q: %w", vm.ID, err)
	}

	result := &ResolveResult{
		PublicKey: pub,
		Document:  doc,
	}

	// Look for FDOVoucherRecipient service
	for _, svc := range doc.Service {
		if svc.Type == FDOVoucherRecipientServiceType {
			result.VoucherRecipientURL = svc.ServiceEndpoint
			break
		}
	}

	return result, nil
}

// JWKToPublicKey converts a JWK to a crypto.PublicKey.
func JWKToPublicKey(jwk *JWK) (crypto.PublicKey, error) {
	switch jwk.Kty {
	case "EC":
		return jwkToECPublicKey(jwk)
	case "RSA":
		return jwkToRSAPublicKey(jwk)
	default:
		return nil, fmt.Errorf("unsupported JWK key type: %s", jwk.Kty)
	}
}

func jwkToECPublicKey(jwk *JWK) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", jwk.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("invalid JWK x coordinate: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("invalid JWK y coordinate: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("EC point is not on curve %s", jwk.Crv)
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func jwkToRSAPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("invalid JWK n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("invalid JWK e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	if !e.IsInt64() {
		return nil, fmt.Errorf("JWK exponent too large")
	}

	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}
