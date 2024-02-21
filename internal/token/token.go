// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package token implements all server state interfaces possible using a
// stateless token.
package token

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
)

var errInvalidToken = fmt.Errorf("invalid token")
var errNotFound = fmt.Errorf("not found")

// Unique provides randomness to a token before any state is set.
type Unique struct {
	Random [16]byte
}

func (u Unique) id() []byte { return u.Random[:] }

type diState struct {
	Unique
	OVH   *fdo.VoucherHeader
	Chain []*cbor.X509Certificate
}

type to1State struct {
	Unique
}

type to2State struct {
	Unique
}

// CA for creating a device certificate chain
type CA struct {
	Key   crypto.Signer
	Chain []*x509.Certificate
}

// Service implements the fdo.TokenService interface and state interfaces
// that do not need to persist beyond a single protocol session.
type Service struct {
	HmacSecret []byte
	CAs        map[fdo.KeyType]CA
}

var _ fdo.TokenService = (*Service)(nil)
var _ fdo.VoucherCreationState = (*Service)(nil)

// NewService initializes a stateless token service with a random HMAC secret
// and self-signed CAs for the common key types.
func NewService() (*Service, error) {
	// Hmac secret
	var secret [64]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return nil, err
	}

	// Private keys
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	ec256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	ec384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// CA cert chains
	generateCA := func(key crypto.Signer) ([]*x509.Certificate, error) {
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "Test CA"},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(30 * 365 * 24 * time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		return []*x509.Certificate{cert}, nil
	}
	rsaChain, err := generateCA(rsaKey)
	if err != nil {
		return nil, err
	}
	ec256Chain, err := generateCA(ec256Key)
	if err != nil {
		return nil, err
	}
	ec384Chain, err := generateCA(ec384Key)
	if err != nil {
		return nil, err
	}

	return &Service{
		HmacSecret: secret[:],
		CAs: map[fdo.KeyType]CA{
			fdo.Rsa2048RestrKeyType: {
				Key:   rsaKey,
				Chain: rsaChain,
			},
			fdo.RsaPkcsKeyType: {
				Key:   rsaKey,
				Chain: rsaChain,
			},
			fdo.RsaPssKeyType: {
				Key:   rsaKey,
				Chain: rsaChain,
			},
			fdo.Secp256r1KeyType: {
				Key:   ec256Key,
				Chain: ec256Chain,
			},
			fdo.Secp384r1KeyType: {
				Key:   ec384Key,
				Chain: ec384Chain,
			},
		},
	}, nil
}

// NewToken initializes state for a given protocol and return the
// associated token.
func (s Service) NewToken(ctx context.Context, proto fdo.Protocol) (string, error) {
	switch proto {
	case fdo.DIProtocol:
		return newToken[*diState, diState](s.HmacSecret)
	case fdo.TO1Protocol:
		return newToken[*to1State, to1State](s.HmacSecret)
	case fdo.TO2Protocol:
		return newToken[*to2State, to2State](s.HmacSecret)
	default:
		return "", fmt.Errorf("unsupported protocol %s", proto)
	}
}

type contextKey struct{}

var key contextKey

// TokenContext injects a context with a token value so that it may be used
// for any of the XXXState interfaces.
func (s Service) TokenContext(parent context.Context, token string) context.Context {
	return context.WithValue(parent, key, &token)
}

// TokenFromContext gets the token value from a context. This is useful,
// because some TokenServices may allow token mutation, such as in the case
// of token-encoded state (i.e. JWTs/CWTs).
func (s Service) TokenFromContext(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(key).(*string)
	if !ok || token == nil {
		return "", false
	}
	return *token, true
}

// NewDeviceCertChain creates a device certificate chain based on info
// provided in the (non-normative) DI.AppStart message and also stores it
// in session state.
func (s Service) NewDeviceCertChain(ctx context.Context, info fdo.DeviceMfgInfo) ([]*x509.Certificate, error) {
	token, ok := ctx.Value(key).(*string)
	if !ok {
		return nil, errInvalidToken
	}
	state, err := fromToken[*diState, diState](*token, s.HmacSecret)
	if err != nil {
		return nil, err
	}

	// Sign CSR
	csr := x509.CertificateRequest(info.CertInfo)
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR: %w", err)
	}
	ca, ok := s.CAs[info.KeyType]
	if !ok {
		return nil, fmt.Errorf("unsupported key type %s", info.KeyType)
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("error generating certificate serial number: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Issuer:       ca.Chain[0].Subject,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(30 * 360 * 24 * time.Hour), // Matches Java impl
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Chain[0], csr.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("error signing CSR: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("error parsing signed device cert: %w", err)
	}

	// Update state with cert chain
	chain := append([]*x509.Certificate{cert}, ca.Chain...)
	state.Chain = make([]*cbor.X509Certificate, len(chain))
	for i, cert := range chain {
		state.Chain[i] = (*cbor.X509Certificate)(cert)
	}

	// Mutate token with new state
	newToken, err := toToken(state, s.HmacSecret)
	if err != nil {
		return nil, err
	}
	*token = newToken

	return chain, nil
}

// DeviceCertChain gets a device certificate chain from the current
// session.
func (s Service) DeviceCertChain(ctx context.Context) ([]*x509.Certificate, error) {
	token, ok := s.TokenFromContext(ctx)
	if !ok {
		return nil, errInvalidToken
	}
	state, err := fromToken[*diState, diState](token, s.HmacSecret)
	if err != nil {
		return nil, err
	}
	if len(state.Chain) == 0 {
		return nil, errNotFound
	}
	chain := make([]*x509.Certificate, len(state.Chain))
	for i, cert := range state.Chain {
		chain[i] = (*x509.Certificate)(cert)
	}
	return chain, nil
}

// SetIncompleteVoucherHeader stores an incomplete (missing HMAC) voucher
// header tied to a session.
func (s Service) SetIncompleteVoucherHeader(ctx context.Context, ovh *fdo.VoucherHeader) error {
	token, ok := ctx.Value(key).(*string)
	if !ok {
		return errInvalidToken
	}
	state, err := fromToken[*diState, diState](*token, s.HmacSecret)
	if err != nil {
		return err
	}
	state.OVH = ovh
	newToken, err := toToken(state, s.HmacSecret)
	if err != nil {
		return err
	}
	*token = newToken
	return nil
}

// IncompleteVoucherHeader gets an incomplete (missing HMAC) voucher header
// which has not yet been persisted.
func (s Service) IncompleteVoucherHeader(ctx context.Context) (*fdo.VoucherHeader, error) {
	token, ok := s.TokenFromContext(ctx)
	if !ok {
		return nil, errInvalidToken
	}
	state, err := fromToken[*diState, diState](token, s.HmacSecret)
	if err != nil {
		return nil, err
	}
	if state.OVH == nil {
		return nil, errNotFound
	}
	return state.OVH, nil
}
