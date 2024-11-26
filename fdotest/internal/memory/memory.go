// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package memory implements server state using non-persistent memory to
// complement [internal/token.Service] for state that must persist between
// protocol sessions.
package memory

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
	"encoding/asn1"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// State implements interfaces for state which must be persisted between
// protocol sessions, but not between server processes.
type State struct {
	RVBlobs   map[protocol.GUID]*cose.Sign1[protocol.To1d, []byte]
	Vouchers  map[protocol.GUID]*fdo.Voucher
	OwnerKeys map[protocol.KeyType]struct {
		Key   crypto.Signer
		Chain []*x509.Certificate
	}
	DelegateKeys map[string]struct {
		Key   crypto.Signer
		Chain []*x509.Certificate
	}
}

var _ fdo.RendezvousBlobPersistentState = (*State)(nil)
var _ fdo.ManufacturerVoucherPersistentState = (*State)(nil)
var _ fdo.OwnerVoucherPersistentState = (*State)(nil)
var _ fdo.OwnerKeyPersistentState = (*State)(nil)

// NewState initializes the in-memory state.
func NewState() (*State, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	rsaCert, err := newCA(rsaKey)
	if err != nil {
		return nil, err
	}
	rsaDelegate, err := newDelegateChain(rsaKey)
	if err != nil {
		return nil, err
	}
	ec256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	ec256Cert, err := newCA(ec256Key)
	if err != nil {
		return nil, err
	}
	ec256Delegate, err := newDelegateChain(ec256Key)
	if err != nil {
		return nil, err
	}
	ec384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	ec384Cert, err := newCA(ec384Key)
	if err != nil {
		return nil, err
	}
	ec384Delegate, err := newDelegateChain(ec384Key)
	if err != nil {
		return nil, err
	}
	return &State{
		RVBlobs:  make(map[protocol.GUID]*cose.Sign1[protocol.To1d, []byte]),
		Vouchers: make(map[protocol.GUID]*fdo.Voucher),
		OwnerKeys: map[protocol.KeyType]struct {
			Key   crypto.Signer
			Chain []*x509.Certificate
		}{
			protocol.Rsa2048RestrKeyType: {Key: rsaKey, Chain: []*x509.Certificate{rsaCert}},
			protocol.RsaPkcsKeyType:      {Key: rsaKey, Chain: []*x509.Certificate{rsaCert}},
			protocol.RsaPssKeyType:       {Key: rsaKey, Chain: []*x509.Certificate{rsaCert}},
			protocol.Secp256r1KeyType:    {Key: ec256Key, Chain: []*x509.Certificate{ec256Cert}},
			protocol.Secp384r1KeyType:    {Key: ec384Key, Chain: []*x509.Certificate{ec384Cert}},
		},
		DelegateKeys: map[string]struct {
			Key   crypto.Signer
			Chain []*x509.Certificate
		}{
			"RSA2048RESTR": {Key: rsaKey, Chain: rsaDelegate},
			"SECP256R1": {Key: ec256Key, Chain: ec256Delegate},
			"SECP384R1": {Key: ec384Key, Chain: ec384Delegate},
		},
	}, nil
}

// NewVoucher creates and stores a voucher for a newly initialized device.
// Note that the voucher may have entries if the server was configured for
// auto voucher extension.
func (s *State) NewVoucher(_ context.Context, ov *fdo.Voucher) error {
	s.Vouchers[ov.Header.Val.GUID] = ov
	return nil
}

// AddVoucher stores the voucher of a device owned by the service.
func (s *State) AddVoucher(_ context.Context, ov *fdo.Voucher) error {
	s.Vouchers[ov.Header.Val.GUID] = ov
	return nil
}

// ReplaceVoucher stores a new voucher, possibly deleting or marking the
// previous voucher as replaced.
func (s *State) ReplaceVoucher(_ context.Context, oldGUID protocol.GUID, ov *fdo.Voucher) error {
	delete(s.Vouchers, oldGUID)
	s.Vouchers[ov.Header.Val.GUID] = ov
	return nil
}

// RemoveVoucher untracks a voucher, possibly by deleting it or marking it
// as removed, and returns it for extension.
func (s *State) RemoveVoucher(ctx context.Context, guid protocol.GUID) (*fdo.Voucher, error) {
	ov, ok := s.Vouchers[guid]
	if !ok {
		return nil, fdo.ErrNotFound
	}
	delete(s.Vouchers, guid)
	return ov, nil
}

// Voucher retrieves a voucher by GUID.
func (s *State) Voucher(_ context.Context, guid protocol.GUID) (*fdo.Voucher, error) {
	ov, ok := s.Vouchers[guid]
	if !ok {
		return nil, fdo.ErrNotFound
	}
	return ov, nil
}

// OwnerKey returns the private key matching a given key type and optionally
// its certificate chain.
func (s *State) OwnerKey(keyType protocol.KeyType) (crypto.Signer, []*x509.Certificate, error) {
	key, ok := s.OwnerKeys[keyType]
	if !ok {
		return nil, nil, fdo.ErrNotFound
	}
	return key.Key, key.Chain, nil
}

// DelegateKey returns the private key matching a given key type and 
// its certificate chain.
func (s *State) DelegateKey(name string) (crypto.Signer, []*x509.Certificate, error) {
	key, ok := s.DelegateKeys[name]
	if !ok {
		return nil, nil, fdo.ErrNotFound
	}
	return key.Key, key.Chain, nil
}

// TODO: Make things easier by using the same key for each cert in the chain
func newDelegateChain(owner crypto.Signer) ([]*x509.Certificate, error) {
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Issuer:       pkix.Name{CommonName: "DelegateRoot"},
		Subject:      pkix.Name{CommonName: "DelegateRoot"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(30 * 360 * 24 * time.Hour),
		IsCA:         true,
                BasicConstraintsValid: true,
                KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
                UnknownExtKeyUsage:    []asn1.ObjectIdentifier{fdo.OID_delegateOnboard, fdo.OID_delegateRedirect},
	}
	der, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, owner.Public(), owner)
	rootCert, err := x509.ParseCertificate(der)

	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "DelegateIntermediate"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(30 * 360 * 24 * time.Hour),
		IsCA:         true,
                BasicConstraintsValid: true,
                KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
                UnknownExtKeyUsage:    []asn1.ObjectIdentifier{fdo.OID_delegateOnboard, fdo.OID_delegateRedirect},
	}
	der, err = x509.CreateCertificate(rand.Reader, intermediateTemplate, rootTemplate, owner.Public(), owner)
	intermediateCert, err := x509.ParseCertificate(der)

	delegateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "DelegateCert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(30 * 360 * 24 * time.Hour),
		
                BasicConstraintsValid: true,
		KeyUsage:     x509.KeyUsageDigitalSignature,
                UnknownExtKeyUsage:    []asn1.ObjectIdentifier{fdo.OID_delegateOnboard, fdo.OID_delegateRedirect},
	}
	der, err = x509.CreateCertificate(rand.Reader, delegateTemplate, intermediateTemplate, owner.Public(), owner)
	delegateCert, err := x509.ParseCertificate(der)
	return []*x509.Certificate{delegateCert,intermediateCert,rootCert}, err
}
func newCA(priv crypto.Signer) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Issuer:       pkix.Name{CommonName: "CA"},
		Subject:      pkix.Name{CommonName: "CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(30 * 360 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// ManufacturerKey returns the signer of a given key type.
func (s *State) ManufacturerKey(keyType protocol.KeyType) (crypto.Signer, []*x509.Certificate, error) {
	return s.OwnerKey(keyType)
}

// SetRVBlob sets the owner rendezvous blob for a device.
func (s *State) SetRVBlob(ctx context.Context, ov *fdo.Voucher, to1d *cose.Sign1[protocol.To1d, []byte], exp time.Time) error {
	// TODO: Handle expiration
	s.RVBlobs[ov.Header.Val.GUID] = to1d
	s.Vouchers[ov.Header.Val.GUID] = ov
	return nil
}

// RVBlob returns the owner rendezvous blob for a device.
func (s *State) RVBlob(ctx context.Context, guid protocol.GUID) (*cose.Sign1[protocol.To1d, []byte], *fdo.Voucher, error) {
	to1d, ok := s.RVBlobs[guid]
	if !ok {
		return nil, nil, fdo.ErrNotFound
	}
	ov, ok := s.Vouchers[guid]
	if !ok {
		return nil, nil, fdo.ErrNotFound
	}
	return to1d, ov, nil
}
