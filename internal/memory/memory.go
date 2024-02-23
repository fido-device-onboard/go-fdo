// Copyright 2023 Intel Corporation
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
	"fmt"

	"github.com/fido-device-onboard/go-fdo"
)

// State implements interfaces for state which must be persisted between
// protocol sessions, but not between server processes.
type State struct {
	Vouchers   map[fdo.GUID]*fdo.Voucher
	OwnerKeys  map[fdo.KeyType]crypto.Signer
	AutoExtend interface {
		ExtendVoucher(*fdo.Voucher, crypto.PublicKey) (*fdo.Voucher, error)
	}
}

var _ fdo.VoucherPersistentState = (*State)(nil)
var _ fdo.OwnerKeyPersistentState = (*State)(nil)

// NewState initializes the in-memory state.
func NewState() (*State, error) {
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
	return &State{
		Vouchers: make(map[fdo.GUID]*fdo.Voucher),
		OwnerKeys: map[fdo.KeyType]crypto.Signer{
			fdo.Rsa2048RestrKeyType: rsaKey,
			fdo.RsaPkcsKeyType:      rsaKey,
			fdo.RsaPssKeyType:       rsaKey,
			fdo.Secp256r1KeyType:    ec256Key,
			fdo.Secp384r1KeyType:    ec384Key,
		},
	}, nil
}

// NewVoucher creates and stores a new voucher.
func (s *State) NewVoucher(_ context.Context, ov *fdo.Voucher) error {
	if s.AutoExtend != nil {
		keyType := ov.Header.Val.ManufacturerKey.Type
		key, ok := s.OwnerKeys[keyType]
		if !ok {
			return fmt.Errorf("auto extend: no owner key of type %s", keyType)
		}
		ex, err := s.AutoExtend.ExtendVoucher(ov, key.Public())
		if err != nil {
			return err
		}
		ov = ex
	}
	s.Vouchers[ov.Header.Val.GUID] = ov
	return nil
}

// Voucher retrieves a voucher by GUID.
func (s *State) Voucher(_ context.Context, guid fdo.GUID) (*fdo.Voucher, error) {
	ov, ok := s.Vouchers[guid]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return ov, nil
}

// Signer returns the private key matching a given key type.
func (s *State) Signer(keyType fdo.KeyType) (crypto.Signer, bool) {
	key, ok := s.OwnerKeys[keyType]
	return key, ok
}
