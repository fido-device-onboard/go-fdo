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
	"fmt"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

// State implements interfaces for state which must be persisted between
// protocol sessions, but not between server processes.
type State struct {
	RVBlobs    map[fdo.GUID]*cose.Sign1[fdo.To1d, []byte]
	Vouchers   map[fdo.GUID]*fdo.Voucher
	OwnerKeys  map[fdo.KeyType]crypto.Signer
	AutoExtend interface {
		ExtendVoucher(*fdo.Voucher, crypto.PublicKey) (*fdo.Voucher, error)
	}
	AutoRegisterRV           *fdo.To1d
	PreserveReplacedVouchers bool
}

var _ fdo.RendezvousBlobPersistentState = (*State)(nil)
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
		RVBlobs:  make(map[fdo.GUID]*cose.Sign1[fdo.To1d, []byte]),
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

		if s.AutoRegisterRV != nil {
			keyType := ov.Header.Val.ManufacturerKey.Type
			key, ok := s.OwnerKeys[keyType]
			if !ok {
				return fmt.Errorf("auto register RV blob: no owner key of type %s", keyType)
			}
			var opts crypto.SignerOpts
			switch keyType {
			case fdo.Rsa2048RestrKeyType, fdo.RsaPkcsKeyType, fdo.RsaPssKeyType:
				switch rsaPub := key.Public().(*rsa.PublicKey); rsaPub.Size() {
				case 2048 / 8:
					opts = crypto.SHA256
				case 3072 / 8:
					opts = crypto.SHA384
				default:
					return fmt.Errorf("unsupported RSA key size: %d bits", rsaPub.Size()*8)
				}

				if keyType == fdo.RsaPssKeyType {
					opts = &rsa.PSSOptions{
						SaltLength: rsa.PSSSaltLengthEqualsHash,
						Hash:       opts.(crypto.Hash),
					}
				}
			}

			sign1 := cose.Sign1[fdo.To1d, []byte]{
				Payload: cbor.NewByteWrap(*s.AutoRegisterRV),
			}
			if err := sign1.Sign(key, nil, nil, opts); err != nil {
				return fmt.Errorf("auto register RV blob: %w", err)
			}
			s.RVBlobs[ov.Header.Val.GUID] = &sign1
		}
	}
	s.Vouchers[ov.Header.Val.GUID] = ov
	return nil
}

// ReplaceVoucher stores a new voucher, possibly deleting or marking the
// previous voucher as replaced.
func (s *State) ReplaceVoucher(_ context.Context, oldGUID fdo.GUID, ov *fdo.Voucher) error {
	if !s.PreserveReplacedVouchers {
		delete(s.Vouchers, oldGUID)
	}
	s.Vouchers[ov.Header.Val.GUID] = ov
	return nil
}

// Voucher retrieves a voucher by GUID.
func (s *State) Voucher(_ context.Context, guid fdo.GUID) (*fdo.Voucher, error) {
	ov, ok := s.Vouchers[guid]
	if !ok {
		return nil, fdo.ErrNotFound
	}
	return ov, nil
}

// Signer returns the private key matching a given key type.
func (s *State) Signer(keyType fdo.KeyType) (crypto.Signer, bool) {
	key, ok := s.OwnerKeys[keyType]
	return key, ok
}

// SetRVBlob sets the owner rendezvous blob for a device.
func (s *State) SetRVBlob(ctx context.Context, guid fdo.GUID, to1d *cose.Sign1[fdo.To1d, []byte]) error {
	s.RVBlobs[guid] = to1d
	return nil
}

// RVBlob returns the owner rendezvous blob for a device.
func (s *State) RVBlob(ctx context.Context, guid fdo.GUID) (*cose.Sign1[fdo.To1d, []byte], error) {
	to1d, ok := s.RVBlobs[guid]
	if !ok {
		return nil, fdo.ErrNotFound
	}
	return to1d, nil
}
