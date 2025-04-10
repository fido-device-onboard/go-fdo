// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// AllInOne is a construct with functionality that is only possible when
// different FDO services are combined.
type AllInOne struct {
	// A combination DI and Owner service can auto-extend vouchers for itself.
	DIAndOwner interface {
		// ManufacturerKey returns the signer of a given key type and its
		// certificate chain (required). If key type is not RSAPKCS or RSAPSS
		// then rsaBits is ignored. Otherwise it must be either 2048 or 3072.
		ManufacturerKey(ctx context.Context, keyType protocol.KeyType, rsaBits int) (crypto.Signer, []*x509.Certificate, error)

		// OwnerKey returns the private key matching a given key type and
		// optionally its certificate chain. If key type is not RSAPKCS or
		// RSAPSS then rsaBits is ignored. Otherwise it must be either 2048 or
		// 3072.
		OwnerKey(ctx context.Context, keyType protocol.KeyType, rsaBits int) (crypto.Signer, []*x509.Certificate, error)
	}

	// A combination Rendezvous and Owner service can auto-register devices for
	// rendezvous
	RendezvousAndOwner interface {
		// SetRVBlob sets the owner rendezvous blob for a device.
		SetRVBlob(context.Context, *Voucher, *cose.Sign1[protocol.To1d, []byte], time.Time) error

		// OwnerKey returns the private key matching a given key type and
		// optionally its certificate chain. If key type is not RSAPKCS or
		// RSAPSS then rsaBits is ignored. Otherwise it must be either 2048 or
		// 3072.
		OwnerKey(ctx context.Context, keyType protocol.KeyType, rsaBits int) (crypto.Signer, []*x509.Certificate, error)

		// OwnerAddrs are the owner service addresses to register with the
		// rendezvous service and the expiration duration. If the duration is
		// zero, then a default of 30 years will be used.
		OwnerAddrs(context.Context, Voucher) ([]protocol.RvTO2Addr, time.Duration, error)
	}
}

// Extend a voucher and replace the value pointed to with the newly extended
// voucher.
//
// This function is meant to be used as a callback in DIServer.
func (aio AllInOne) Extend(ctx context.Context, ov *Voucher) error {
	if aio.DIAndOwner == nil {
		panic("DIAndOwner must be set")
	}

	mfgKey := ov.Header.Val.ManufacturerKey
	keyType, rsaBits := mfgKey.Type, mfgKey.RsaBits()
	owner, _, err := aio.DIAndOwner.ManufacturerKey(ctx, keyType, rsaBits)
	if err != nil {
		return fmt.Errorf("auto extend: error getting %s manufacturer key: %w", keyType, err)
	}
	nextOwner, _, err := aio.DIAndOwner.OwnerKey(ctx, keyType, rsaBits)
	if err != nil {
		return fmt.Errorf("auto extend: error getting %s owner key: %w", keyType, err)
	}
	switch owner.Public().(type) {
	case *ecdsa.PublicKey:
		nextOwner, ok := nextOwner.Public().(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("auto extend: owner key must be %s", keyType)
		}
		extended, err := ExtendVoucher(ov, owner, nextOwner, nil)
		if err != nil {
			return err
		}
		*ov = *extended
		return nil

	case *rsa.PublicKey:
		nextOwner, ok := nextOwner.Public().(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("auto extend: owner key must be %s", keyType)
		}
		extended, err := ExtendVoucher(ov, owner, nextOwner, nil)
		if err != nil {
			return err
		}
		*ov = *extended
		return nil

	default:
		return fmt.Errorf("auto extend: invalid key type %T", owner)
	}
}

// RegisterOwnerAddr sets the owner service address for the device to discover
// in TO1.
//
// This function is meant to be used as a callback in DIServer.
func (aio AllInOne) RegisterOwnerAddr(ctx context.Context, ov Voucher) error {
	if aio.RendezvousAndOwner == nil {
		panic("RendezvousAndOwner must be set")
	}

	mfgKey := ov.Header.Val.ManufacturerKey
	keyType, rsaBits := mfgKey.Type, mfgKey.RsaBits()
	nextOwner, _, err := aio.RendezvousAndOwner.OwnerKey(ctx, keyType, rsaBits)
	if err != nil {
		return fmt.Errorf("auto-to0: error getting %s owner key: %w", keyType, err)
	}

	var opts crypto.SignerOpts
	switch keyType {
	case protocol.Rsa2048RestrKeyType, protocol.RsaPkcsKeyType, protocol.RsaPssKeyType:
		switch rsaPub := nextOwner.Public().(*rsa.PublicKey); rsaPub.Size() {
		case 2048 / 8:
			opts = crypto.SHA256
		case 3072 / 8:
			opts = crypto.SHA384
		default:
			return fmt.Errorf("auto-to0: unsupported RSA key size: %d bits", rsaPub.Size()*8)
		}

		if keyType == protocol.RsaPssKeyType {
			opts = &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       opts.(crypto.Hash),
			}
		}
	}

	ownerAddrs, expDur, err := aio.RendezvousAndOwner.OwnerAddrs(ctx, ov)
	if err != nil {
		return fmt.Errorf("auto-to0: error getting owner service address(es): %w", err)
	}
	sign1 := cose.Sign1[protocol.To1d, []byte]{
		Payload: cbor.NewByteWrap(protocol.To1d{
			RV: ownerAddrs,
			To0dHash: protocol.Hash{
				Algorithm: protocol.Sha256Hash,
				Value:     make([]byte, 32),
			},
		}),
	}
	if err := sign1.Sign(nextOwner, nil, nil, opts); err != nil {
		return fmt.Errorf("auto-to0: error signing to1d: %w", err)
	}

	// Default to expiring in 30 years
	exp := time.Now().Add(expDur)
	if expDur <= 0 {
		exp = exp.AddDate(30, 0, 0)
	}
	if err := aio.RendezvousAndOwner.SetRVBlob(ctx, &ov, &sign1, exp); err != nil {
		return fmt.Errorf("auto-to0: error storing to1d: %w", err)
	}

	return nil
}
