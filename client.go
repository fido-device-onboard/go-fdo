// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"
	"crypto/sha512"
	"fmt"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// Client implements methods for performing FDO protocols DI (non-normative),
// TO1, and TO2.
type Client struct {
	// Transport performs message passing and may be implemented over TCP,
	// HTTP, CoAP, and others.
	Transport Transport

	// GUID of the device credential currently in use.
	GUID GUID

	// HMAC secret of the device credential currently in use.
	Hmac KeyedHasher

	// Private key of the device credential currently in use.
	Key crypto.Signer

	// When true and an RSA key is used as a crypto.Signer argument, RSA-SSAPSS
	// will be used for signing.
	PSS bool

	// ServiceInfoModulesForOwner returns a map of registered FDO Service Info
	// Modules (FSIMs) for a given Owner Service.
	ServiceInfoModulesForOwner func(RvTO2Addr) map[string]ServiceInfoModule
}

// DeviceInitialize runs the DI protocol and returns the voucher header and
// manufacturer public key hash.
//
// The device is identified to the manufacturing component by the ID string,
// which may be a device serial, MAC address, or similar. There is generally an
// expectation of network trust for DI.
//
// The device certificate chain should be created before DI is performed,
// because the manufacturing component signs the ownership voucher, but isn't
// necessarily the root of trust for the device's identity and may or may not
// validate the device's presented certificate chain.
//
// However, the [Java server] implementation expects a certificate signing
// request marshaled in the device info and performs certificate signing, so
// PKI and voucher signing duties may be simultaneously handled by the
// manufacturing component.
//
// [Java server]: https://github.com/fido-device-onboard/pri-fidoiot
func (c *Client) DeviceInitialize(ctx context.Context, baseURL string, info any) (*DeviceCredential, error) {
	ovh, err := c.appStart(ctx, baseURL, info)
	if err != nil {
		return nil, err
	}

	// Hash initial owner public key
	ownerKeyDigest := sha512.New384()
	if err := cbor.NewEncoder(ownerKeyDigest).Encode(ovh.ManufacturerKey); err != nil {
		return nil, fmt.Errorf("error computing hash of initial owner (manufacturer) key: %w", err)
	}
	ownerKeyHash := Hash{Algorithm: Sha384Hash, Value: ownerKeyDigest.Sum(nil)[:]}

	if err := c.setHmac(ctx, baseURL, ovh); err != nil {
		return nil, err
	}

	return &DeviceCredential{
		Version:       ovh.Version,
		DeviceInfo:    ovh.DeviceInfo,
		GUID:          ovh.GUID,
		RvInfo:        ovh.RvInfo,
		PublicKeyHash: ownerKeyHash,
	}, nil
}

// TransferOwnership1 runs the TO1 protocol and returns the owner service (TO2)
// addresses.
func (c *Client) TransferOwnership1(ctx context.Context, baseURL string) ([]RvTO2Addr, error) {
	nonce, err := c.helloRv(ctx, baseURL)
	if err != nil {
		return nil, err
	}

	return c.proveToRv(ctx, baseURL, nonce)
}

// TransferOwnership2 runs the TO2 protocol and returns replacement GUID,
// rendezvous info, and owner public key.
//
// It has the side effect of performing FSIMs, which may include actions such
// as downloading files.
func (c *Client) TransferOwnership2(ctx context.Context, baseURL, deviceInfo string, certChainHash Hash) (*DeviceCredential, error) {
	nonce, err := c.verifyOwner(ctx)
	if err != nil {
		return nil, err
	}

	replaceGUID, replaceRVInfo, replaceOwnerKey, err := c.proveDevice(ctx, nonce)
	if err != nil {
		return nil, err
	}

	// Hash new initial owner public key
	replaceKeyDigest := sha512.New384()
	if err := cbor.NewEncoder(replaceKeyDigest).Encode(replaceOwnerKey); err != nil {
		return nil, fmt.Errorf("error computing hash of replacement owner key: %w", err)
	}
	replaceKeyHash := Hash{Algorithm: Sha384Hash, Value: replaceKeyDigest.Sum(nil)[:]}

	// Calculate the new OVH HMac similar to DI.SetHMAC
	replaceHmac, err := c.Hmac.Hmac(HmacSha384Hash, VoucherHeader{
		Version:         101,
		GUID:            replaceGUID,
		RvInfo:          replaceRVInfo,
		DeviceInfo:      deviceInfo,
		ManufacturerKey: replaceOwnerKey,
		CertChainHash:   &certChainHash,
	})
	if err != nil {
		return nil, fmt.Errorf("error computing HMAC of ownership voucher header: %w", err)
	}

	if err := c.exchangeServiceInfo(ctx, replaceHmac); err != nil {
		return nil, err
	}

	return &DeviceCredential{
		Version:       101,
		DeviceInfo:    deviceInfo,
		GUID:          replaceGUID,
		RvInfo:        replaceRVInfo,
		PublicKeyHash: replaceKeyHash,
	}, nil
}
