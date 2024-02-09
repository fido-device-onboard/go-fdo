// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"
	"crypto/sha512"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// Client implements methods for performing FDO protocols DI (non-normative),
// TO1, and TO2.
type Client struct {
	// Transport performs message passing and may be implemented over TCP,
	// HTTP, CoAP, and others
	Transport Transport

	// DeviceCredential currently in use
	Cred DeviceCredential

	// HMAC secret of the device credential currently in use
	Hmac KeyedHasher

	// Private key of the device credential currently in use
	Key crypto.Signer

	// When true and an RSA key is used as a crypto.Signer argument, RSA-SSAPSS
	// will be used for signing
	PSS bool

	// Devmod contains all required and any number of optional messages.
	Devmod Devmod

	// Key exchange options, default to the strongest implemented for the Owner
	// Key type
	KeyExchange kex.Suite
	CipherSuite kex.CipherSuiteID

	// Maximum transmission unit (MTU) to tell owner service to send with. If
	// zero, the default of 1300 will be used. The value chosen can make a
	// difference for performance when using service info to exchange large
	// amounts of data, but choosing the best value depends on network
	// configuration (e.g. jumbo packets) and transport (overhead size).
	MaxServiceInfoSizeReceive uint16
}

// DeviceInitialize runs the DI protocol and returns the voucher header and
// manufacturer public key hash. It requires that the client is configured with
// an HMAC secret, but not necessarily a key.
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
	ctx = contextWithErrMsg(ctx)

	ovh, err := c.appStart(ctx, baseURL, info)
	if err != nil {
		c.errorMsg(ctx, baseURL, err)
		return nil, err
	}

	// Hash initial owner public key
	ownerKeyDigest := sha512.New384()
	if err := cbor.NewEncoder(ownerKeyDigest).Encode(ovh.ManufacturerKey); err != nil {
		err = fmt.Errorf("error computing hash of initial owner (manufacturer) key: %w", err)
		c.errorMsg(ctx, baseURL, err)
		return nil, err
	}
	ownerKeyHash := Hash{Algorithm: Sha384Hash, Value: ownerKeyDigest.Sum(nil)[:]}

	if err := c.setHmac(ctx, baseURL, ovh); err != nil {
		c.errorMsg(ctx, baseURL, err)
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
// addresses. It requires that a device credential, hmac secret, and key are
// all configured on the client.
func (c *Client) TransferOwnership1(ctx context.Context, baseURL string) (*cose.Sign1[To1d, []byte], error) {
	ctx = contextWithErrMsg(ctx)

	nonce, err := c.helloRv(ctx, baseURL)
	if err != nil {
		c.errorMsg(ctx, baseURL, err)
		return nil, err
	}

	blob, err := c.proveToRv(ctx, baseURL, nonce)
	if err != nil {
		c.errorMsg(ctx, baseURL, err)
		return nil, err
	}

	return blob, nil
}

// TransferOwnership2 runs the TO2 protocol and returns a DeviceCredential with
// replaced GUID, rendezvous info, and owner public key. It requires that a
// device credential, hmac secret, and key are all configured on the client.
//
// It has the side effect of performing FSIMs, which may include actions such
// as downloading files.
func (c *Client) TransferOwnership2(ctx context.Context, baseURL string, to1d *cose.Sign1[To1d, []byte], fsims map[string]serviceinfo.Module) (*DeviceCredential, error) {
	ctx = contextWithErrMsg(ctx)

	// Client configuraiton defaults
	if c.KeyExchange == "" {
		c.KeyExchange = kex.ECDH384Suite
	}
	if c.CipherSuite == 0 {
		c.CipherSuite = kex.A256GcmCipher
	}
	if c.MaxServiceInfoSizeReceive == 0 {
		c.MaxServiceInfoSizeReceive = serviceinfo.DefaultMTU
	}

	// TODO: Validate key exchange options using table in 3.6.5

	// Mutually attest the device and owner service
	//
	// Results: Replacement ownership voucher, nonces to be retransmitted in
	// Done/Done2 messages
	proveDeviceNonce, originalOVH, session, err := c.verifyOwner(ctx, baseURL, to1d)
	if err != nil {
		c.errorMsg(ctx, baseURL, err)
		return nil, err
	}
	setupDeviceNonce, partialOVH, err := c.proveDevice(ctx, baseURL, proveDeviceNonce, session)
	if err != nil {
		c.errorMsg(ctx, baseURL, err)
		return nil, err
	}
	replacementOVH := &VoucherHeader{
		Version:         originalOVH.Version,
		GUID:            partialOVH.GUID,
		RvInfo:          partialOVH.RvInfo,
		DeviceInfo:      originalOVH.DeviceInfo,
		ManufacturerKey: partialOVH.ManufacturerKey,
		CertChainHash:   originalOVH.CertChainHash,
	}

	// Prepare to send and receive service info, determining the transmit MTU
	sendMTU, err := c.readyServiceInfo(ctx, baseURL, replacementOVH, session)
	if err != nil {
		c.errorMsg(ctx, baseURL, err)
		return nil, err
	}

	// Start synchronously writing the initial device service info. This occurs
	// in a goroutine because the pipe is unbuffered and needs to be
	// concurrently read by the send/receive service info loop.
	serviceInfoReader, serviceInfoWriter := serviceinfo.NewChunkOutPipe()
	defer func() { _ = serviceInfoWriter.Close() }()

	// Ensure that FSIMs include devmod at a minimum
	if fsims == nil {
		fsims = make(map[string]serviceinfo.Module)
	}
	if fsims[devmodModuleName] == nil {
		fsims[devmodModuleName] = serviceinfo.Handler(
			func(context.Context, string, io.Reader, func(string, string) io.Writer) error {
				// Empty handler to cause active=true to be sent and to include
				// devmod in the modules list
				return nil
			},
		)
	}

	// Send devmod KVs in initial ServiceInfo
	var modules []string
	for key := range fsims {
		module, _, _ := strings.Cut(key, ":")
		modules = append(modules, module)
	}
	go c.Devmod.Write(modules, sendMTU, serviceInfoWriter)

	// Loop, sending and receiving service info until done
	if err := c.exchangeServiceInfo(ctx, baseURL, proveDeviceNonce, setupDeviceNonce, sendMTU, serviceInfoReader, fsims, session); err != nil {
		c.errorMsg(ctx, baseURL, err)
		return nil, err
	}

	// Hash new initial owner public key and return replacement device
	// credential
	replacementKeyDigest := sha512.New384()
	if err := cbor.NewEncoder(replacementKeyDigest).Encode(replacementOVH.ManufacturerKey); err != nil {
		err = fmt.Errorf("error computing hash of replacement owner key: %w", err)
		c.errorMsg(ctx, baseURL, err)
		return nil, err
	}
	replacementPublicKeyHash := Hash{Algorithm: Sha384Hash, Value: replacementKeyDigest.Sum(nil)[:]}

	return &DeviceCredential{
		Version:       replacementOVH.Version,
		DeviceInfo:    replacementOVH.DeviceInfo,
		GUID:          replacementOVH.GUID,
		RvInfo:        replacementOVH.RvInfo,
		PublicKeyHash: replacementPublicKeyHash,
	}, nil
}

func (c *Client) errorMsg(ctx context.Context, baseURL string, err error) {
	// If no previous message, then exit, because the protocol hasn't started
	errMsg := errMsgFromContext(ctx)
	if errMsg.PrevMsgType == 0 {
		return
	}

	// Default to error code 500, error message of err parameter, and timestamp
	// of the current time
	if errMsg.Code == 0 {
		errMsg.Code = internalServerErrCode
	}
	if errMsg.ErrString == "" {
		errMsg.ErrString = err.Error()
	}
	/*
		if errMsg.Timestamp == (Timestamp{}) {
			errMsg.Timestamp = Timestamp(time.Now())
		}
	*/

	// Create a new context, because the previous one may have expired, thus
	// causing the protocol failure
	//
	// TODO: Make timeout configurable
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Send error, but ignore the response, only making sure to close the
	// reader if one is returned
	_, rc, err := c.Transport.Send(ctx, baseURL, ErrorMsgType, errMsg, nil)
	if err == nil {
		_ = rc.Close()
	}
}
