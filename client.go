// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/plugin"
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
	//
	// Alternatively to setting this field, a devmod module may be provided in
	// the arguments to TransferOwnership2 where the module must provide any
	// devmod messages EXCEPT nummodules and modules via its Yield method.
	//
	// Note: The device plugin will be yielded to exactly once and is expected
	// to provide all required and desired fields and yield. It may then exit.
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
	alg := Sha384Hash
	ownerKeyDigest := alg.HashFunc().New()
	if err := cbor.NewEncoder(ownerKeyDigest).Encode(ovh.ManufacturerKey); err != nil {
		err = fmt.Errorf("error computing hash of initial owner (manufacturer) key: %w", err)
		c.errorMsg(ctx, baseURL, err)
		return nil, err
	}
	ownerKeyHash := Hash{Algorithm: alg, Value: ownerKeyDigest.Sum(nil)[:]}

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
// It has the side effect of performing service info modules, which may include
// actions such as downloading files.
func (c *Client) TransferOwnership2(ctx context.Context, baseURL string, to1d *cose.Sign1[To1d, []byte], deviceModules map[string]serviceinfo.DeviceModule) (*DeviceCredential, error) {
	ctx = contextWithErrMsg(ctx)

	// Client configuration defaults
	if c.KeyExchange == "" {
		c.KeyExchange = kex.ECDH384Suite
	}
	if c.CipherSuite == 0 {
		c.CipherSuite = kex.A256GcmCipher
	}
	if c.MaxServiceInfoSizeReceive == 0 {
		c.MaxServiceInfoSizeReceive = serviceinfo.DefaultMTU
	}
	if deviceModules == nil {
		deviceModules = make(map[string]serviceinfo.DeviceModule)
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

	// Select the appropriate hash algorithm
	ownerPubKey, _ := partialOVH.ManufacturerKey.Public()
	alg, err := hashAlgFor(c.Key.Public(), ownerPubKey)
	if err != nil {
		return nil, fmt.Errorf("error selecting the appropriate hash algorithm: %w", err)
	}

	// Prepare to send and receive service info, determining the transmit MTU
	sendMTU, err := c.readyServiceInfo(ctx, baseURL, alg, replacementOVH, session)
	if err != nil {
		c.errorMsg(ctx, baseURL, err)
		return nil, err
	}

	// Start synchronously writing the initial device service info. This occurs
	// in a goroutine because the pipe is unbuffered and needs to be
	// concurrently read by the send/receive service info loop.
	serviceInfoReader, serviceInfoWriter := serviceinfo.NewChunkOutPipe(0)
	defer func() { _ = serviceInfoWriter.Close() }()

	// Send devmod KVs in initial ServiceInfo
	go c.Devmod.Write(ctx, deviceModules, sendMTU, serviceInfoWriter)

	// Loop, sending and receiving service info until done
	defer c.stopPlugins(deviceModules)
	if err := c.exchangeServiceInfo(ctx, baseURL, proveDeviceNonce, setupDeviceNonce, sendMTU, serviceInfoReader, deviceModules, session); err != nil {
		c.errorMsg(ctx, baseURL, err)
		return nil, err
	}

	// Hash new initial owner public key and return replacement device
	// credential
	replacementKeyDigest := alg.HashFunc().New()
	if err := cbor.NewEncoder(replacementKeyDigest).Encode(replacementOVH.ManufacturerKey); err != nil {
		err = fmt.Errorf("error computing hash of replacement owner key: %w", err)
		c.errorMsg(ctx, baseURL, err)
		return nil, err
	}
	replacementPublicKeyHash := Hash{Algorithm: alg, Value: replacementKeyDigest.Sum(nil)[:]}

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
	if errMsg.Timestamp == 0 {
		errMsg.Timestamp = time.Now().Unix()
	}

	// Create a new context, because the previous one may have expired, thus
	// causing the protocol failure
	//
	// TODO: Make timeout configurable
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Send error, but ignore the response, only making sure to close the
	// reader if one is returned
	_, rc, err := c.Transport.Send(ctx, baseURL, ErrorMsgType, errMsg, nil)
	if err == nil && rc != nil {
		_ = rc.Close()
	}
}

// Stop any plugin device modules
func (c *Client) stopPlugins(deviceModules map[string]serviceinfo.DeviceModule) {
	// TODO: Make timeout configurable?
	pluginStopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var pluginStopWg sync.WaitGroup
	for _, mod := range deviceModules {
		if p, ok := mod.(plugin.Module); ok {
			pluginStopWg.Add(1)
			pluginGracefulStopCtx, done := context.WithCancel(pluginStopCtx)

			// Allow Graceful stop up to the original shared timeout
			go func(p plugin.Module) {
				defer done()
				if err := p.GracefulStop(pluginGracefulStopCtx); err != nil && !errors.Is(err, context.Canceled) { //nolint:revive,staticcheck
					// TODO: Write to error log
				}
			}(p)

			// Force stop after the shared timeout expires or graceful stop
			// completes
			go func(p plugin.Module) {
				<-pluginGracefulStopCtx.Done()
				_ = p.Stop()
				pluginStopWg.Done()
			}(p)
		}
	}
	pluginStopWg.Wait()
}
