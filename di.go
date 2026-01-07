// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"
	"crypto/rand"
	"fmt"
	"hash"
	"io"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// DIConfig contains required device secrets and optional configuration.
type DIConfig struct {
	// HMAC-SHA256 with a device secret that does not change when ownership is
	// transferred. HMAC-SHA256 support is always required by spec, so this
	// field must be non-nil.
	//
	// This hash.Hash may optionally implement the following interface to
	// return errors from Reset/Write/Sum, noting that implementations of
	// hash.Hash are not supposed to return non-nil errors from Write.
	//
	// 	type FallibleHash interface {
	// 		Err() error
	// 	}
	HmacSha256 hash.Hash

	// HMAC-SHA384 with a device secret that does not change when ownership is
	// transferred. HMAC-SHA384 support is optional by spec, so this field may
	// be nil iff Key is RSA 2048 or EC P-256.
	//
	// This hash.Hash may optionally implement the following interface to
	// return errors from Reset/Write/Sum, noting that implementations of
	// hash.Hash are not supposed to return non-nil errors from Write.
	//
	// 	type FallibleHash interface {
	// 		Err() error
	// 	}
	HmacSha384 hash.Hash

	// An ECDSA or RSA private key
	Key crypto.Signer

	// When true and an RSA key is used as a crypto.Signer argument, RSA-SSAPSS
	// will be used for signing
	PSS bool
}

// DI runs the DI protocol and returns the voucher header and manufacturer
// public key hash. It requires that the client is configured with an HMAC
// secret, but not necessarily a key.
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
func DI(ctx context.Context, transport Transport, info any, c DIConfig) (*DeviceCredential, error) {
	ctx = contextWithErrMsg(ctx)

	ovh, err := appStart(ctx, transport, info)
	if err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}

	// Select the appropriate hash algorithm
	ownerPubKey, err := ovh.ManufacturerKey.Public()
	if err != nil {
		return nil, fmt.Errorf("error parsing manufacturer public key type from received ownership voucher header: %w", err)
	}
	alg, err := hashAlgFor(c.Key.Public(), ownerPubKey)
	if err != nil {
		return nil, fmt.Errorf("error selecting the appropriate hash algorithm: %w", err)
	}

	// Hash initial owner public key
	ownerKeyDigest := alg.HashFunc().New()
	if err := cbor.NewEncoder(ownerKeyDigest).Encode(ovh.ManufacturerKey); err != nil {
		err = fmt.Errorf("error computing hash of initial owner (manufacturer) key: %w", err)
		errorMsg(ctx, transport, err)
		return nil, err
	}
	ownerKeyHash := protocol.Hash{Algorithm: alg, Value: ownerKeyDigest.Sum(nil)[:]}

	var hmac hash.Hash
	switch alg {
	case protocol.Sha256Hash:
		hmac = c.HmacSha256
	case protocol.Sha384Hash:
		hmac = c.HmacSha384
	}
	if err := setHmac(ctx, transport, hmac, ovh); err != nil {
		errorMsg(ctx, transport, err)
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

// AppStart(10) -> SetCredentials(11)
func appStart(ctx context.Context, transport Transport, info any) (*VoucherHeader, error) {
	// Define request structure
	var msg struct {
		DeviceMfgInfo *cbor.Bstr[any]
		CapabilityFlags
	}
	if info != nil {
		msg.DeviceMfgInfo = cbor.NewBstr(info)
	}
	msg.CapabilityFlags = GlobalCapabilityFlags


	// Make request
	typ, resp, err := transport.Send(ctx, protocol.DIAppStartMsgType, msg, nil)
	if err != nil {
		return nil, fmt.Errorf("DI.AppStart: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case protocol.DISetCredentialsMsgType:
		captureMsgType(ctx, typ)
		var setCredentials setCredentialsMsg
		if err := cbor.NewDecoder(resp).Decode(&setCredentials); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return nil, fmt.Errorf("error parsing DI.SetCredentials request: %w", err)
		}
		return &setCredentials.OVHeader.Val, nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return nil, fmt.Errorf("error parsing error message contents of DI.AppStart response: %w", err)
		}
		return nil, fmt.Errorf("error received from DI.AppStart request: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		return nil, fmt.Errorf("unexpected message type for response to DI.AppStart: %d", typ)
	}
}

type setCredentialsMsg struct {
	OVHeader cbor.Bstr[VoucherHeader]
}

// AppStart(10) -> SetCredentials(11)
func (s *DIServer[T]) setCredentials(ctx context.Context, msg io.Reader) (*setCredentialsMsg, error) {
	// Decode proprietary device mfg info from app start
	var appStart struct {
		Info *cbor.Bstr[T]
		CapabilityFlags
	}
	if err := cbor.NewDecoder(msg).Decode(&appStart); err != nil {
		return nil, fmt.Errorf("error decoding device manufacturing info: %w", err)
	}
	var info *T // Null info is valid
	if appStart.Info != nil {
		info = &appStart.Info.Val
	}

	// Create and store a new device certificate chain
	chain, err := s.SignDeviceCertificate(info)
	if err != nil {
		return nil, fmt.Errorf("error creating device certificate chain: %w", err)
	}
	if err := s.Session.SetDeviceCertChain(ctx, chain); err != nil {
		return nil, fmt.Errorf("error storing device certificate chain: %w", err)
	}

	// If supported by the storage implementation, also store device reported
	// info
	if deviceSelfInfoStore, ok := s.Session.(interface {
		SetDeviceSelfInfo(context.Context, *T) error
	}); ok {
		if err := deviceSelfInfoStore.SetDeviceSelfInfo(ctx, info); err != nil {
			return nil, fmt.Errorf("error storing device info: %w", err)
		}
	}

	// Get device info string and key info
	deviceInfo, mfgPubKey, err := s.DeviceInfo(ctx, info, chain)
	if err != nil {
		return nil, fmt.Errorf("error getting device info: %w", err)
	}
	ownerPubKey, err := mfgPubKey.Public()
	if err != nil {
		return nil, fmt.Errorf("error getting manufacturer public key: %w", err)
	}

	// Compute the appropriate cert chain hash
	alg, err := hashAlgFor(chain[0].PublicKey, ownerPubKey)
	if err != nil {
		return nil, fmt.Errorf("error determining appropriate device cert chain hash algorithm: %w", err)
	}
	certChain := make([]*cbor.X509Certificate, len(chain))
	certChainHash := alg.HashFunc().New()
	for i, cert := range chain {
		certChain[i] = (*cbor.X509Certificate)(cert)
		_, _ = certChainHash.Write(cert.Raw)
	}

	// Generate voucher header
	var guid protocol.GUID
	if _, err := rand.Read(guid[:]); err != nil {
		return nil, fmt.Errorf("error generating device GUID: %w", err)
	}
	ovh := &VoucherHeader{
		Version:         101,
		GUID:            guid,
		DeviceInfo:      deviceInfo,
		ManufacturerKey: mfgPubKey,
		CertChainHash: &protocol.Hash{
			Algorithm: alg,
			Value:     certChainHash.Sum(nil),
		},
	}
	rvInfo, err := s.RvInfo(ctx, &Voucher{
		Version:   101,
		Header:    *cbor.NewBstr(*ovh),
		CertChain: &certChain,
	})
	if err != nil {
		return nil, fmt.Errorf("error determining rendezvous info for device: %w", err)
	}
	ovh.RvInfo = rvInfo

	// Store and return voucher header
	if err := s.Session.SetIncompleteVoucherHeader(ctx, ovh); err != nil {
		return nil, fmt.Errorf("error storing incomplete voucher header: %w", err)
	}
	return &setCredentialsMsg{
		OVHeader: *cbor.NewBstr(*ovh),
	}, nil
}

// SetHMAC(12) -> Done(13)
func setHmac(ctx context.Context, transport Transport, hmac hash.Hash, ovh *VoucherHeader) (err error) {
	// Compute HMAC
	ovhHash, err := hmacHash(hmac, ovh)
	if err != nil {
		return fmt.Errorf("error computing HMAC of ownership voucher header: %w", err)
	}

	// Define request structure
	var msg struct {
		Hmac protocol.Hmac
	}
	msg.Hmac = ovhHash

	// Make request
	typ, resp, err := transport.Send(ctx, protocol.DISetHmacMsgType, msg, nil)
	if err != nil {
		return fmt.Errorf("DI.SetHMAC: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case protocol.DIDoneMsgType:
		captureMsgType(ctx, typ)
		return nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return fmt.Errorf("error parsing error message contents of DI.SetHMAC response: %w", err)
		}
		return fmt.Errorf("error received from DI.SetHMAC request: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		return fmt.Errorf("unexpected message type for response to DI.SetHMAC: %d", typ)
	}
}

// SetHMAC(12) -> Done(13)
func (s *DIServer[T]) diDone(ctx context.Context, msg io.Reader) (struct{}, error) {
	var req struct {
		Hmac protocol.Hmac
	}
	if err := cbor.NewDecoder(msg).Decode(&req); err != nil {
		return struct{}{}, fmt.Errorf("error parsing DI.SetHMAC request: %w", err)
	}
	ovh, err := s.Session.IncompleteVoucherHeader(ctx)
	if err != nil {
		return struct{}{}, fmt.Errorf("voucher header not found for session: %w", err)
	}
	deviceCertChain, err := s.Session.DeviceCertChain(ctx)
	if err != nil {
		return struct{}{}, fmt.Errorf("device certificate chain not found for session: %w", err)
	}
	certChain := make([]*cbor.X509Certificate, len(deviceCertChain))
	for i, cert := range deviceCertChain {
		certChain[i] = (*cbor.X509Certificate)(cert)
	}
	ov := &Voucher{
		Version:   101,
		Header:    *cbor.NewBstr(*ovh),
		Hmac:      req.Hmac,
		CertChain: &certChain,
		Entries:   nil,
	}
	if s.BeforeVoucherPersist != nil {
		if err := s.BeforeVoucherPersist(ctx, ov); err != nil {
			return struct{}{}, fmt.Errorf("error in callback before new voucher is persisted: %w", err)
		}
	}
	if err := s.Vouchers.AddVoucher(ctx, ov); err != nil {
		return struct{}{}, fmt.Errorf("error storing voucher: %w", err)
	}
	if s.AfterVoucherPersist != nil {
		if err := s.AfterVoucherPersist(ctx, *ov); err != nil {
			return struct{}{}, fmt.Errorf("error in callback after new voucher is persisted: %w", err)
		}
	}
	return struct{}{}, nil
}
