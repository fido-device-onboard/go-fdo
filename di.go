// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// DI Message Types
const (
	diAppStartMsgType       uint8 = 10
	diSetCredentialsMsgType uint8 = 11
	diSetHmacMsgType        uint8 = 12
	diDoneMsgType           uint8 = 13
)

// DeviceMfgInfo is an example structure for use in DI.AppStart. The structure
// is not part of the spec, but matches the [C client] and [Java client]
// implementations.
//
// Type definition from C:
//
//	MfgInfo.cbor = [
//	  pkType,                 // as per FDO spec
//	  pkEnc,                  // as per FDO spec
//	  serialNo,               // tstr
//	  modelNo,                // tstr
//	  CSR,                    // bstr
//	  OnDie ECDSA cert chain, // bstr OR OMITTED
//	  test signature,         // bstr OR OMITTED
//	  MAROE prefix,           // bstr OR OMITTED
//	]
//
//	DeviceMfgInfo = bstr, MfgInfo.cbor (bstr-wrap MfgInfo CBOR bytes)
//
// [C client]: https://github.com/fido-device-onboard/client-sdk-fidoiot/
// [Java client]: https://github.com/fido-device-onboard/pri-fidoiot
type DeviceMfgInfo struct {
	KeyType      KeyType
	KeyEncoding  KeyEncoding
	SerialNumber string
	DeviceInfo   string
	CertInfo     cbor.X509CertificateRequest
	// ODCAChain          []byte // deprecated
	// TestSig            []byte // deprecated
	// TestSigMAROEPrefix []byte // deprecated
}

// AppStart(10) -> SetCredentials(11)
func (c *Client) appStart(ctx context.Context, baseURL string, info any) (*VoucherHeader, error) {
	// Define request structure
	var msg struct {
		DeviceMfgInfo *cbor.Bstr[any]
	}
	if info != nil {
		msg.DeviceMfgInfo = cbor.NewBstr(info)
	}

	// Make request
	typ, resp, err := c.Transport.Send(ctx, baseURL, diAppStartMsgType, msg, nil)
	if err != nil {
		return nil, fmt.Errorf("error sending DI.AppStart: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case diSetCredentialsMsgType:
		captureMsgType(ctx, typ)
		var setCredentials struct {
			OVHeader cbor.Bstr[VoucherHeader]
		}
		if err := cbor.NewDecoder(resp).Decode(&setCredentials); err != nil {
			captureErr(ctx, messageBodyErrCode, "")
			return nil, fmt.Errorf("error parsing DI.SetCredentials request: %w", err)
		}
		return &setCredentials.OVHeader.Val, nil

	case ErrorMsgType:
		var errMsg ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return nil, fmt.Errorf("error parsing error message contents of DI.AppStart response: %w", err)
		}
		return nil, fmt.Errorf("error received from DI.AppStart request: %w", errMsg)

	default:
		captureErr(ctx, messageBodyErrCode, "")
		return nil, fmt.Errorf("unexpected message type for response to DI.AppStart: %d", typ)
	}
}

// AppStart(10) -> SetCredentials(11)
func (s *Server) setCredentials(ctx context.Context, msg io.Reader) (*VoucherHeader, error) {
	var info DeviceMfgInfo
	if err := cbor.NewDecoder(msg).Decode(&info); err != nil {
		return nil, fmt.Errorf("error decoding device manufacturing info: %w", err)
	}
	chain, err := s.NewDevices.NewDeviceCertChain(ctx, info)
	if err != nil {
		return nil, fmt.Errorf("error creating device certificate chain: %w", err)
	}
	certChainHash := sha512.New384()
	for _, cert := range chain {
		_, _ = certChainHash.Write(cert.Raw)
	}
	var guid GUID
	if _, err := rand.Read(guid[:]); err != nil {
		return nil, fmt.Errorf("error generating device GUID: %w", err)
	}
	if err := s.GUID.SetGUID(ctx, guid); err != nil {
		return nil, fmt.Errorf("error storing device GUID: %w", err)
	}
	_, mfgPubKey, ok := s.ManufacturerKeys(info.KeyType)
	if !ok {
		return nil, fmt.Errorf("no manufacturer keys available for key type %s", info.KeyType)
	}
	ovh := &VoucherHeader{
		Version:         101,
		GUID:            guid,
		RvInfo:          s.RvInfo,
		DeviceInfo:      info.DeviceInfo,
		ManufacturerKey: mfgPubKey,
		CertChainHash: &Hash{
			Algorithm: Sha384Hash,
			Value:     certChainHash.Sum(nil),
		},
	}
	if err := s.NewDevices.SetIncompleteVoucherHeader(ctx, ovh); err != nil {
		return nil, fmt.Errorf("error storing incomplete voucher header: %w", err)
	}
	return ovh, nil
}

// SetHMAC(12) -> Done(13)
func (c *Client) setHmac(ctx context.Context, baseURL string, ovh *VoucherHeader) (err error) {
	var ovhHash Hmac
	if c.Hmac.Supports(HmacSha384Hash) {
		ovhHash, err = hmacHash(c.Hmac, HmacSha384Hash, ovh)
	} else {
		ovhHash, err = hmacHash(c.Hmac, HmacSha256Hash, ovh)
	}
	if err != nil {
		return fmt.Errorf("error computing HMAC of ownership voucher header: %w", err)
	}

	// Define request structure
	var msg struct {
		Hmac Hmac
	}
	msg.Hmac = ovhHash

	// Make request
	typ, resp, err := c.Transport.Send(ctx, baseURL, diSetHmacMsgType, msg, nil)
	if err != nil {
		return fmt.Errorf("error sending DI.SetHMAC: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case diDoneMsgType:
		captureMsgType(ctx, typ)
		return nil

	case ErrorMsgType:
		var errMsg ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			captureErr(ctx, messageBodyErrCode, "")
			return fmt.Errorf("error parsing error message contents of DI.SetHMAC response: %w", err)
		}
		return fmt.Errorf("error received from DI.SetHMAC request: %w", errMsg)

	default:
		captureErr(ctx, messageBodyErrCode, "")
		return fmt.Errorf("unexpected message type for response to DI.SetHMAC: %d", typ)
	}
}

// SetHMAC(12) -> Done(13)
func (s *Server) diDone(ctx context.Context, msg io.Reader) (struct{}, error) {
	var req struct {
		Hmac Hmac
	}
	if err := cbor.NewDecoder(msg).Decode(&req); err != nil {
		return struct{}{}, fmt.Errorf("error parsing DI.SetHMAC request: %w", err)
	}
	ovh, err := s.NewDevices.IncompleteVoucherHeader(ctx)
	if err != nil {
		return struct{}{}, fmt.Errorf("voucher header not found for session: %w", err)
	}
	deviceCertChain, err := s.NewDevices.DeviceCertChain(ctx)
	if err != nil {
		return struct{}{}, fmt.Errorf("device certificate chain not found for session: %w", err)
	}
	certChain := make([]*cbor.X509Certificate, len(deviceCertChain))
	for i, cert := range deviceCertChain {
		certChain[i] = (*cbor.X509Certificate)(cert)
	}
	if err := s.Devices.NewVoucher(ctx, &Voucher{
		Version:   101,
		Header:    *cbor.NewBstr(*ovh),
		Hmac:      req.Hmac,
		CertChain: &certChain,
		Entries:   nil,
	}); err != nil {
		return struct{}{}, fmt.Errorf("error creating voucher: %w", err)
	}
	return struct{}{}, nil
}
