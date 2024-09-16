// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
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
		var setCredentials setCredentialsMsg
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

type setCredentialsMsg struct {
	OVHeader cbor.Bstr[VoucherHeader]
}

// AppStart(10) -> SetCredentials(11)
func (s *DIServer[T]) setCredentials(ctx context.Context, msg io.Reader) (*setCredentialsMsg, error) {
	// Decode proprietary device mfg info from app start
	var appStart struct {
		Info *cbor.Bstr[T]
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
	deviceInfo, keyType, keyEncoding, err := s.DeviceInfo(ctx, info, chain)
	if err != nil {
		return nil, fmt.Errorf("error getting device info: %w", err)
	}

	// Use issuer chain of device certificate to identify manufacturer pubkey
	// and encode as the device requested
	mfgPubKey, err := encodePublicKey(keyType, keyEncoding, chain[1:])
	if err != nil {
		return nil, fmt.Errorf("error constructing manufacturer public key from CA chain: %w", err)
	}

	// Compute the appropriate cert chain hash
	alg, err := hashAlgFor(chain[0].PublicKey, chain[1].PublicKey)
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
	var guid GUID
	if _, err := rand.Read(guid[:]); err != nil {
		return nil, fmt.Errorf("error generating device GUID: %w", err)
	}
	ovh := &VoucherHeader{
		Version:         101,
		GUID:            guid,
		DeviceInfo:      deviceInfo,
		ManufacturerKey: *mfgPubKey,
		CertChainHash: &Hash{
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

func encodePublicKey(keyType KeyType, keyEncoding KeyEncoding, chain []*x509.Certificate) (*PublicKey, error) {
	switch keyEncoding {
	case X509KeyEnc:
		return newPublicKey(keyType, chain[0].PublicKey, false)
	case X5ChainKeyEnc:
		return newPublicKey(keyType, chain, false)
	case CoseKeyEnc:
		return newPublicKey(keyType, chain[0].PublicKey, true)
	default:
		return nil, fmt.Errorf("unsupported key encoding: %s", keyEncoding)
	}
}

// SetHMAC(12) -> Done(13)
func (c *Client) setHmac(ctx context.Context, baseURL string, ovh *VoucherHeader) (err error) {
	// Compute HMAC
	ownerPubKey, _ := ovh.ManufacturerKey.Public()
	alg, err := hashAlgFor(c.Key.Public(), ownerPubKey)
	if err != nil {
		return fmt.Errorf("error selecting the appropriate hash algorithm: %w", err)
	}
	switch alg {
	case Sha256Hash:
		alg = HmacSha256Hash
	case Sha384Hash:
		alg = HmacSha384Hash
	default:
		panic("only SHA256 and SHA384 are supported in FDO")
	}
	ovhHash, err := hmacHash(c.Hmac, alg, ovh)
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
func (s *DIServer[T]) diDone(ctx context.Context, msg io.Reader) (struct{}, error) {
	var req struct {
		Hmac Hmac
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
	if err := s.maybeAutoExtend(ov); err != nil {
		return struct{}{}, fmt.Errorf("error extending voucher: %w", err)
	}
	if err := s.Vouchers.NewVoucher(ctx, ov); err != nil {
		return struct{}{}, fmt.Errorf("error storing voucher: %w", err)
	}
	if err := s.maybeAutoTO0(ctx, ov); err != nil {
		return struct{}{}, fmt.Errorf("error auto-registering device for rendezvous: %w", err)
	}
	return struct{}{}, nil
}

func (s *DIServer[T]) maybeAutoExtend(ov *Voucher) error {
	if s.AutoExtend == nil {
		return nil
	}

	keyType := ov.Header.Val.ManufacturerKey.Type
	owner, _, err := s.AutoExtend.ManufacturerKey(keyType)
	if err != nil {
		return fmt.Errorf("error getting %s manufacturer key: %w", keyType, err)
	}
	nextOwner, _, err := s.AutoExtend.OwnerKey(keyType)
	if err != nil {
		return fmt.Errorf("error getting %s owner key: %w", keyType, err)
	}
	switch owner.Public().(type) {
	case *ecdsa.PublicKey:
		nextOwner, ok := nextOwner.Public().(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("owner key must be %s", keyType)
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
			return fmt.Errorf("owner key must be %s", keyType)
		}
		extended, err := ExtendVoucher(ov, owner, nextOwner, nil)
		if err != nil {
			return err
		}
		*ov = *extended
		return nil

	default:
		return fmt.Errorf("invalid key type %T", owner)
	}
}

func (s *DIServer[T]) maybeAutoTO0(ctx context.Context, ov *Voucher) error {
	if s.AutoTO0 == nil {
		return nil
	}
	if s.AutoExtend == nil {
		return fmt.Errorf("voucher auto-extension must be enabled when auto-TO0 is enabled")
	}
	if len(s.AutoTO0Addrs) == 0 {
		return fmt.Errorf("TO2 addrs cannot be empty when auto-TO0 is enabled")
	}

	keyType := ov.Header.Val.ManufacturerKey.Type
	nextOwner, _, err := s.AutoTO0.OwnerKey(keyType)
	if err != nil {
		return fmt.Errorf("error getting %s owner key: %w", keyType, err)
	}

	var opts crypto.SignerOpts
	switch keyType {
	case Rsa2048RestrKeyType, RsaPkcsKeyType, RsaPssKeyType:
		switch rsaPub := nextOwner.Public().(*rsa.PublicKey); rsaPub.Size() {
		case 2048 / 8:
			opts = crypto.SHA256
		case 3072 / 8:
			opts = crypto.SHA384
		default:
			return fmt.Errorf("unsupported RSA key size: %d bits", rsaPub.Size()*8)
		}

		if keyType == RsaPssKeyType {
			opts = &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       opts.(crypto.Hash),
			}
		}
	}

	sign1 := cose.Sign1[To1d, []byte]{
		Payload: cbor.NewByteWrap(To1d{
			RV: s.AutoTO0Addrs,
		}),
	}
	if err := sign1.Sign(nextOwner, nil, nil, opts); err != nil {
		return fmt.Errorf("error signing to1d: %w", err)
	}
	exp := time.Now().AddDate(30, 0, 0) // Expire in 30 years
	if err := s.AutoTO0.SetRVBlob(ctx, ov, &sign1, exp); err != nil {
		return fmt.Errorf("error storing to1d: %w", err)
	}

	return nil
}
