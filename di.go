// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"fmt"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// DI Message Types
const (
	DIAppStartMsgType       uint8 = 10
	DISetCredentialsMsgType uint8 = 11
	DISetHmacMsgType        uint8 = 12
	DIDoneMsgType           uint8 = 13
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
//	  OnDie ECDSA cert chain, // bstr
//	  test signature,         // bstr
//	  MAROE prefix,           // bstr
//	]
//
//	DeviceMfgInfo = bstr, MfgInfo.cbor (bstr-wrap MfgInfo CBOR bytes)
//
// [C client]: https://github.com/fido-device-onboard/client-sdk-fidoiot/
// [Java client]: https://github.com/fido-device-onboard/pri-fidoiot
type DeviceMfgInfo struct {
	KeyType            KeyType
	KeyEncoding        KeyEncoding
	KeyHashAlg         HashAlg
	SerialNumber       string
	DeviceInfo         string
	CertInfo           cbor.X509CertificateRequest
	ODCAChain          []byte
	TestSig            []byte
	TestSigMAROEPrefix []byte
}

// AppStart(10) -> SetCredential(11)
func (c *Client) appStart(ctx context.Context, baseURL string, info any) (*VoucherHeader, error) {
	// Define request structure
	var msg struct {
		DeviceMfgInfo *cbor.Bstr[any]
	}
	if info != nil {
		msg.DeviceMfgInfo = cbor.NewBstrPtr(info)
	}

	// Make request
	typ, resp, err := c.Transport.Send(ctx, baseURL, DIAppStartMsgType, msg)
	if err != nil {
		return nil, fmt.Errorf("error sending DI.AppStart: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case DISetCredentialsMsgType:
		var setCredentials struct {
			OVHeader cbor.Bstr[VoucherHeader]
		}
		if err := cbor.NewDecoder(resp).Decode(&setCredentials); err != nil {
			return nil, fmt.Errorf("error parsing DI.SetCredentials contents: %w", err)
		}
		return &setCredentials.OVHeader.Val, nil

	case ErrorMsgType:
		var errMsg ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return nil, fmt.Errorf("error parsing error message contents of DI.AppStart response: %w", err)
		}
		return nil, fmt.Errorf("error received from DI.AppStart request: %s", errMsg)

	default:
		return nil, fmt.Errorf("unexpected message type for response to DI.AppStart: %d", typ)
	}
}

// SetHMAC(12) -> Done(13)
func (c *Client) setHmac(ctx context.Context, baseURL string, ovhHash Hmac) error {
	// Define request structure
	var msg struct {
		Hmac Hmac
	}
	msg.Hmac = ovhHash

	// Make request
	typ, resp, err := c.Transport.Send(ctx, baseURL, DISetHmacMsgType, msg)
	if err != nil {
		return fmt.Errorf("error sending DI.SetHMAC: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case DIDoneMsgType:
		return nil

	case ErrorMsgType:
		var errMsg ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return fmt.Errorf("error parsing error message contents of DI.SetHMAC response: %w", err)
		}
		return fmt.Errorf("error received from DI.SetHMAC request: %s", errMsg)

	default:
		return fmt.Errorf("unexpected message type for response to DI.SetHMAC: %d", typ)
	}
}
