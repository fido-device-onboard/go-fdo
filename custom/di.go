// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package custom implements non-normative types and functions for DI.
package custom

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
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
	KeyType      protocol.KeyType
	KeyEncoding  protocol.KeyEncoding
	SerialNumber string
	DeviceInfo   string
	CertInfo     cbor.X509CertificateRequest
	// ODCAChain          []byte // deprecated
	// TestSig            []byte // deprecated
	// TestSigMAROEPrefix []byte // deprecated
}

// SignDeviceCertificate creates a device certificate chain from the info sent
// in DI.AppStart. All info sent from the device is ignored except for its
// certificate signing request (CSR), which is signed by the device CA key and
// prepended to the device CA chain.
//
// Unlike voucher extension chains, device certificate chains may contain any
// signers of mixed key types. There is no restriction, because the device does
// not ever receive or validate the device certificate chain and key
// restrictions in FDO are for the purpose of reducing the amount of crypto
// support a possibly constrained device needs.
func SignDeviceCertificate(deviceCAKey crypto.Signer, deviceCAChain []*x509.Certificate) func(*DeviceMfgInfo) ([]*x509.Certificate, error) {
	return func(info *DeviceMfgInfo) ([]*x509.Certificate, error) {
		// Validate device info
		csr := x509.CertificateRequest(info.CertInfo)
		if err := csr.CheckSignature(); err != nil {
			return nil, fmt.Errorf("invalid CSR: %w", err)
		}

		// Sign CSR
		template := &x509.Certificate{
			Issuer:    deviceCAChain[0].Subject,
			Subject:   csr.Subject,
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(30 * 360 * 24 * time.Hour), // Matches Java impl
			KeyUsage:  x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, deviceCAChain[0], csr.PublicKey, deviceCAKey)
		if err != nil {
			return nil, fmt.Errorf("error signing CSR: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("error parsing signed device cert: %w", err)
		}
		return append([]*x509.Certificate{cert}, deviceCAChain...), nil
	}
}
