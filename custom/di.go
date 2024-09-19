// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package custom implements non-normative types and functions for DI.
package custom

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/fido-device-onboard/go-fdo"
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

// CertificateAuthority contains the necessary method to get a CA key and chain
// for signing device certificates.
type CertificateAuthority interface {
	// ManufacturerKey returns the signer of a given key type and its certificate
	// chain (required).
	ManufacturerKey(keyType protocol.KeyType) (crypto.Signer, []*x509.Certificate, error)
}

// SignDeviceCertificate creates a device certificate chain from the info sent
// in DI.AppStart.
func SignDeviceCertificate(ca CertificateAuthority) func(*DeviceMfgInfo) ([]*x509.Certificate, error) {
	return func(info *DeviceMfgInfo) ([]*x509.Certificate, error) {
		// Validate device info
		csr := x509.CertificateRequest(info.CertInfo)
		if err := csr.CheckSignature(); err != nil {
			return nil, fmt.Errorf("invalid CSR: %w", err)
		}

		// Sign CSR
		key, chain, err := ca.ManufacturerKey(info.KeyType)
		if err != nil {
			var unsupportedErr fdo.ErrUnsupportedKeyType
			if errors.As(err, &unsupportedErr) {
				return nil, unsupportedErr
			}
			return nil, fmt.Errorf("error retrieving manufacturer key [type=%s]: %w", info.KeyType, err)
		}
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			return nil, fmt.Errorf("error generating certificate serial number: %w", err)
		}
		template := &x509.Certificate{
			SerialNumber: serialNumber,
			Issuer:       chain[0].Subject,
			Subject:      csr.Subject,
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(30 * 360 * 24 * time.Hour), // Matches Java impl
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, chain[0], csr.PublicKey, key)
		if err != nil {
			return nil, fmt.Errorf("error signing CSR: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("error parsing signed device cert: %w", err)
		}
		chain = append([]*x509.Certificate{cert}, chain...)
		return chain, nil
	}
}
