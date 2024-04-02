// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package tpm implements device credentials using the
// [TPM Draft Spec](https://fidoalliance.org/specs/FDO/securing-fdo-in-tpm-v1.0-rd-20231010/securing-fdo-in-tpm-v1.0-rd-20231010.html).
package tpm

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"hash"
	"io"
	"log/slog"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/protocol"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// DeviceKeyType enumerates how DeviceKey is encoded and stored.
type DeviceKeyType uint8

// DeviceKeyType enum as defined in section 4.1
//
//	0: FDO key (device key is derived from Unique String)
//	1: The IDevID in the TPM
//	2: An LDevID in the TPM
const (
	FdoDeviceKey    DeviceKeyType = 0
	IDevIDDeviceKey DeviceKeyType = 1
	LDevIDDeviceKey DeviceKeyType = 2
)

// TPM will open a TPM device at the given path.
//
// Clients should use /dev/tpmrm0 because using /dev/tpm0 requires more
// extensive resource management that the kernel already handles for us
// when using the kernel resource manager.
func TPM(path string) (transport.TPMCloser, error) {
	switch path {
	case "/dev/tpmrm0":
		return transport.OpenTPM(path)
	case "/dev/tpm0":
		slog.Warn("direct use of the TPM can lead to resource exhaustion, use a TPM resource manager instead")
		return transport.OpenTPM(path)
	default:
		return nil, fmt.Errorf("unsupported TPM device path: %s", path)
	}
}

// DeviceCredential implements the signing and hmac interfaces and conforms to the
// [TPM Draft Spec](https://fidoalliance.org/specs/FDO/securing-fdo-in-tpm-v1.0-rd-20231010/securing-fdo-in-tpm-v1.0-rd-20231010.html).
type DeviceCredential struct {
	fdo.DeviceCredential
	DeviceKey       DeviceKeyType
	DeviceKeyHandle *tpm2.NamedHandle

	TpmDevice transport.TPMCloser `cbor:"-"`
	pubkey    crypto.PublicKey
	signOpts  crypto.SignerOpts
}

var _ crypto.Signer = (*DeviceCredential)(nil)

// NewKey creates a new key and sets the device key handle.
func (dc *DeviceCredential) NewKey(pss bool) error {
	if dc.TpmDevice == nil {
		return fmt.Errorf("TPM must be set before generating a key")
	}

	var err error
	dc.DeviceKeyHandle, err = newPrimaryRsaKey(dc.TpmDevice, keyTemplate(pss))
	if err != nil {
		return err
	}

	return dc.LoadKey()
}

// LoadKey reads the public portion of the device key handle.
func (dc *DeviceCredential) LoadKey() error {
	if dc.TpmDevice == nil {
		return fmt.Errorf("TPM must be set before loading a key")
	}
	if dc.DeviceKeyHandle == nil {
		return fmt.Errorf("TPM device key handle must be set before loading a key")
	}

	var err error
	dc.pubkey, dc.signOpts, err = readPublicRsaKey(dc.TpmDevice, dc.DeviceKeyHandle)
	return err
}

// Public returns the corresponding public key. It must be called after
// NewKey/LoadKey.
//
// Current implementation will only return *rsa.PublicKey
func (dc *DeviceCredential) Public() crypto.PublicKey { return dc.pubkey }

// SignerOpts returns the signature scheme for the signing key stored in the
// TPM. It must be called after NewKey/LoadKey.
func (dc *DeviceCredential) SignerOpts() crypto.SignerOpts { return dc.signOpts }

// Sign signs digest with the private key.
func (dc *DeviceCredential) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := tpm2.Sign{
		KeyHandle: *dc.DeviceKeyHandle,
		Digest: tpm2.TPM2BDigest{
			Buffer: digest,
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}.Execute(dc.TpmDevice)
	if err != nil {
		return nil, fmt.Errorf("unable to sign digest: %w", err)
	}

	var sigData *tpm2.TPMSSignatureRSA
	if _, ok := opts.(*rsa.PSSOptions); ok {
		sigData, err = sig.Signature.Signature.RSAPSS()
	} else {
		sigData, err = sig.Signature.Signature.RSASSA()
	}
	if err != nil {
		return nil, fmt.Errorf("unable to extract signature data: %w", err)
	}
	return sigData.Sig.Buffer, nil
}

// NewHmac returns a key-based hash (Hmac) using the given hash algorithm
//
// The returned hash.Hash will panic if DeviceCredential.TpmDevice is closed before
// using the Hash.
func (dc *DeviceCredential) NewHmac(alg protocol.HashAlg) (hash.Hash, error) {
	return nil, fmt.Errorf("DEPRECATED")
}
