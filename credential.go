// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"crypto"
	"crypto/hmac"
	"fmt"
	"io"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// DeviceCredential is non-normative, but the [TPM Draft Spec] proposes a CBOR
// encoding, so that will be used, excluding the key type/handle.
//
//	DCTPM = [
//	    DCProtVer: protver,
//	    DCDeviceInfo: tstr,
//	    DCGuid: bstr
//	    DCRVInfo: RendezvousInfo,
//	    DCPubKeyHash: Hash
//	    DeviceKeyType: uint
//	    DeviceKeyHandle: uint
//	]
//
// [TPM Draft Spec]: https://fidoalliance.org/specs/FDO/securing-fdo-in-tpm-v1.0-rd-20231010/securing-fdo-in-tpm-v1.0-rd-20231010.html
type DeviceCredential struct {
	Version       uint16
	DeviceInfo    string
	GUID          GUID
	RvInfo        [][]RvInstruction
	PublicKeyHash Hash // expected to be a hash of the entire CBOR structure (not just pkBody) for Voucher.VerifyEntries to succeed
}

// DeviceCredentialBlob contains all device state, including both public and private
// parts of keys and secrets.
type DeviceCredentialBlob struct {
	Active bool
	DeviceCredential

	// Secrets that would otherwise be stored inside a TPM or other enclave.
	HmacSecret []byte
	PrivateKey Pkcs8Key
}

var _ KeyedHasher = (*DeviceCredentialBlob)(nil)

// Hmac encodes the given value to CBOR and calculates the hashed MAC for the
// given algorithm.
func (dc *DeviceCredentialBlob) Hmac(alg HashAlg, payload any) (Hmac, error) {
	if !dc.PrivateKey.IsValid() {
		return Hmac{}, fmt.Errorf("private key is invalid")
	}

	var hash crypto.Hash
	switch alg {
	case HmacSha256Hash:
		hash = crypto.SHA256
	case HmacSha384Hash:
		hash = crypto.SHA384
	default:
		return Hmac{}, fmt.Errorf("unsupported hash algorithm: %s", alg)
	}

	mac := hmac.New(hash.New, dc.HmacSecret)
	if err := cbor.NewEncoder(mac).Encode(payload); err != nil {
		return Hmac{}, fmt.Errorf("error computing hmac: marshaling payload: %w", err)
	}
	return Hmac{
		Algorithm: alg,
		Value:     mac.Sum(nil),
	}, nil
}

// Supports returns whether a particular HashAlg is supported.
func (dc *DeviceCredential) Supports(alg HashAlg) bool {
	switch alg {
	case HmacSha256Hash, HmacSha384Hash:
		return true
	default:
		return false
	}
}

var _ crypto.Signer = (*DeviceCredentialBlob)(nil)

// Public returns the corresponding public key.
func (dc *DeviceCredentialBlob) Public() crypto.PublicKey { return dc.PrivateKey.Public() }

// Sign signs digest with the private key.
func (dc *DeviceCredentialBlob) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if !dc.PrivateKey.IsValid() {
		return nil, fmt.Errorf("private key is an invalid type or curve/size for FDO device credential usage")
	}
	return dc.PrivateKey.Sign(rand, digest, opts)
}
