// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

// DeviceCredential is non-normative, but the [TPM Draft Spec] proposes a CBOR
// encoding, so that will be used.
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
	Version         uint16
	DeviceInfo      string
	Guid            Guid
	RvInfo          [][]RvVariable
	PublicKeyHash   Hash
	DeviceKeyType   uint64
	DeviceKeyHandle uint64
}

// DeviceCredentialBlob contains all device state, including both public and private
// parts of keys and secrets.
type DeviceCredentialBlob struct {
	DeviceCredential

	Active     bool
	HmacType   HashAlg
	HmacSecret []byte
	PrivateKey []byte // PKCS#8
}

var _ Signer = (*DeviceCredentialBlob)(nil)

// Hmac encodes the given value to CBOR and calculates the hashed MAC for the
// given algorithm.
func (dc *DeviceCredentialBlob) Hmac(alg HashAlg, payload any) (Hmac, error) {
	var newHash func() hash.Hash
	switch alg {
	case HmacSha256Hash:
		newHash = sha256.New
	case HmacSha384Hash:
		newHash = sha512.New384
	default:
		return Hmac{}, fmt.Errorf("unsupported hmac algorithm: %v", alg)
	}

	mac := hmac.New(newHash, dc.HmacSecret)
	if err := cbor.NewEncoder(mac).Encode(payload); err != nil {
		return Hmac{}, fmt.Errorf("error computing hmac: marshaling payload: %w", err)
	}
	return Hmac{
		Algorithm: alg,
		Value:     mac.Sum(nil),
	}, nil
}

// HmacVerify encodes the given value to CBOR and verifies that the given HMAC
// matches it.
func (dc *DeviceCredentialBlob) HmacVerify(h Hmac, v any) error {
	h1, err := dc.Hmac(h.Algorithm, v)
	if err != nil {
		return err
	}
	if !hmac.Equal(h.Value, h1.Value) {
		return fmt.Errorf("%w: hmac did not match", ErrCryptoVerifyFailed)
	}
	return nil
}

// Sign encodes the given payload to CBOR and performs signs it as a COSE Sign1
// signature structure.
func (dc *DeviceCredentialBlob) Sign(payload any) (cose.Sign1[any], error) {
	panic("unimplemented")
}

// Verify uses the same private material as Sign to verify the given COSE Sign1
// signature structure.
func (dc *DeviceCredentialBlob) Verify(v cose.Sign1[any]) error {
	panic("unimplemented")
}
