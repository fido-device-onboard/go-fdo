// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package blob implements a device credential that may be stored to disk as a
// marshaled blob.
package blob

import (
	"crypto"
	"crypto/hmac"
	"fmt"
	"hash"
	"io"

	"github.com/fido-device-onboard/go-fdo"
)

// DeviceCredential contains all device state, including both public and private
// parts of keys and secrets.
type DeviceCredential struct {
	Active bool
	fdo.DeviceCredential

	// Secrets that would otherwise be stored inside a TPM or other enclave.
	HmacSecret Hmac
	PrivateKey Pkcs8Key
}

var _ fdo.KeyedHasher = (*DeviceCredential)(nil)

// NewHmac returns a key-based hash (Hmac) using the given hash function some
// secret.
func (dc *DeviceCredential) NewHmac(alg fdo.HashAlg) hash.Hash {
	return hmac.New(alg.HashFunc().New, dc.HmacSecret)
}

// Supports returns whether a particular HashAlg is supported.
func (dc *DeviceCredential) Supports(alg fdo.HashAlg) bool {
	switch alg {
	case fdo.HmacSha256Hash, fdo.HmacSha384Hash:
		return true
	default:
		return false
	}
}

var _ crypto.Signer = (*DeviceCredential)(nil)

// Public returns the corresponding public key.
func (dc *DeviceCredential) Public() crypto.PublicKey { return dc.PrivateKey.Public() }

// Sign signs digest with the private key.
func (dc *DeviceCredential) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if !dc.PrivateKey.IsValid() {
		return nil, fmt.Errorf("private key is an invalid type or curve/size for FDO device credential usage")
	}
	return dc.PrivateKey.Sign(rand, digest, opts)
}
