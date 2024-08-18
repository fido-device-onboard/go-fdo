// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
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

func (dc DeviceCredential) String() string {
	var key crypto.PrivateKey
	if dc.PrivateKey.IsValid() {
		key = dc.PrivateKey.PrivateKey
	}
	s := fmt.Sprintf(`blobcred[
  Active        %t
  Version       %d
  DeviceInfo   %q
  GUID          %x
  PublicKeyHash
    Algorithm   %s
    Value       %x
  HmacSecret    %x
  PrivateKey    %T
    %+v
  RvInfo
`, dc.Active, dc.Version, dc.DeviceInfo, dc.GUID, dc.PublicKeyHash.Algorithm, dc.PublicKeyHash.Value, dc.HmacSecret, key, key)
	for _, directive := range dc.RvInfo {
		s += "    >\n"
		for _, instruction := range directive {
			s += fmt.Sprintf("      %d = %x\n", instruction.Variable, instruction.Value)
		}
	}
	return s + "]"
}

var _ fdo.KeyedHasher = (*DeviceCredential)(nil)

// NewHmac returns a key-based hash (Hmac) using the given hash function some
// secret.
func (dc *DeviceCredential) NewHmac(alg fdo.HashAlg) (hash.Hash, error) {
	return hmac.New(alg.HashFunc().New, dc.HmacSecret), nil
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
