// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package blob implements a device credential that may be stored to disk as a
// marshaled blob.
package blob

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"io"

	"github.com/fido-device-onboard/go-fdo"
)

// DeviceCredential contains all device state, including both public and private
// parts of keys and secrets.
type DeviceCredential struct {
	Active           bool
	DeviceCredential fdo.DeviceCredential

	// Secrets that would otherwise be stored inside a TPM or other enclave.
	HmacSecret []byte
	PrivateKey Pkcs8Key
}

func (dc DeviceCredential) String() string {
	var key crypto.PrivateKey
	if dc.PrivateKey.IsValid() {
		key = dc.PrivateKey.Signer
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
`, dc.Active, dc.DeviceCredential.Version, dc.DeviceCredential.DeviceInfo, dc.DeviceCredential.GUID, dc.DeviceCredential.PublicKeyHash.Algorithm, dc.DeviceCredential.PublicKeyHash.Value, dc.HmacSecret, key, key)
	for _, directive := range dc.DeviceCredential.RvInfo {
		s += "    >\n"
		for _, instruction := range directive {
			s += fmt.Sprintf("      %d = %x\n", instruction.Variable, instruction.Value)
		}
	}
	return s + "]"
}

// HMACs returns hmac hashes for SHA256 and SHA384.
func (dc *DeviceCredential) HMACs() (hmacSha256, hmacSha384 hash.Hash) {
	return hmac.New(sha256.New, dc.HmacSecret), hmac.New(sha512.New384, dc.HmacSecret)
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
