// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package tpm_test

import (
	"crypto"
	"crypto/elliptic"
	"hash"
	"testing"

	"github.com/google/go-tpm/tpm2/transport/simulator"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/fdotest"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/tpm"
)

func TestTPMDevice(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("error opening opening TPM simulator: %v", err)
	}
	defer func() {
		if err := sim.Close(); err != nil {
			t.Error(err)
		}
	}()

	fdotest.RunClientTestSuite(t, fdotest.Config{
		UnsupportedRSA3072: true,
		NewCredential: func(keyType protocol.KeyType) (hmacSha256, hmacSha384 hash.Hash, key crypto.Signer, toDeviceCred func(fdo.DeviceCredential) any) {
			hmacSha256, err := tpm.NewHmac(sim, crypto.SHA256)
			if err != nil {
				t.Fatal(err)
			}
			hmacSha384, err = tpm.NewHmac(sim, crypto.SHA384)
			if err != nil {
				t.Fatal(err)
			}
			switch keyType {
			case protocol.Secp256r1KeyType:
				key, err = tpm.GenerateECKey(sim, elliptic.P256())
			case protocol.Secp384r1KeyType:
				key, err = tpm.GenerateECKey(sim, elliptic.P384())
			case protocol.Rsa2048RestrKeyType:
				key, err = tpm.GenerateRSAKey(sim, 2048)
			case protocol.RsaPkcsKeyType:
				key, err = tpm.GenerateRSAKey(sim, 2048) // Simulator does not support RSA3072
			case protocol.RsaPssKeyType:
				key, err = tpm.GenerateRSAPSSKey(sim, 2048) // Simulator does not support RSA3072
			default:
				t.Fatalf("unsupported key type %s", keyType)
			}
			if err != nil {
				t.Fatalf("error generating device key: %v", err)
			}
			return hmacSha256, hmacSha384, key, func(dc fdo.DeviceCredential) any {
				return tpm.DeviceCredential{
					DeviceCredential: dc,
					DeviceKey:        tpm.FdoDeviceKey,
				}
			}
		},
	})
}
