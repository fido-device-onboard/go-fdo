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

func TestIsDevNode(t *testing.T) {
	for _, test := range []struct {
		path   string
		kind   tpm.DevNodeKind
		expect bool
	}{
		{
			path:   "/dev/tpm0",
			kind:   tpm.DevNodeUnmanaged,
			expect: true,
		},
		{
			path:   "/dev/tpm1",
			kind:   tpm.DevNodeUnmanaged,
			expect: true,
		},
		{
			path:   "/dev/tpmrm0",
			kind:   tpm.DevNodeManaged,
			expect: true,
		},
		{
			path:   "/dev/tpmrm1",
			kind:   tpm.DevNodeManaged,
			expect: true,
		},
		{
			path:   "/dev/tpm0",
			kind:   tpm.DevNodeManaged,
			expect: false,
		},
		{
			path:   "/dev/tpmrm0",
			kind:   tpm.DevNodeUnmanaged,
			expect: false,
		},
		{
			path:   "tpmrm0",
			kind:   tpm.DevNodeManaged,
			expect: false,
		},
	} {
		t.Run("whether "+test.path+" is a "+test.kind.PathPrefix(), func(t *testing.T) {
			if got, expect := tpm.IsDevNode(test.path, test.kind), test.expect; got != expect {
				var direction string
				if !expect {
					direction = " not"
				}
				t.Errorf("expected %q to%s match %q suffixed with a number", test.path, direction, test.kind.PathPrefix())
			}
		})
	}
}

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
