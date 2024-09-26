// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package tpm_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"

	"github.com/fido-device-onboard/go-fdo/tpm"
)

func TestPublicKey(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("error opening opening TPM simulator: %v", err)
	}
	defer func() {
		if err := sim.Close(); err != nil {
			t.Error(err)
		}
	}()

	for _, test := range []struct {
		Name string
		Gen  func(transport.TPM) (tpm.Key, error)
		Hash crypto.Hash
	}{
		{
			Name: "RSA-SSA-2048",
			Gen: func(t transport.TPM) (tpm.Key, error) {
				return tpm.GenerateRSAKey(t, 2048)
			},
			Hash: crypto.SHA256,
		},
		{
			Name: "RSA-PSS-2048",
			Gen: func(t transport.TPM) (tpm.Key, error) {
				return tpm.GenerateRSAPSSKey(t, 2048)
			},
			Hash: crypto.SHA256,
		},
		{
			Name: "EC-P256",
			Gen: func(t transport.TPM) (tpm.Key, error) {
				return tpm.GenerateECKey(t, elliptic.P256())
			},
			Hash: crypto.SHA256,
		},
		{
			Name: "EC-P384",
			Gen: func(t transport.TPM) (tpm.Key, error) {
				return tpm.GenerateECKey(t, elliptic.P384())
			},
			Hash: crypto.SHA384,
		},

		//  RSA-3072 is not supported by the simulator and the simulator
		//  segfaults when -DRSA_3072 is added to CFLAGS
		//
		// {
		// 	Name: "RSA-SSA-3072",
		//	Gen: func(t transport.TPM) (crypto.Signer, error) {
		//		return tpm.GenerateRSAKey(t, 3072)
		//	},
		// 	Hash: crypto.SHA384,
		// },
		// {
		// 	Name: "RSA-PSS-3072",
		//	Gen: func(t transport.TPM) (crypto.Signer, error) {
		//		return tpm.GenerateRSAPSSKey(t, 3072)
		//	},
		// 	Hash: crypto.SHA384,
		// },
	} {
		t.Run(test.Name, func(t *testing.T) {
			// Generate a new key in the TPM
			key, err := test.Gen(sim)
			if err != nil {
				t.Fatalf("error generating key: %v", err)
			}
			defer func() {
				if err := key.Close(); err != nil {
					t.Error(err)
				}
			}()

			// Sign test data
			hash := test.Hash.New()
			_, _ = hash.Write([]byte("Hello World!"))
			digest := hash.Sum(nil)

			var opts crypto.SignerOpts
			if strings.HasPrefix(test.Name, "RSA-PSS") {
				opts = &rsa.PSSOptions{}
			}
			sig, err := key.Sign(rand.Reader, digest, opts)
			if err != nil {
				t.Fatalf("error signing digest: %v", err)
			}

			// Verify the test signature
			switch pub := key.Public().(type) {
			case *ecdsa.PublicKey:
				// Decode signature following RFC8152 8.1.
				n := (pub.Params().N.BitLen() + 7) / 8
				r := new(big.Int).SetBytes(sig[:n])
				s := new(big.Int).SetBytes(sig[n:])
				if !ecdsa.Verify(pub, digest, r, s) {
					t.Fatalf("error verifying ECDSA signature")
				}

			case *rsa.PublicKey:
				if strings.HasPrefix(test.Name, "RSA-PSS") {
					err = rsa.VerifyPSS(pub, test.Hash, digest, sig, &rsa.PSSOptions{
						SaltLength: rsa.PSSSaltLengthEqualsHash,
						Hash:       test.Hash,
					})
				} else {
					err = rsa.VerifyPKCS1v15(pub, test.Hash, digest, sig)
				}
				if err != nil {
					t.Fatalf("error verifying RSA signature: %v", err)
				}

			default:
				t.Fatalf("unexpected key type: %T", pub)
			}
		})
	}
}
