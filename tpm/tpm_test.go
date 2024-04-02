// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package tpm_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/google/go-tpm/tpm2/transport/simulator"

	"github.com/fido-device-onboard/go-fdo/tpm"
)

func TestPublicKey(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("error opening opening TPM simulator: %v", err)
	}
	defer func() { _ = sim.Close() }()

	dc := tpm.DeviceCredential{TpmDevice: sim}

	for _, test := range []struct {
		PSS bool
	}{
		{PSS: false},
		{PSS: true},
	} {
		t.Run(fmt.Sprintf("PSS=%t", test.PSS), func(t *testing.T) {
			// Generate a new key in the TPM
			if err := dc.NewKey(test.PSS); err != nil {
				t.Fatalf("error generating key: %v", err)
			}

			// Sign test data
			hash := sha256.New()
			_, _ = hash.Write([]byte("Hello World!"))
			digest := hash.Sum(nil)
			opts := crypto.SignerOpts(crypto.SHA256)
			if test.PSS {
				opts = &rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthEqualsHash,
					Hash:       crypto.SHA256,
				}
			}
			sig, err := dc.Sign(rand.Reader, digest, opts)
			if err != nil {
				t.Fatalf("error signing digest: %v", err)
			}

			// Get the public key
			pub, ok := dc.Public().(*rsa.PublicKey)
			if !ok {
				t.Fatalf("unexpected key type: %T", dc.Public())
			}

			// Verify the test signature
			if test.PSS {
				err = rsa.VerifyPSS(pub, crypto.SHA256, digest, sig, opts.(*rsa.PSSOptions))
			} else {
				err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig)
			}
			if err != nil {
				t.Fatalf("error verifying signature: %v", err)
			}
		})
	}
}
