// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"crypto"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"flag"
	"fmt"
	"hash"
	"os"
	"path/filepath"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/blob"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/tpm"
)

const tpmSimulatorPath = "simulator"

func tpmCred() (hash.Hash, hash.Hash, crypto.Signer, func() error, error) {
	var diKeyFlagSet bool
	clientFlags.Visit(func(flag *flag.Flag) {
		diKeyFlagSet = diKeyFlagSet || flag.Name == "di-key"
	})
	if !diKeyFlagSet {
		return nil, nil, nil, nil, fmt.Errorf("-di-key must be set explicitly when using a TPM")
	}

	tpmc, err := tpmOpen(tpmPath)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Use TPM keys for HMAC and Device Key
	h256, err := tpm.NewHmac(tpmc, crypto.SHA256)
	if err != nil {
		_ = tpmc.Close()
		return nil, nil, nil, nil, err
	}
	h384, err := tpm.NewHmac(tpmc, crypto.SHA384)
	if err != nil {
		_ = tpmc.Close()
		return nil, nil, nil, nil, err
	}
	var key tpm.Key
	switch diKey {
	case "ec256":
		key, err = tpm.GenerateECKey(tpmc, elliptic.P256())
	case "ec384":
		key, err = tpm.GenerateECKey(tpmc, elliptic.P384())
	case "rsa2048":
		key, err = tpm.GenerateRSAKey(tpmc, 2048)
	case "rsa3072":
		if tpmPath == tpmSimulatorPath {
			err = fmt.Errorf("TPM simulator does not support RSA3072")
		} else {
			key, err = tpm.GenerateRSAKey(tpmc, 3072)
		}
	default:
		err = fmt.Errorf("unsupported key type: %s", diKey)
	}
	if err != nil {
		_ = tpmc.Close()
		return nil, nil, nil, nil, err
	}

	return h256, h384, key, func() error {
		_ = h256.Close()
		_ = h384.Close()
		_ = key.Close()
		return tpmc.Close()
	}, nil
}

func tpmOpen(tpmPath string) (tpm.Closer, error) {
	if tpmPath == tpmSimulatorPath {
		sim, err := simulator.GetWithFixedSeedInsecure(8086)
		if err != nil {
			return nil, err
		}
		return transport.FromReadWriteCloser(sim), nil
	}
	return linuxtpm.Open(tpmPath)
}

func readCred() (_ *fdo.DeviceCredential, hmacSha256, hmacSha384 hash.Hash, key crypto.Signer, cleanup func() error, _ error) {
	if tpmPath != "" {
		// DeviceCredential requires integrity, so it is stored as a file and
		// expected to be protected. In the future, it should be stored in the
		// TPM and access-protected with a policy.
		var dc tpm.DeviceCredential
		if err := readCredFile(&dc); err != nil {
			return nil, nil, nil, nil, nil, err
		}

		hmacSha256, hmacSha384, key, cleanup, err := tpmCred()
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		return &dc.DeviceCredential, hmacSha256, hmacSha384, key, cleanup, nil
	}

	var dc blob.DeviceCredential
	if err := readCredFile(&dc); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return &dc.DeviceCredential,
		hmac.New(sha256.New, dc.HmacSecret),
		hmac.New(sha512.New384, dc.HmacSecret),
		dc.PrivateKey,
		nil,
		nil
}

func readCredFile(v any) error {
	blobData, err := os.ReadFile(filepath.Clean(blobPath))
	if err != nil {
		return fmt.Errorf("error reading blob credential %q: %w", blobPath, err)
	}
	if err := cbor.Unmarshal(blobData, v); err != nil {
		return fmt.Errorf("error parsing blob credential %q: %w", blobPath, err)
	}
	if printDevice {
		fmt.Printf("%+v\n", v)
	}
	return nil
}

func updateCred(newDC fdo.DeviceCredential) error {
	if tpmPath != "" {
		var dc tpm.DeviceCredential
		if err := readCredFile(&dc); err != nil {
			return err
		}
		dc.DeviceCredential = newDC
		return saveCred(dc)
	}

	var dc blob.DeviceCredential
	if err := readCredFile(&dc); err != nil {
		return err
	}
	dc.DeviceCredential = newDC
	return saveCred(dc)
}

func saveCred(dc any) error {
	// Encode device credential to temp file
	tmp, err := os.CreateTemp(".", "fdo_cred_*")
	if err != nil {
		return fmt.Errorf("error creating temp file for device credential: %w", err)
	}
	defer func() { _ = tmp.Close() }()

	if err := cbor.NewEncoder(tmp).Encode(dc); err != nil {
		return err
	}

	// Rename temp file to given blob path
	_ = tmp.Close()
	if err := os.Rename(tmp.Name(), blobPath); err != nil {
		return fmt.Errorf("error renaming temp blob credential to %q: %w", blobPath, err)
	}

	return nil
}
