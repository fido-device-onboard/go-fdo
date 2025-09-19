// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"os"
	"path/filepath"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/blob"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/tpm"
)

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
