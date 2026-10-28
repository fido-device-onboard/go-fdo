// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

// Package cred provides a unified credential store for FDO device credentials.
//
// The storage backend is selected at compile time via build tags:
//
//   - Default (no tags): file-based blob — keys and HMAC secret stored in a
//     CBOR credential file. Pure software, no hardware dependency.
//   - -tags=tpm: hardware TPM — HMAC and device key live in the TPM,
//     credential metadata in a file (transitional; NV storage planned).
//   - -tags=tpmsim: TPM software simulator — same as tpm but uses a
//     software simulator. Requires CGO.
//
// Consumer code is identical regardless of backend:
//
//	store, err := cred.Open("cred.bin")
//	defer store.Close()
//
//	// Device Initialization
//	h256, h384, key, err := store.NewDI(protocol.Secp384r1KeyType)
//	dc, err := fdo.DI(ctx, transport, mfgInfo, fdo.DIConfig{
//	    HmacSha256: h256, HmacSha384: h384, Key: key,
//	})
//	store.Save(*dc)
//
//	// Transfer of Ownership
//	dc, h256, h384, key, err := store.Load()
//	newDC, err := fdo.TO2(ctx, ...)
//	if newDC != nil { store.Save(*newDC) }
package cred

import (
	"crypto"
	"fmt"
	"hash"
	"os"
	"path/filepath"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// Store manages FDO device credential lifecycle.
// The storage backend is determined by build tags at compile time.
type Store interface {
	// NewDI creates fresh HMAC and key material for Device Initialization.
	// The keyType selects the algorithm (e.g., protocol.Secp256r1KeyType).
	//
	// For blob mode, keys are generated in software.
	// For TPM modes, keys are generated inside the TPM.
	NewDI(keyType protocol.KeyType) (hmacSHA256, hmacSHA384 hash.Hash, key crypto.Signer, err error)

	// Save persists a device credential after DI or TO2 completes.
	// The store retains the key material internally; only the credential
	// metadata (GUID, RV info, etc.) is updated.
	Save(dc fdo.DeviceCredential) error

	// Load reads a previously saved credential and reconstructs HMAC/key
	// material for use in TO1/TO2.
	//
	// For blob mode, the HMAC secret and private key are read from the file.
	// For TPM modes, keys are deterministically regenerated from the TPM seed.
	Load() (dc *fdo.DeviceCredential, hmacSHA256, hmacSHA384 hash.Hash, key crypto.Signer, err error)

	// Close releases resources (TPM handles, etc.). For blob mode this is a no-op.
	Close() error
}

// Open returns a credential store backed by the build-tag-selected backend.
// The path argument is the credential file path (e.g., "cred.bin").
//
// func Open(path string) (Store, error)  — defined in build-tag-selected files

// writeCredFile atomically writes a credential to a file.
func writeCredFile(path string, dc any) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "fdo_cred_*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	defer func() { _ = tmp.Close() }()

	if err := cbor.NewEncoder(tmp).Encode(dc); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	_ = tmp.Close()

	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("renaming credential file: %w", err)
	}
	return nil
}
