// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"crypto"
	"fmt"
	"hash"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cred"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// credStore is the active credential store for the session.
// Build tags on the cred package select the backend (blob, tpm, tpmsim).
var credStore cred.Store

func openCredStore() error {
	var err error
	credStore, err = cred.Open(blobPath)
	if err != nil {
		return fmt.Errorf("opening credential store: %w", err)
	}
	return nil
}

// ensureCredStore lazily opens the credential store if not already open.
func ensureCredStore() error {
	if credStore != nil {
		return nil
	}
	return openCredStore()
}

func newDICred(keyType protocol.KeyType) (hash.Hash, hash.Hash, crypto.Signer, error) {
	if err := ensureCredStore(); err != nil {
		return nil, nil, nil, err
	}
	return credStore.NewDI(keyType)
}

func saveCred(dc fdo.DeviceCredential) error {
	if err := ensureCredStore(); err != nil {
		return err
	}
	return credStore.Save(dc)
}

func readCred() (_ *fdo.DeviceCredential, hmacSha256, hmacSha384 hash.Hash, key crypto.Signer, _ error) {
	if err := ensureCredStore(); err != nil {
		return nil, nil, nil, nil, err
	}
	dc, h256, h384, k, err := credStore.Load()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return dc, h256, h384, k, nil
}

func closeCredStore() error {
	if credStore != nil {
		return credStore.Close()
	}
	return nil
}
