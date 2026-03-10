// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

//go:build tpm || tpmsim

package cred

import (
	"crypto"
	"crypto/elliptic"
	"fmt"
	"hash"
	"os"
	"path/filepath"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/tpm"
)

// tpmCredData is the on-disk format for TPM-backed credentials.
// Keys live in the TPM; this file stores credential metadata + key type.
type tpmCredData struct {
	fdo.DeviceCredential
	KeyType protocol.KeyType
}

type tpmStore struct {
	path    string
	tpmc    tpm.Closer
	h256    tpm.Hmac
	h384    tpm.Hmac
	key     tpm.Key
	keyType protocol.KeyType
}

// Open returns a TPM-backed credential store.
// The TPM transport is selected by build tag (hardware or simulator).
func Open(path string) (Store, error) {
	t, err := tpm.DefaultOpen()
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	return &tpmStore{path: path, tpmc: t}, nil
}

func (s *tpmStore) NewDI(keyType protocol.KeyType) (hash.Hash, hash.Hash, crypto.Signer, error) {
	s.keyType = keyType

	var err error
	s.h256, err = tpm.NewHmac(s.tpmc, crypto.SHA256)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("TPM HMAC SHA-256: %w", err)
	}
	s.h384, err = tpm.NewHmac(s.tpmc, crypto.SHA384)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("TPM HMAC SHA-384: %w", err)
	}

	switch keyType {
	case protocol.Secp256r1KeyType:
		s.key, err = tpm.GenerateECKey(s.tpmc, elliptic.P256())
	case protocol.Secp384r1KeyType:
		s.key, err = tpm.GenerateECKey(s.tpmc, elliptic.P384())
	case protocol.Rsa2048RestrKeyType:
		s.key, err = tpm.GenerateRSAKey(s.tpmc, 2048)
	case protocol.RsaPkcsKeyType:
		s.key, err = tpm.GenerateRSAKey(s.tpmc, 3072)
	case protocol.RsaPssKeyType:
		s.key, err = tpm.GenerateRSAPSSKey(s.tpmc, 3072)
	default:
		return nil, nil, nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("TPM device key: %w", err)
	}

	return s.h256, s.h384, s.key, nil
}

func (s *tpmStore) Save(dc fdo.DeviceCredential) error {
	return writeCredFile(s.path, tpmCredData{
		DeviceCredential: dc,
		KeyType:          s.keyType,
	})
}

func (s *tpmStore) Load() (*fdo.DeviceCredential, hash.Hash, hash.Hash, crypto.Signer, error) {
	var cdata tpmCredData
	data, err := os.ReadFile(filepath.Clean(s.path))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("reading credential %q: %w", s.path, err)
	}
	if err := cbor.Unmarshal(data, &cdata); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parsing credential %q: %w", s.path, err)
	}

	s.keyType = cdata.KeyType

	// Recreate HMAC handles (TPM HMAC keys are derived from seed — deterministic)
	s.h256, err = tpm.NewHmac(s.tpmc, crypto.SHA256)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("TPM HMAC SHA-256: %w", err)
	}
	s.h384, err = tpm.NewHmac(s.tpmc, crypto.SHA384)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("TPM HMAC SHA-384: %w", err)
	}

	// Recreate device key (TPM primary keys: Seed + Template = same key)
	switch s.keyType {
	case protocol.Secp256r1KeyType:
		s.key, err = tpm.GenerateECKey(s.tpmc, elliptic.P256())
	case protocol.Secp384r1KeyType:
		s.key, err = tpm.GenerateECKey(s.tpmc, elliptic.P384())
	case protocol.Rsa2048RestrKeyType:
		s.key, err = tpm.GenerateRSAKey(s.tpmc, 2048)
	case protocol.RsaPkcsKeyType:
		s.key, err = tpm.GenerateRSAKey(s.tpmc, 3072)
	case protocol.RsaPssKeyType:
		s.key, err = tpm.GenerateRSAPSSKey(s.tpmc, 3072)
	default:
		return nil, nil, nil, nil, fmt.Errorf("unsupported key type: %s", s.keyType)
	}
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("TPM device key: %w", err)
	}

	return &cdata.DeviceCredential, s.h256, s.h384, s.key, nil
}

func (s *tpmStore) Close() error {
	if s.h256 != nil {
		_ = s.h256.Close()
	}
	if s.h384 != nil {
		_ = s.h384.Close()
	}
	if s.key != nil {
		_ = s.key.Close()
	}
	if s.tpmc != nil {
		return s.tpmc.Close()
	}
	return nil
}
