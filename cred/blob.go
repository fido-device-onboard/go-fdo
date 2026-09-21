// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

//go:build !tpm && !tpmsim

package cred

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"os"
	"path/filepath"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/blob"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

type blobStore struct {
	path   string
	secret []byte
	key    crypto.Signer
}

// Open returns a blob-backed credential store.
func Open(path string) (Store, error) {
	return &blobStore{path: path}, nil
}

func (s *blobStore) NewDI(keyType protocol.KeyType) (hash.Hash, hash.Hash, crypto.Signer, error) {
	s.secret = make([]byte, 32)
	if _, err := rand.Read(s.secret); err != nil {
		return nil, nil, nil, fmt.Errorf("generating HMAC secret: %w", err)
	}

	var err error
	switch keyType {
	case protocol.Secp256r1KeyType:
		s.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case protocol.Secp384r1KeyType:
		s.key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case protocol.Rsa2048RestrKeyType:
		s.key, err = rsa.GenerateKey(rand.Reader, 2048)
	case protocol.RsaPkcsKeyType:
		s.key, err = rsa.GenerateKey(rand.Reader, 3072)
	case protocol.RsaPssKeyType:
		s.key, err = rsa.GenerateKey(rand.Reader, 3072)
	default:
		return nil, nil, nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generating device key: %w", err)
	}

	return hmac.New(sha256.New, s.secret),
		hmac.New(sha512.New384, s.secret),
		s.key, nil
}

func (s *blobStore) Save(dc fdo.DeviceCredential) error {
	return writeCredFile(s.path, blob.DeviceCredential{
		Active:           true,
		DeviceCredential: dc,
		HmacSecret:       s.secret,
		PrivateKey:       blob.Pkcs8Key{Signer: s.key},
	})
}

func (s *blobStore) Load() (*fdo.DeviceCredential, hash.Hash, hash.Hash, crypto.Signer, error) {
	var dc blob.DeviceCredential
	data, err := os.ReadFile(filepath.Clean(s.path))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("reading credential %q: %w", s.path, err)
	}
	if err := cbor.Unmarshal(data, &dc); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parsing credential %q: %w", s.path, err)
	}

	s.secret = dc.HmacSecret
	s.key = dc.PrivateKey.Signer

	return &dc.DeviceCredential,
		hmac.New(sha256.New, dc.HmacSecret),
		hmac.New(sha512.New384, dc.HmacSecret),
		dc.PrivateKey,
		nil
}

func (s *blobStore) Close() error { return nil }
