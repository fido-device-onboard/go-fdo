// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package sqlite_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/fido-device-onboard/go-fdo/fdotest"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

func TestClient(t *testing.T) {
	state, cleanup := newDB(t)
	defer func() { _ = cleanup() }()

	fdotest.RunClientTestSuite(t, fdotest.Config{
		State: state,
	})
}

func TestServerState(t *testing.T) {
	state, cleanup := newDB(t)
	defer func() { _ = cleanup() }()

	fdotest.RunServerStateSuite(t, state)
}

func newDB(t *testing.T) (_ *sqlite.DB, cleanup func() error) {
	cleanup = func() error { return os.Remove("db.test") }
	_ = cleanup()

	state, err := sqlite.New("db.test", "test_password")
	if err != nil {
		t.Fatal(err)
	}
	state.DebugLog = fdotest.TestingLog(t)

	// Add manufacturer keys
	rsa2048MfgKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsa3072MfgKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	ec256MfgKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec384MfgKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for keyType, key := range map[protocol.KeyType]crypto.Signer{
		protocol.Rsa2048RestrKeyType: rsa2048MfgKey,
		protocol.RsaPkcsKeyType:      rsa3072MfgKey,
		protocol.RsaPssKeyType:       rsa3072MfgKey,
		protocol.Secp256r1KeyType:    ec256MfgKey,
		protocol.Secp384r1KeyType:    ec384MfgKey,
	} {
		chain, err := generateCA(key)
		if err != nil {
			t.Fatal(err)
		}
		if err := state.AddManufacturerKey(keyType, key, chain); err != nil {
			t.Fatal(err)
		}
	}

	// Add owner keys
	rsa2048OwnerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsa3072OwnerKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	ec256OwnerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec384OwnerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	for keyType, key := range map[protocol.KeyType]crypto.Signer{
		protocol.Rsa2048RestrKeyType: rsa2048OwnerKey,
		protocol.RsaPkcsKeyType:      rsa3072OwnerKey,
		protocol.RsaPssKeyType:       rsa3072OwnerKey,
		protocol.Secp256r1KeyType:    ec256OwnerKey,
		protocol.Secp384r1KeyType:    ec384OwnerKey,
	} {
		chain, err := generateCA(key)
		if err != nil {
			t.Fatal(err)
		}
		if err := state.AddOwnerKey(keyType, key, chain); err != nil {
			t.Fatal(err)
		}
	}

	return state, cleanup
}

func generateCA(key crypto.Signer) ([]*x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}
