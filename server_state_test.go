// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/internal/memory"
	"github.com/fido-device-onboard/go-fdo/internal/token"
	"github.com/fido-device-onboard/go-fdo/kex"
)

func TestServerState(t *testing.T) {
	stateless, err := token.NewService()
	if err != nil {
		t.Fatal(err)
	}
	inMemory, err := memory.NewState()
	if err != nil {
		t.Fatal(err)
	}
	state := struct {
		fdo.TokenService
		fdo.VoucherCreationState
		fdo.VoucherProofState
		fdo.VoucherPersistentState
		fdo.VoucherReplacementState
		fdo.KeyExchangeState
		fdo.NonceState
		fdo.OwnerKeyPersistentState
		fdo.ServiceInfoState
	}{
		TokenService:            stateless,
		VoucherCreationState:    stateless,
		VoucherProofState:       stateless,
		VoucherPersistentState:  inMemory,
		VoucherReplacementState: stateless,
		KeyExchangeState:        stateless,
		NonceState:              stateless,
		OwnerKeyPersistentState: inMemory,
		ServiceInfoState:        stateless,
	}

	t.Run("TokenService", func(t *testing.T) {
		// Shadow state to limit testable functions
		var state fdo.TokenService = state

		for _, protocol := range []fdo.Protocol{fdo.DIProtocol, fdo.TO1Protocol, fdo.TO2Protocol} {
			token, err := state.NewToken(context.Background(), protocol)
			if err != nil {
				t.Fatalf("error creating token for %s: %v", protocol, err)
			}
			ctx := state.TokenContext(context.Background(), token)
			got, _ := state.TokenFromContext(ctx)
			if got != token {
				t.Fatalf("expected token %q, got %q", token, got)
			}
			if err := state.InvalidateToken(ctx); err != nil {
				t.Fatalf("error invalidating token: %v", err)
			}
		}
	})

	t.Run("VoucherCreationState", func(t *testing.T) {
		token, err := state.NewToken(context.TODO(), fdo.DIProtocol)
		if err != nil {
			t.Fatal(err)
		}
		ctx := state.TokenContext(context.TODO(), token)

		// Shadow state to limit testable functions
		var state fdo.VoucherCreationState = state

		// Create a CSR
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		asn1Data, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "Test Device"},
		}, priv)
		if err != nil {
			t.Fatal(err)
		}
		csr, err := x509.ParseCertificateRequest(asn1Data)
		if err != nil {
			t.Fatal(err)
		}

		// Sign a new chain
		chain, err := state.NewDeviceCertChain(ctx, fdo.DeviceMfgInfo{
			KeyType:      fdo.RsaPkcsKeyType,
			KeyEncoding:  fdo.X509KeyEnc,
			SerialNumber: "testserial",
			DeviceInfo:   "something",
			CertInfo:     cbor.X509CertificateRequest(*csr),
		})
		if err != nil {
			t.Fatal(err)
		}

		// Check state against generated chain
		gotChain, err := state.DeviceCertChain(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(chain) != len(gotChain) {
			t.Fatal("device cert chain lengths did not match")
		}
		for i := 0; i < len(chain); i++ {
			if !chain[i].Equal(gotChain[i]) {
				t.Fatalf("device cert chain index %d did not match server state", i)
			}
		}

		// Hash certificate chain
		hash := sha256.New()
		for _, cert := range chain {
			_, _ = hash.Write(cert.Raw)
		}

		// Marshal manufacturer public key
		pub := chain[1].PublicKey
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		body, err := cbor.Marshal(der)
		if err != nil {
			t.Fatal(err)
		}

		// Create OVH
		var guid fdo.GUID
		if _, err := rand.Read(guid[:]); err != nil {
			t.Fatal(err)
		}
		ovh := &fdo.VoucherHeader{
			Version: 101,
			GUID:    guid,
			RvInfo: [][]fdo.RvInstruction{
				{
					{Variable: fdo.RVBypass},
					{Variable: fdo.RVDns, Value: []byte("owner.fidoalliance.org")},
				},
			},
			DeviceInfo: "something",
			ManufacturerKey: fdo.PublicKey{
				Type:     fdo.RsaPkcsKeyType,
				Encoding: fdo.X509KeyEnc,
				Body:     body,
			},
			CertChainHash: &fdo.Hash{
				Algorithm: fdo.Sha256Hash,
				Value:     hash.Sum(nil),
			},
		}

		// Store and retrieve OVH
		if err := state.SetIncompleteVoucherHeader(ctx, ovh); err != nil {
			t.Fatal(err)
		}
		gotOVH, err := state.IncompleteVoucherHeader(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !ovh.Equal(gotOVH) {
			t.Fatal("incomplete voucher header state does not match expected")
		}
	})

	t.Run("VoucherProofState", func(t *testing.T) {
		token, err := state.NewToken(context.TODO(), fdo.TO2Protocol)
		if err != nil {
			t.Fatal(err)
		}
		ctx := state.TokenContext(context.TODO(), token)

		// Shadow state to limit testable functions
		var state fdo.VoucherProofState = state

		var guid fdo.GUID
		if _, err := rand.Read(guid[:]); err != nil {
			t.Fatal(err)
		}

		if err := state.SetGUID(ctx, guid); err != nil {
			t.Fatal(err)
		}
		got, err := state.GUID(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(guid[:], got[:]) {
			t.Fatal("guid state did not match expected")
		}
	})

	t.Run("VoucherPersistentState", func(t *testing.T) {
		// Parse ownership voucher from testdata
		b, err := os.ReadFile(filepath.Join("testdata", "ov.pem"))
		if err != nil {
			t.Fatalf("error opening voucher test data: %v", err)
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			t.Fatal("voucher contained invalid PEM data")
		}
		ov := new(fdo.Voucher)
		if err := cbor.Unmarshal(blk.Bytes, ov); err != nil {
			t.Fatalf("error parsing voucher test data: %v", err)
		}

		// Shadow state to limit testable functions
		var state fdo.VoucherPersistentState = state

		// Create and retrieve voucher
		if err := state.NewVoucher(context.TODO(), ov); err != nil {
			t.Fatal(err)
		}
		got, err := state.Voucher(context.TODO(), ov.Header.Val.GUID)
		if err != nil {
			t.Fatal(err)
		}
		if !ov.Header.Val.Equal(&got.Header.Val) {
			t.Fatal("state did not match voucher")
		}

		// Change GUID and replace voucher
		var newGUID fdo.GUID
		if _, err := rand.Read(newGUID[:]); err != nil {
			t.Fatal(err)
		}
		oldGUID := ov.Header.Val.GUID
		ov.Header.Val.GUID = newGUID
		if err := state.ReplaceVoucher(context.TODO(), oldGUID, ov); err != nil {
			t.Fatal(err)
		}
		if _, err := state.Voucher(context.TODO(), oldGUID); !errors.Is(err, memory.ErrNotFound) {
			t.Fatalf("replaced voucher GUID should return not found, got error %v", err)
		}
		if _, err := state.Voucher(context.TODO(), newGUID); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("VoucherReplacementState", func(t *testing.T) {
		token, err := state.NewToken(context.TODO(), fdo.TO2Protocol)
		if err != nil {
			t.Fatal(err)
		}
		ctx := state.TokenContext(context.TODO(), token)

		// Shadow state to limit testable functions
		var state fdo.VoucherReplacementState = state

		var newGUID fdo.GUID
		if _, err := rand.Read(newGUID[:]); err != nil {
			t.Fatal(err)
		}

		if err := state.SetReplacementGUID(ctx, newGUID); err != nil {
			t.Fatal(err)
		}
		got, err := state.ReplacementGUID(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(newGUID[:], got[:]) {
			t.Fatal("guid state did not match expected")
		}
	})

	t.Run("KeyExchangeState", func(t *testing.T) {
		token, err := state.NewToken(context.TODO(), fdo.TO2Protocol)
		if err != nil {
			t.Fatal(err)
		}
		ctx := state.TokenContext(context.TODO(), token)
		getToken := func() string {
			newToken, _ := state.TokenFromContext(ctx)
			return newToken
		}

		// Shadow state to limit testable functions
		var state fdo.KeyExchangeState = state

		// Store and retrieve
		suite := kex.ECDH256Suite
		sess := suite.New([]byte{}, kex.A128GcmCipher)
		if err := state.SetSession(ctx, suite, sess); err != nil {
			t.Fatal(err)
		}
		gotSuite, gotSess, err := state.Session(ctx, getToken())
		if err != nil {
			t.Fatal(err)
		}
		if suite != gotSuite {
			t.Fatal("key exchange suite does not match state")
		}
		if !reflect.DeepEqual(sess, gotSess) {
			t.Fatal("key exchange session does not match state")
		}
	})

	t.Run("NonceState", func(t *testing.T) {
		token, err := state.NewToken(context.TODO(), fdo.TO2Protocol)
		if err != nil {
			t.Fatal(err)
		}
		ctx := state.TokenContext(context.TODO(), token)

		// Shadow state to limit testable functions
		var state fdo.NonceState = state

		// Store and retrieve
		var proveDeviceNonce fdo.Nonce
		if _, err := rand.Read(proveDeviceNonce[:]); err != nil {
			t.Fatal(err)
		}
		if err := state.SetProveDeviceNonce(ctx, proveDeviceNonce); err != nil {
			t.Fatal(err)
		}
		gotProveDeviceNonce, err := state.ProveDeviceNonce(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(proveDeviceNonce[:], gotProveDeviceNonce[:]) {
			t.Fatal("prove device nonce state did not match expected")
		}

		var setupDeviceNonce fdo.Nonce
		if _, err := rand.Read(setupDeviceNonce[:]); err != nil {
			t.Fatal(err)
		}
		if err := state.SetSetupDeviceNonce(ctx, setupDeviceNonce); err != nil {
			t.Fatal(err)
		}
		gotSetupDeviceNonce, err := state.SetupDeviceNonce(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(setupDeviceNonce[:], gotSetupDeviceNonce[:]) {
			t.Fatal("setup device nonce state did not match expected")
		}
	})

	t.Run("OwnerKeyPersistentState", func(t *testing.T) {
		// Shadow state to limit testable functions
		var state fdo.OwnerKeyPersistentState = state

		// RSA
		rsaKey, ok := state.Signer(fdo.RsaPkcsKeyType)
		if !ok {
			t.Fatal("RSA owner key not set")
		}
		if _, ok := rsaKey.(*rsa.PrivateKey); !ok {
			t.Fatalf("RSA owner key is an incorrect type: %T", rsaKey)
		}

		// EC
		ecKey, ok := state.Signer(fdo.Secp256r1KeyType)
		if !ok {
			t.Fatal("EC owner key not set")
		}
		if _, ok := ecKey.(*ecdsa.PrivateKey); !ok {
			t.Fatalf("EC owner key is an incorrect type: %T", rsaKey)
		}
	})

	t.Run("ServiceInfoState", func(t *testing.T) {
		token, err := state.NewToken(context.TODO(), fdo.TO2Protocol)
		if err != nil {
			t.Fatal(err)
		}
		ctx := state.TokenContext(context.TODO(), token)

		// Shadow state to limit testable functions
		var state fdo.ServiceInfoState = state

		// Store and retrieve
		mtu := uint16(1300)
		if err := state.SetMTU(ctx, mtu); err != nil {
			t.Fatal(err)
		}
		got, err := state.MTU(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got != mtu {
			t.Fatal("mtu state did not match expected")
		}
	})
}
