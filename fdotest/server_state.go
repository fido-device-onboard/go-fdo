// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdotest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/fdotest/internal/memory"
	"github.com/fido-device-onboard/go-fdo/fdotest/internal/token"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/testdata"
)

// AllServerState includes all server state interfaces.
type AllServerState interface {
	fdo.TokenService
	fdo.DISessionState
	fdo.TO0SessionState
	fdo.TO1SessionState
	fdo.TO2SessionState
	fdo.RendezvousBlobPersistentState
	fdo.VoucherPersistentState
	fdo.OwnerKeyPersistentState
}

// RunServerStateSuite is used to test different implementations of all server
// state methods.
//
//nolint:gocyclo
func RunServerStateSuite(t *testing.T, state AllServerState) {
	if state == nil {
		stateless, err := token.NewService()
		if err != nil {
			t.Fatal(err)
		}

		inMemory, err := memory.NewState()
		if err != nil {
			t.Fatal(err)
		}

		state = struct {
			*token.Service
			*memory.State
		}{stateless, inMemory}
	}

	t.Run("TokenService", func(t *testing.T) {
		// Shadow state to limit testable functions
		var state fdo.TokenService = state

		for _, protocol := range []fdo.Protocol{fdo.DIProtocol, fdo.TO0Protocol, fdo.TO1Protocol, fdo.TO2Protocol} {
			token, err := state.NewToken(context.Background(), protocol)
			if err != nil {
				t.Fatalf("error creating token for %s: %v", protocol, err)
			}
			ctx := state.TokenContext(context.Background(), token)
			defer func() { _ = state.InvalidateToken(ctx) }()
			got, _ := state.TokenFromContext(ctx)
			if got != token {
				t.Fatalf("expected token %q, got %q", token, got)
			}
			if err := state.InvalidateToken(ctx); err != nil {
				t.Fatalf("error invalidating token: %v", err)
			}
		}
	})

	t.Run("DISessionState", func(t *testing.T) {
		token, err := state.NewToken(context.TODO(), fdo.DIProtocol)
		if err != nil {
			t.Fatal(err)
		}
		ctx := state.TokenContext(context.TODO(), token)
		defer func() { _ = state.InvalidateToken(ctx) }()

		// Shadow state to limit testable functions
		var state fdo.DISessionState = state

		// Check for not found
		if _, err := state.DeviceCertChain(ctx); !errors.Is(err, fdo.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}

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
		if _, err := state.IncompleteVoucherHeader(ctx); !errors.Is(err, fdo.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
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

	t.Run("TO0SessionState", func(t *testing.T) {
		token, err := state.NewToken(context.TODO(), fdo.TO0Protocol)
		if err != nil {
			t.Fatal(err)
		}
		ctx := state.TokenContext(context.TODO(), token)
		defer func() { _ = state.InvalidateToken(ctx) }()

		// Shadow state to limit testable functions
		var state fdo.TO0SessionState = state

		// Store and retrieve proof nonce
		if _, err := state.TO0SignNonce(ctx); !errors.Is(err, fdo.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
		var nonce fdo.Nonce
		if _, err := rand.Read(nonce[:]); err != nil {
			t.Fatal(err)
		}
		if err := state.SetTO0SignNonce(ctx, nonce); err != nil {
			t.Fatal(err)
		}
		gotNonce, err := state.TO0SignNonce(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(nonce[:], gotNonce[:]) {
			t.Fatal("TO0 sign nonce state did not match expected")
		}
	})

	t.Run("TO1SessionState", func(t *testing.T) {
		token, err := state.NewToken(context.TODO(), fdo.TO1Protocol)
		if err != nil {
			t.Fatal(err)
		}
		ctx := state.TokenContext(context.TODO(), token)
		defer func() { _ = state.InvalidateToken(ctx) }()

		// Shadow state to limit testable functions
		var state fdo.TO1SessionState = state

		// Store and retrieve proof nonce
		if _, err := state.TO1ProofNonce(ctx); !errors.Is(err, fdo.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
		var nonce fdo.Nonce
		if _, err := rand.Read(nonce[:]); err != nil {
			t.Fatal(err)
		}
		if err := state.SetTO1ProofNonce(ctx, nonce); err != nil {
			t.Fatal(err)
		}
		gotNonce, err := state.TO1ProofNonce(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(nonce[:], gotNonce[:]) {
			t.Fatal("TO1 proof nonce state did not match expected")
		}
	})

	t.Run("TO2SessionState", func(t *testing.T) {
		t.Run("GUID", func(t *testing.T) {
			token, err := state.NewToken(context.TODO(), fdo.TO2Protocol)
			if err != nil {
				t.Fatal(err)
			}
			ctx := state.TokenContext(context.TODO(), token)
			defer func() { _ = state.InvalidateToken(ctx) }()

			// Shadow state to limit testable functions
			var state fdo.TO2SessionState = state

			// Check for not found
			if _, err := state.GUID(ctx); !errors.Is(err, fdo.ErrNotFound) {
				t.Fatalf("expected ErrNotFound, got %v", err)
			}

			// Store and retrieve GUID
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

		t.Run("Replacement", func(t *testing.T) {
			token, err := state.NewToken(context.TODO(), fdo.TO2Protocol)
			if err != nil {
				t.Fatal(err)
			}
			ctx := state.TokenContext(context.TODO(), token)
			defer func() { _ = state.InvalidateToken(ctx) }()

			// Shadow state to limit testable functions
			var state fdo.TO2SessionState = state

			// Store and retrieve replacement GUID
			if _, err := state.ReplacementGUID(ctx); !errors.Is(err, fdo.ErrNotFound) {
				t.Fatalf("expected ErrNotFound, got %v", err)
			}
			var newGUID fdo.GUID
			if _, err := rand.Read(newGUID[:]); err != nil {
				t.Fatal(err)
			}

			if err := state.SetReplacementGUID(ctx, newGUID); err != nil {
				t.Fatal(err)
			}
			gotGUID, err := state.ReplacementGUID(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(newGUID[:], gotGUID[:]) {
				t.Fatal("replacement GUID state did not match expected")
			}

			// Store and retrieve replacement Hmac
			if _, err := state.ReplacementHmac(ctx); !errors.Is(err, fdo.ErrNotFound) {
				t.Fatalf("expected ErrNotFound, got %v", err)
			}
			fakeHmac := hmac.New(sha256.New, []byte("fake key"))
			_, _ = fakeHmac.Write([]byte("fake voucher header"))
			newHmac := fdo.Hmac{
				Algorithm: fdo.HmacSha256Hash,
				Value:     fakeHmac.Sum(nil),
			}
			if err := state.SetReplacementHmac(ctx, newHmac); err != nil {
				t.Fatal(err)
			}
			gotHmac, err := state.ReplacementHmac(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(newHmac.Value, gotHmac.Value) {
				t.Fatal("replacement hmac state did not match expected")
			}
		})

		t.Run("KeyExchangeState", func(t *testing.T) {
			token, err := state.NewToken(context.TODO(), fdo.TO2Protocol)
			if err != nil {
				t.Fatal(err)
			}
			ctx := state.TokenContext(context.TODO(), token)
			defer func() { _ = state.InvalidateToken(ctx) }()
			getToken := func() string {
				newToken, _ := state.TokenFromContext(ctx)
				return newToken
			}

			// Shadow state to limit testable functions
			var state fdo.TO2SessionState = state

			// Store and retrieve
			if _, _, err := state.Session(ctx, getToken()); !errors.Is(err, fdo.ErrNotFound) {
				t.Fatalf("expected ErrNotFound, got %v", err)
			}
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

		t.Run("Nonces", func(t *testing.T) {
			token, err := state.NewToken(context.TODO(), fdo.TO2Protocol)
			if err != nil {
				t.Fatal(err)
			}
			ctx := state.TokenContext(context.TODO(), token)
			defer func() { _ = state.InvalidateToken(ctx) }()

			// Shadow state to limit testable functions
			var state fdo.TO2SessionState = state

			// Store and retrieve
			if _, err := state.ProveDeviceNonce(ctx); !errors.Is(err, fdo.ErrNotFound) {
				t.Fatalf("expected ErrNotFound, got %v", err)
			}
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

			if _, err := state.SetupDeviceNonce(ctx); !errors.Is(err, fdo.ErrNotFound) {
				t.Fatalf("expected ErrNotFound, got %v", err)
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

		t.Run("MTU", func(t *testing.T) {
			token, err := state.NewToken(context.TODO(), fdo.TO2Protocol)
			if err != nil {
				t.Fatal(err)
			}
			ctx := state.TokenContext(context.TODO(), token)
			defer func() { _ = state.InvalidateToken(ctx) }()

			// Shadow state to limit testable functions
			var state fdo.TO2SessionState = state

			// Store and retrieve
			if _, err := state.MTU(ctx); !errors.Is(err, fdo.ErrNotFound) {
				t.Fatalf("expected ErrNotFound, got %v", err)
			}
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
	})

	t.Run("RendezvousBlobPersistentState", func(t *testing.T) {
		var guid fdo.GUID
		if _, err := rand.Read(guid[:]); err != nil {
			t.Fatal(err)
		}
		dnsAddr := "owner.fidoalliance.org"
		fakeHash := sha256.Sum256([]byte("fake blob"))
		expect := cose.Sign1[fdo.To1d, []byte]{
			Payload: cbor.NewByteWrap(fdo.To1d{
				RV: []fdo.RvTO2Addr{
					{
						DNSAddress:        &dnsAddr,
						Port:              8080,
						TransportProtocol: fdo.HTTPTransport,
					},
				},
				To0dHash: fdo.Hash{
					Algorithm: fdo.Sha256Hash,
					Value:     fakeHash[:],
				},
			}),
		}
		testKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := expect.Sign(testKey, nil, nil, nil); err != nil {
			t.Fatal(err)
		}

		// Shadow state to limit testable functions
		var state fdo.RendezvousBlobPersistentState = state

		// Store and retrieve rendezvous blob
		if _, err := state.RVBlob(context.TODO(), guid); !errors.Is(err, fdo.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
		exp := time.Now().Add(time.Hour)
		if err := state.SetRVBlob(context.TODO(), guid, &expect, exp); err != nil {
			t.Fatal(err)
		}
		got, err := state.RVBlob(context.TODO(), guid)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(*got, expect) {
			t.Fatalf("expected %+v, got %+v", expect, got)
		}
	})

	t.Run("VoucherPersistentState", func(t *testing.T) {
		// Parse ownership voucher from testdata
		b, err := testdata.Files.ReadFile("ov.pem")
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
		if _, err := state.Voucher(context.TODO(), ov.Header.Val.GUID); !errors.Is(err, fdo.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
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
		if _, err := state.Voucher(context.TODO(), oldGUID); !errors.Is(err, fdo.ErrNotFound) {
			t.Fatalf("replaced voucher GUID should return not found, got error %v", err)
		}
		if _, err := state.Voucher(context.TODO(), newGUID); err != nil {
			t.Fatal(err)
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
}
