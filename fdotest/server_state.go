// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdotest

import (
	"bytes"
	"context"
	"crypto"
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
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/fdotest/internal/memory"
	"github.com/fido-device-onboard/go-fdo/fdotest/internal/token"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/testdata"
)

// AllServerState includes all server state interfaces and additional functions
// needed for testing.
type AllServerState interface {
	protocol.TokenService
	fdo.DISessionState
	fdo.TO0SessionState
	fdo.TO1SessionState
	fdo.TO2SessionState
	fdo.RendezvousBlobPersistentState
	fdo.ManufacturerVoucherPersistentState
	fdo.OwnerVoucherPersistentState
	fdo.OwnerKeyPersistentState
	fdo.DelegateKeyPersistentState
	ManufacturerKey(keyType protocol.KeyType) (crypto.Signer, []*x509.Certificate, error)
}

// RunServerStateSuite is used to test different implementations of all server
// state methods.
func RunServerStateSuite(t *testing.T, state AllServerState) { //nolint:gocyclo
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
		var state protocol.TokenService = state

		for _, protocol := range []protocol.Protocol{protocol.DIProtocol, protocol.TO0Protocol, protocol.TO1Protocol, protocol.TO2Protocol} {
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
		token, err := state.NewToken(context.TODO(), protocol.DIProtocol)
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

		// Create a new certificate chain
		mfgCert, mfgKey, err := newCert(nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		devCert, _, err := newCert(mfgCert, mfgKey)
		if err != nil {
			t.Fatal(err)
		}
		chain := []*x509.Certificate{devCert, mfgCert}
		if err := state.SetDeviceCertChain(ctx, chain); err != nil {
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
		var guid protocol.GUID
		if _, err := rand.Read(guid[:]); err != nil {
			t.Fatal(err)
		}
		ovh := &fdo.VoucherHeader{
			Version: 101,
			GUID:    guid,
			RvInfo: [][]protocol.RvInstruction{
				{
					{Variable: protocol.RVBypass},
					{Variable: protocol.RVDns, Value: []byte("owner.fidoalliance.org")},
				},
			},
			DeviceInfo: "something",
			ManufacturerKey: protocol.PublicKey{
				Type:     protocol.RsaPkcsKeyType,
				Encoding: protocol.X509KeyEnc,
				Body:     body,
			},
			CertChainHash: &protocol.Hash{
				Algorithm: protocol.Sha256Hash,
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
		token, err := state.NewToken(context.TODO(), protocol.TO0Protocol)
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
		var nonce protocol.Nonce
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
		token, err := state.NewToken(context.TODO(), protocol.TO1Protocol)
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
		var nonce protocol.Nonce
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
			token, err := state.NewToken(context.TODO(), protocol.TO2Protocol)
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
			var guid protocol.GUID
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

		t.Run("RvInfo", func(t *testing.T) {
			token, err := state.NewToken(context.TODO(), protocol.TO2Protocol)
			if err != nil {
				t.Fatal(err)
			}
			ctx := state.TokenContext(context.TODO(), token)
			defer func() { _ = state.InvalidateToken(ctx) }()

			// Shadow state to limit testable functions
			var state fdo.TO2SessionState = state

			// Check for not found
			if rvInfo, err := state.RvInfo(ctx); !errors.Is(err, fdo.ErrNotFound) {
				t.Fatalf("expected ErrNotFound, got %v: %v", err, rvInfo)
			}

			// Store and retrieve RV info
			rvInfo := [][]protocol.RvInstruction{
				{
					{Variable: protocol.RVProtocol, Value: mustMarshal(t, protocol.HTTPTransport)},
					{Variable: protocol.RVIPAddress, Value: mustMarshal(t, net.IP{127, 0, 0, 1})},
					{Variable: protocol.RVDevPort, Value: mustMarshal(t, 8080)},
				},
			}
			if err := state.SetRvInfo(ctx, rvInfo); err != nil {
				t.Fatal(err)
			}
			got, err := state.RvInfo(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(rvInfo, got) {
				t.Fatal("RV info state did not match expected")
			}
		})

		t.Run("Replacement", func(t *testing.T) {
			token, err := state.NewToken(context.TODO(), protocol.TO2Protocol)
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
			var newGUID protocol.GUID
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
			newHmac := protocol.Hmac{
				Algorithm: protocol.HmacSha256Hash,
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
			token, err := state.NewToken(context.TODO(), protocol.TO2Protocol)
			if err != nil {
				t.Fatal(err)
			}
			ctx := state.TokenContext(context.TODO(), token)
			defer func() { _ = state.InvalidateToken(ctx) }()

			// Shadow state to limit testable functions
			var state fdo.TO2SessionState = state

			// Store and retrieve
			if _, _, err := state.XSession(ctx); !errors.Is(err, fdo.ErrNotFound) {
				t.Fatalf("expected ErrNotFound, got %v", err)
			}
			suite := kex.ECDH256Suite
			sess := suite.New([]byte{}, kex.A128GcmCipher)
			if err := state.SetXSession(ctx, suite, sess); err != nil {
				t.Fatal(err)
			}
			gotSuite, gotSess, err := state.XSession(ctx)
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
			token, err := state.NewToken(context.TODO(), protocol.TO2Protocol)
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
			var proveDeviceNonce protocol.Nonce
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
			var setupDeviceNonce protocol.Nonce
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
			token, err := state.NewToken(context.TODO(), protocol.TO2Protocol)
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
		var guid protocol.GUID
		if _, err := rand.Read(guid[:]); err != nil {
			t.Fatal(err)
		}
		ov := &fdo.Voucher{Header: *cbor.NewBstr(fdo.VoucherHeader{GUID: guid})}
		dnsAddr := "owner.fidoalliance.org"
		fakeHash := sha256.Sum256([]byte("fake blob"))
		expect := cose.Sign1[protocol.To1d, []byte]{
			Payload: cbor.NewByteWrap(protocol.To1d{
				RV: []protocol.RvTO2Addr{
					{
						DNSAddress:        &dnsAddr,
						Port:              8080,
						TransportProtocol: protocol.HTTPTransport,
					},
				},
				To0dHash: protocol.Hash{
					Algorithm: protocol.Sha256Hash,
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
		if _, _, err := state.RVBlob(context.TODO(), guid); !errors.Is(err, fdo.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
		exp := time.Now().Add(time.Hour)
		if err := state.SetRVBlob(context.TODO(), ov, &expect, exp); err != nil {
			t.Fatal(err)
		}
		got, _, err := state.RVBlob(context.TODO(), guid)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(*got, expect) {
			t.Fatalf("expected %+v, got %+v", expect, got)
		}
	})

	t.Run("OwnerVoucherPersistentState", func(t *testing.T) {
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
		var state fdo.OwnerVoucherPersistentState = state

		// Create and retrieve voucher
		if _, err := state.Voucher(context.TODO(), ov.Header.Val.GUID); !errors.Is(err, fdo.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
		if err := state.AddVoucher(context.TODO(), ov); err != nil {
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
		var newGUID protocol.GUID
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
		rsaKey, _, err := state.OwnerKey(protocol.RsaPkcsKeyType)
		if err != nil {
			t.Fatal("RSA owner key", err)
		}
		if _, ok := rsaKey.(*rsa.PrivateKey); !ok {
			t.Fatalf("RSA owner key is an incorrect type: %T", rsaKey)
		}

		// EC
		ecKey, _, err := state.OwnerKey(protocol.Secp256r1KeyType)
		if err != nil {
			t.Fatal("EC owner key", err)
		}
		if _, ok := ecKey.(*ecdsa.PrivateKey); !ok {
			t.Fatalf("EC owner key is an incorrect type: %T", rsaKey)
		}
	})
}

func mustMarshal(t *testing.T, v any) []byte {
	data, err := cbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func newCert(issuer *x509.Certificate, issuerKey crypto.Signer) (*x509.Certificate, crypto.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Issuer:       pkix.Name{CommonName: "CA"},
		Subject:      pkix.Name{CommonName: "CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(30 * 360 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if issuer != nil {
		template.Issuer = issuer.Subject
		template.Subject = pkix.Name{CommonName: "Test Device"}
	} else {
		issuer = template
		issuerKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), issuerKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}
