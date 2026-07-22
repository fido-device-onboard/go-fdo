// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdotest_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"iter"
	"log/slog"
	"math/big"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/blob"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/custom"
	"github.com/fido-device-onboard/go-fdo/fdotest"
	"github.com/fido-device-onboard/go-fdo/fdotest/internal/memory"
	"github.com/fido-device-onboard/go-fdo/fdotest/internal/token"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// delegationTestCase describes a single delegation E2E scenario.
type delegationTestCase struct {
	name string

	// setupDelegation is called with the owner key for the key type under test.
	// It returns the delegate name, the DelegateKeyPersistentState store, and
	// optionally a separate delegate name+store for TO0. If to0DelegateName is
	// empty, TO0 uses the owner key directly.
	setupDelegation func(t *testing.T, ownerKey crypto.Signer) (
		onboardDelegateName string,
		store fdo.DelegateKeyPersistentState,
	)

	// wantTO2Err, if true, means the TO2 protocol is expected to fail.
	wantTO2Err bool

	// errContains, if non-empty, is checked against the error string.
	errContains string
}

// delegationDelegateKeyStore implements fdo.DelegateKeyPersistentState for E2E tests.
type delegationDelegateKeyStore struct {
	keys   map[string]crypto.Signer
	chains map[string][]*x509.Certificate
}

func (s *delegationDelegateKeyStore) DelegateKey(name string) (crypto.Signer, []*x509.Certificate, error) {
	key, ok := s.keys[name]
	if !ok {
		return nil, nil, fmt.Errorf("delegate key %q not found", name)
	}
	chain, ok := s.chains[name]
	if !ok {
		return nil, nil, fmt.Errorf("delegate chain %q not found", name)
	}
	return key, chain, nil
}

// TestDelegationE2E_TO2v200 exercises the full DI -> TO0 -> TO1 -> TO2 protocol
// flow with FDO 2.0 delegation enabled on the TO2 server. This is the critical
// missing integration test: it verifies that when TO2Server.OnboardDelegate is
// configured with a delegate name and DelegateKeys provides the corresponding
// key material, the server signs ProveOVHdr20 (type 83) with the delegate key,
// includes the delegate chain in COSE unprotected headers (label 258), and the
// client successfully validates the chain and completes onboarding.
//
// Table-driven test cases cover:
//   - Single-level delegation (owner -> leaf delegate)
//   - Multi-level delegation (owner -> intermediate -> leaf delegate)
//   - Permission enforcement (delegate without onboard permission is rejected)
func TestDelegationE2E_TO2v200(t *testing.T) {
	tests := []delegationTestCase{
		{
			name: "single-level delegation with onboard permission",
			setupDelegation: func(t *testing.T, ownerKey crypto.Signer) (string, fdo.DelegateKeyPersistentState) {
				t.Helper()

				leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					t.Fatalf("failed to generate leaf delegate key: %v", err)
				}

				leafCert, err := fdo.GenerateDelegate(
					ownerKey,
					fdo.DelegateFlagRoot,
					leafKey.Public(),
					"E2E-LeafDelegate",
					"E2E-Owner",
					[]asn1.ObjectIdentifier{fdo.OIDPermitOnboardNewCred},
					x509.ECDSAWithSHA384,
				)
				if err != nil {
					t.Fatalf("failed to generate leaf delegate cert: %v", err)
				}

				store := &delegationDelegateKeyStore{
					keys:   map[string]crypto.Signer{"onboard-leaf": leafKey},
					chains: map[string][]*x509.Certificate{"onboard-leaf": {leafCert}},
				}
				return "onboard-leaf", store
			},
		},
		{
			name: "multi-level delegation owner to intermediate to leaf",
			setupDelegation: func(t *testing.T, ownerKey crypto.Signer) (string, fdo.DelegateKeyPersistentState) {
				t.Helper()

				intermediateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					t.Fatalf("failed to generate intermediate delegate key: %v", err)
				}
				leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					t.Fatalf("failed to generate leaf delegate key: %v", err)
				}

				permissions := []asn1.ObjectIdentifier{
					fdo.OIDPermitOnboardNewCred,
					fdo.OIDPermitOnboardReuseCred,
				}

				intermediateCert, err := fdo.GenerateDelegate(
					ownerKey,
					fdo.DelegateFlagRoot|fdo.DelegateFlagIntermediate,
					intermediateKey.Public(),
					"E2E-Intermediate",
					"E2E-Owner",
					permissions,
					x509.ECDSAWithSHA384,
				)
				if err != nil {
					t.Fatalf("failed to generate intermediate delegate cert: %v", err)
				}

				leafCert, err := fdo.GenerateDelegate(
					intermediateKey,
					fdo.DelegateFlagLeaf,
					leafKey.Public(),
					"E2E-LeafDelegate",
					"E2E-Intermediate",
					permissions,
					x509.ECDSAWithSHA384,
				)
				if err != nil {
					t.Fatalf("failed to generate leaf delegate cert: %v", err)
				}

				// Chain is ordered leaf-first as required by DelegateKeyPersistentState
				store := &delegationDelegateKeyStore{
					keys:   map[string]crypto.Signer{"onboard-multi": leafKey},
					chains: map[string][]*x509.Certificate{"onboard-multi": {leafCert, intermediateCert}},
				}
				return "onboard-multi", store
			},
		},
		{
			name: "delegate without onboard permission is rejected",
			setupDelegation: func(t *testing.T, ownerKey crypto.Signer) (string, fdo.DelegateKeyPersistentState) {
				t.Helper()

				leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					t.Fatalf("failed to generate leaf delegate key: %v", err)
				}

				// Only redirect permission -- no onboard permission
				leafCert, err := fdo.GenerateDelegate(
					ownerKey,
					fdo.DelegateFlagRoot,
					leafKey.Public(),
					"E2E-RedirectOnly",
					"E2E-Owner",
					[]asn1.ObjectIdentifier{fdo.OIDPermitRedirect},
					x509.ECDSAWithSHA384,
				)
				if err != nil {
					t.Fatalf("failed to generate redirect-only delegate cert: %v", err)
				}

				store := &delegationDelegateKeyStore{
					keys:   map[string]crypto.Signer{"redirect-only": leafKey},
					chains: map[string][]*x509.Certificate{"redirect-only": {leafCert}},
				}
				return "redirect-only", store
			},
			wantTO2Err:  true,
			errContains: "onboarding permission",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runDelegationE2E(t, tt)
		})
	}
}

// runDelegationE2E executes a single delegation E2E test case. It mirrors the
// infrastructure setup of fdotest.RunClientTestSuite but constructs the servers
// manually so that delegation can be configured on the TO2Server.
//
// The test uses EC P-384 (Secp384r1KeyType) as the key type, ECDH384 for key
// exchange, and A128GCM for the cipher suite. These are the most common
// parameters for FDO 2.0 deployments.
func runDelegationE2E(t *testing.T, tc delegationTestCase) {
	t.Helper()

	slog.SetDefault(slog.New(slog.NewTextHandler(fdotest.TestingLog(t), &slog.HandlerOptions{Level: slog.LevelDebug})))

	// ---------------------------------------------------------------
	// 1. Create server state (token service + persistent state)
	// ---------------------------------------------------------------
	tokenSvc, err := token.NewService()
	if err != nil {
		t.Fatalf("failed to create token service: %v", err)
	}
	memState, err := memory.NewState()
	if err != nil {
		t.Fatalf("failed to create memory state: %v", err)
	}

	// Combine into an AllServerState-compatible struct
	state := struct {
		*token.Service
		*memory.State
	}{tokenSvc, memState}

	// ---------------------------------------------------------------
	// 2. Get the owner key for EC P-384 and set up delegation
	// ---------------------------------------------------------------
	const keyType = protocol.Secp384r1KeyType
	const rsaBits = 0 // ignored for EC keys

	ownerKey, _, err := state.OwnerKey(context.Background(), keyType, rsaBits)
	if err != nil {
		t.Fatalf("failed to get owner key: %v", err)
	}

	onboardDelegateName, delegateStore := tc.setupDelegation(t, ownerKey)

	// ---------------------------------------------------------------
	// 3. Generate Device CA for signing device CSRs during DI
	// ---------------------------------------------------------------
	deviceCAKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("failed to generate device CA key: %v", err)
	}
	deviceCATemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Delegation E2E Device CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	deviceCADER, err := x509.CreateCertificate(rand.Reader, deviceCATemplate, deviceCATemplate, deviceCAKey.Public(), deviceCAKey)
	if err != nil {
		t.Fatalf("failed to create device CA certificate: %v", err)
	}
	deviceCACert, err := x509.ParseCertificate(deviceCADER)
	if err != nil {
		t.Fatalf("failed to parse device CA certificate: %v", err)
	}
	deviceCAChain := []*x509.Certificate{deviceCACert}

	// ---------------------------------------------------------------
	// 4. Create protocol servers (DI, TO0, TO1, TO2)
	// ---------------------------------------------------------------
	diResponder := &fdo.DIServer[custom.DeviceMfgInfo]{
		Session:               state,
		Vouchers:              state,
		SignDeviceCertificate: custom.SignDeviceCertificate(deviceCAKey, deviceCAChain),
		DeviceInfo: func(ctx context.Context, info *custom.DeviceMfgInfo, devChain []*x509.Certificate) (string, protocol.PublicKey, error) {
			mfgKey, mfgChain, err := state.ManufacturerKey(ctx, info.KeyType, rsaBits)
			if err != nil {
				return "", protocol.PublicKey{}, fmt.Errorf("error getting manufacturer key: %w", err)
			}

			var mfgPubKey *protocol.PublicKey
			switch info.KeyEncoding {
			case protocol.X509KeyEnc, protocol.CoseKeyEnc:
				mfgPubKey, err = protocol.NewPublicKey(info.KeyType, mfgKey.Public().(*ecdsa.PublicKey), info.KeyEncoding == protocol.CoseKeyEnc)
			case protocol.X5ChainKeyEnc:
				mfgPubKey, err = protocol.NewPublicKey(info.KeyType, mfgChain, false)
			default:
				err = fmt.Errorf("unsupported key encoding: %s", info.KeyEncoding)
			}
			if err != nil {
				return "", protocol.PublicKey{}, err
			}
			return "delegation_e2e_device", *mfgPubKey, nil
		},
		RvInfo: func(context.Context, *fdo.Voucher) ([][]protocol.RvInstruction, error) {
			return [][]protocol.RvInstruction{}, nil
		},
	}

	to0Responder := &fdo.TO0Server{
		Session: state,
		RVBlobs: state,
	}

	to1Responder := &fdo.TO1Server{
		Session: state,
		RVBlobs: state,
	}

	noopModules := func(context.Context, protocol.GUID, string, []*x509.Certificate, serviceinfo.Devmod, []string) iter.Seq2[string, serviceinfo.OwnerModule] {
		return func(yield func(string, serviceinfo.OwnerModule) bool) {}
	}

	to2Responder := &fdo.TO2Server{
		Session: state,
		Modules: &delegationModuleStateMachine{
			Session:      state,
			Vouchers:     state,
			OwnerModules: noopModules,
		},
		Vouchers:             state,
		OwnerKeys:            state,
		VouchersForExtension: state,
		RvInfo: func(context.Context, fdo.Voucher) ([][]protocol.RvInstruction, error) {
			return [][]protocol.RvInstruction{}, nil
		},
		ReuseCredential: func(context.Context, fdo.Voucher) (bool, error) { return false, nil },
		VerifyVoucher:   func(context.Context, fdo.Voucher) error { return nil },

		// Configure delegation on the TO2 server
		DelegateKeys:    delegateStore,
		OnboardDelegate: onboardDelegateName,
	}

	// ---------------------------------------------------------------
	// 5. Create the test transport
	// ---------------------------------------------------------------
	transport := &fdotest.Transport{
		Tokens:       state,
		DIResponder:  diResponder,
		TO0Responder: to0Responder,
		TO1Responder: to1Responder,
		TO2Responder: to2Responder,
		T:            t,
	}

	// ---------------------------------------------------------------
	// 6. Create device credentials (key, HMAC secrets)
	// ---------------------------------------------------------------
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("error generating device secret: %v", err)
	}
	hmacSha256 := hmac.New(sha256.New, secret)
	hmacSha384 := hmac.New(sha512.New384, secret)

	deviceKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("error generating device key: %v", err)
	}

	toDeviceCred := func(dc fdo.DeviceCredential) any {
		return blob.DeviceCredential{
			Active:           true,
			DeviceCredential: dc,
			HmacSecret:       secret,
			PrivateKey:       blob.Pkcs8Key{Signer: deviceKey},
		}
	}

	// ---------------------------------------------------------------
	// 7. DI: Device Initialization
	// ---------------------------------------------------------------
	t.Run("DI", func(t *testing.T) {
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "delegation-e2e-device.go-fdo"},
		}, deviceKey)
		if err != nil {
			t.Fatalf("error creating CSR: %v", err)
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			t.Fatalf("error parsing CSR: %v", err)
		}

		serial := make([]byte, 10)
		if _, err := rand.Read(serial); err != nil {
			t.Fatalf("error generating serial: %v", err)
		}

		cred, diErr := fdo.DI(context.TODO(), transport, custom.DeviceMfgInfo{
			KeyType:      keyType,
			KeyEncoding:  protocol.X509KeyEnc,
			SerialNumber: hex.EncodeToString(serial),
			DeviceInfo:   "delegation-e2e-test",
			CertInfo:     cbor.X509CertificateRequest(*csr),
		}, fdo.DIConfig{
			HmacSha256: hmacSha256,
			HmacSha384: hmacSha384,
			Key:        deviceKey,
		})
		if diErr != nil {
			t.Fatalf("DI failed: %v", diErr)
		}
		t.Logf("DI complete, credential: %s", toDeviceCred(*cred))

		// Auto-extend the voucher so it has at least one entry
		diResponder.BeforeVoucherPersist = fdo.AllInOne{DIAndOwner: state}.Extend

		// Run DI again with auto-extend to get a properly extended voucher
		hmacSha256.Reset()
		hmacSha384.Reset()
		serial2 := make([]byte, 10)
		if _, err := rand.Read(serial2); err != nil {
			t.Fatalf("error generating serial: %v", err)
		}
		csrDER2, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "delegation-e2e-device.go-fdo"},
		}, deviceKey)
		if err != nil {
			t.Fatalf("error creating CSR: %v", err)
		}
		csr2, err := x509.ParseCertificateRequest(csrDER2)
		if err != nil {
			t.Fatalf("error parsing CSR: %v", err)
		}

		cred, diErr = fdo.DI(context.TODO(), transport, custom.DeviceMfgInfo{
			KeyType:      keyType,
			KeyEncoding:  protocol.X509KeyEnc,
			SerialNumber: hex.EncodeToString(serial2),
			DeviceInfo:   "delegation-e2e-test",
			CertInfo:     cbor.X509CertificateRequest(*csr2),
		}, fdo.DIConfig{
			HmacSha256: hmacSha256,
			HmacSha384: hmacSha384,
			Key:        deviceKey,
		})
		if diErr != nil {
			t.Fatalf("DI with auto-extend failed: %v", diErr)
		}

		// Store credential for subsequent protocol phases
		t.Logf("DI with auto-extend complete, credential GUID: %x", cred.GUID)
		delegationE2ESetCred(t, cred)
	})

	// ---------------------------------------------------------------
	// 8. TO0: Register the device with the rendezvous server
	// ---------------------------------------------------------------
	t.Run("TO0", func(t *testing.T) {
		cred := delegationE2EGetCred(t)

		to0Client := &fdo.TO0Client{
			Vouchers:  state,
			OwnerKeys: state,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		dnsAddr := "owner.fidoalliance.org"
		ttl, err := to0Client.RegisterBlob(ctx, transport, cred.GUID, []protocol.RvTO2Addr{
			{
				DNSAddress:        &dnsAddr,
				Port:              8080,
				TransportProtocol: protocol.HTTPTransport,
			},
		}, "")
		if err != nil {
			t.Fatalf("TO0 RegisterBlob failed: %v", err)
		}
		t.Logf("TO0 complete, TTL: %d seconds", ttl)
	})

	// ---------------------------------------------------------------
	// 9. TO1 + TO2: Transfer Ownership
	// ---------------------------------------------------------------
	t.Run("TO1 and TO2 with delegation", func(t *testing.T) {
		cred := delegationE2EGetCred(t)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// TO1: Discover owner
		to1d, err := fdo.TO1(ctx, transport, *cred, deviceKey, nil)
		if err != nil {
			t.Fatalf("TO1 failed: %v", err)
		}
		t.Logf("TO1 complete, got RV blob")

		// TO2 v2.0: Onboard with delegation
		// Reset HMACs for the new protocol run
		hmacSha256.Reset()
		hmacSha384.Reset()

		newCred, to2Err := fdo.TO2v200(ctx, transport, to1d, fdo.TO2Config{
			Cred:       *cred,
			HmacSha256: hmacSha256,
			HmacSha384: hmacSha384,
			Key:        deviceKey,
			Devmod: serviceinfo.Devmod{
				Os:      runtime.GOOS,
				Arch:    runtime.GOARCH,
				Version: "Delegation-E2E",
				Device:  "go-fdo-delegation-test",
				FileSep: ";",
				Bin:     runtime.GOARCH,
			},
			KeyExchange: kex.ECDH384Suite,
			CipherSuite: kex.A128GcmCipher,
		})

		if tc.wantTO2Err {
			if to2Err == nil {
				t.Fatal("expected TO2 to fail with delegation error, but it succeeded")
			}
			if tc.errContains != "" && !strings.Contains(to2Err.Error(), tc.errContains) {
				t.Fatalf("TO2 error %q does not contain expected substring %q", to2Err.Error(), tc.errContains)
			}
			t.Logf("TO2 correctly rejected: %v", to2Err)
			return
		}

		if to2Err != nil {
			t.Fatalf("TO2 v2.0 with delegation failed: %v", to2Err)
		}

		if newCred == nil {
			t.Fatal("expected new credential from TO2, got nil (credential reuse not expected)")
		}
		t.Logf("TO2 v2.0 with delegation complete, new credential GUID: %x", newCred.GUID)
	})
}

// delegationE2E credential passing between sub-tests.
// We use t.Setenv-style approach via test-local context, but since Go sub-tests
// share the parent scope, we use a simple closure pattern.
var delegationE2ECredStore = make(map[string]*fdo.DeviceCredential)

func delegationE2ESetCred(t *testing.T, cred *fdo.DeviceCredential) {
	t.Helper()
	delegationE2ECredStore[t.Name()] = cred
}

func delegationE2EGetCred(t *testing.T) *fdo.DeviceCredential {
	t.Helper()
	// Walk up the test name hierarchy to find the credential stored by DI
	parts := strings.Split(t.Name(), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		parentName := strings.Join(parts[:i], "/")
		diName := parentName + "/DI"
		if cred, ok := delegationE2ECredStore[diName]; ok {
			return cred
		}
	}
	t.Fatal("credential not set -- DI sub-test must run first")
	return nil
}

// delegationModuleStateMachine implements serviceinfo.ModuleStateMachine for
// delegation E2E tests. This is a minimal copy of the to2ModuleStateMachine
// from client.go, needed because that type is unexported.
type delegationModuleStateMachine struct {
	Session  fdo.TO2SessionState
	Vouchers interface {
		fdo.VoucherPersistentState
		fdo.OwnerVoucherPersistentState
	}
	OwnerModules func(ctx context.Context, guid protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, modules []string) iter.Seq2[string, serviceinfo.OwnerModule]

	module *delegationModuleState
}

type delegationModuleState struct {
	Name string
	Impl serviceinfo.OwnerModule
	Next func() (string, serviceinfo.OwnerModule, bool)
	Stop func()
}

func (s *delegationModuleStateMachine) Module(ctx context.Context) (string, serviceinfo.OwnerModule, error) {
	if s.module == nil {
		return "", nil, fmt.Errorf("NextModule never called")
	}
	if s.module.Impl == nil {
		return "", nil, fmt.Errorf("NextModule already returned false")
	}
	return s.module.Name, s.module.Impl, nil
}

func (s *delegationModuleStateMachine) NextModule(ctx context.Context) (bool, error) {
	if s.module != nil {
		var valid bool
		s.module.Name, s.module.Impl, valid = s.module.Next()
		return valid, nil
	}

	guid, err := s.Session.GUID(ctx)
	if err != nil {
		return false, fmt.Errorf("error retrieving device GUID: %w", err)
	}

	ov, err := s.Vouchers.Voucher(ctx, guid)
	if err != nil {
		return false, fmt.Errorf("error retrieving voucher for device %x: %w", guid, err)
	}
	info := ov.Header.Val.DeviceInfo

	replacementGUID, err := s.Session.ReplacementGUID(ctx)
	if err != nil {
		replacementGUID = guid
	}

	devmod, modules, devmodComplete, err := s.Session.Devmod(ctx)
	if err == nil && !devmodComplete {
		return false, fmt.Errorf("devmod did not complete")
	}
	if err != nil {
		return false, fmt.Errorf("error retrieving devmod: %w", err)
	}

	var deviceCertChain []*x509.Certificate
	if ov.CertChain != nil {
		deviceCertChain = make([]*x509.Certificate, len(*ov.CertChain))
		for i, cert := range *ov.CertChain {
			deviceCertChain[i] = (*x509.Certificate)(cert)
		}
	}

	nextModule, stopIter := iter.Pull2(s.OwnerModules(ctx, replacementGUID, info, deviceCertChain, devmod, modules))
	name, impl, valid := nextModule()
	s.module = &delegationModuleState{
		Name: name,
		Impl: impl,
		Next: nextModule,
		Stop: stopIter,
	}
	return valid, nil
}

func (s *delegationModuleStateMachine) CleanupModules(ctx context.Context) {
	if s.module != nil {
		s.module.Stop()
		s.module = nil
	}
}

// Compile-time check that delegationModuleStateMachine satisfies the
// serviceinfo.ModuleStateMachine interface.
var _ serviceinfo.ModuleStateMachine = (*delegationModuleStateMachine)(nil)

// Compile-time check that delegationDelegateKeyStore satisfies the
// fdo.DelegateKeyPersistentState interface.
var _ fdo.DelegateKeyPersistentState = (*delegationDelegateKeyStore)(nil)
