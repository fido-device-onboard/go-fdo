// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdotest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"iter"
	"log/slog"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/blob"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/fdotest/internal/memory"
	"github.com/fido-device-onboard/go-fdo/fdotest/internal/token"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

const timeout = 10 * time.Second

// OwnerModulesFunc creates an iterator of service info modules for a given
// device.
type OwnerModulesFunc func(ctx context.Context, replacementGUID fdo.GUID, info string, chain []*x509.Certificate, devmod fdo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule]

// RunClientTestSuite is used to test different implementations of server state
// methods at an almost end-to-end level (transport is mocked).
//
// The server state implementation must auto-extend vouchers so that TO2 can
// occur immediately after DI. It also must NOT remove vouchers after TO2 so
// that TO2 may occur with the same device many times in succession.
//
// If state is nil, then an in-memory implementation will be used. This is
// useful for only testing service info modules.
//
//nolint:gocyclo
func RunClientTestSuite(t *testing.T, state AllServerState, deviceModules map[string]serviceinfo.DeviceModule, ownerModules OwnerModulesFunc, customExpect func(*testing.T, error)) {
	slog.SetDefault(slog.New(slog.NewTextHandler(TestingLog(t), &slog.HandlerOptions{Level: slog.LevelDebug})))

	if state == nil {
		stateless, err := token.NewService()
		if err != nil {
			t.Fatal(err)
		}

		inMemory, err := memory.NewState()
		if err != nil {
			t.Fatal(err)
		}
		inMemory.AutoExtend = stateless
		inMemory.PreserveReplacedVouchers = true

		state = struct {
			*token.Service
			*memory.State
		}{stateless, inMemory}
	}

	transport := &Transport{
		Tokens: state,
		DIResponder: &fdo.DIServer{
			Session:  state,
			Vouchers: state,
			RvInfo: func(context.Context, *fdo.Voucher) ([][]fdo.RvInstruction, error) {
				return [][]fdo.RvInstruction{}, nil
			},
		},
		TO0Responder: &fdo.TO0Server{
			Session: state,
			RVBlobs: state,
		},
		TO1Responder: &fdo.TO1Server{
			Session: state,
			RVBlobs: state,
		},
		TO2Responder: &fdo.TO2Server{
			Session:   state,
			Vouchers:  state,
			OwnerKeys: state,
			RvInfo: func(context.Context, *fdo.Voucher) ([][]fdo.RvInstruction, error) {
				return [][]fdo.RvInstruction{}, nil
			},
			OwnerModules: func(ctx context.Context, replacementGUID fdo.GUID, info string, chain []*x509.Certificate, devmod fdo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
				if ownerModules == nil {
					return func(yield func(string, serviceinfo.OwnerModule) bool) {}
				}

				mods := ownerModules(ctx, replacementGUID, info, chain, devmod, supportedMods)
				return func(yield func(string, serviceinfo.OwnerModule) bool) {
					for modName, mod := range mods {
						if slices.Contains(supportedMods, modName) {
							if !yield(modName, mod) {
								return
							}
						}
					}
				}
			},
		},
		T: t,
	}
	dnsAddr := "owner.fidoalliance.org"

	to0 := &fdo.TO0Client{
		Transport: transport,
		Addrs: []fdo.RvTO2Addr{
			{
				DNSAddress:        &dnsAddr,
				Port:              8080,
				TransportProtocol: fdo.HTTPTransport,
			},
		},
		Vouchers:  state,
		OwnerKeys: state,
	}

	cli := &fdo.Client{
		Transport: transport,
		Cred:      fdo.DeviceCredential{Version: 101},
		Devmod: fdo.Devmod{
			Os:      runtime.GOOS,
			Arch:    runtime.GOARCH,
			Version: "Debian Bookworm",
			Device:  "go-validation",
			FileSep: ";",
			Bin:     runtime.GOARCH,
		},
		KeyExchange: kex.ECDH256Suite,
		CipherSuite: kex.A128GcmCipher,
	}

	for _, table := range []struct {
		keyType     fdo.KeyType
		keyEncoding fdo.KeyEncoding
	}{
		{
			keyType:     fdo.Secp256r1KeyType,
			keyEncoding: fdo.X509KeyEnc,
		},
		{
			keyType:     fdo.Secp384r1KeyType,
			keyEncoding: fdo.X509KeyEnc,
		},
		{
			keyType:     fdo.RsaPkcsKeyType,
			keyEncoding: fdo.X509KeyEnc,
		},
		{
			keyType:     fdo.RsaPssKeyType,
			keyEncoding: fdo.X509KeyEnc,
		},
		{
			keyType:     fdo.Secp256r1KeyType,
			keyEncoding: fdo.X5ChainKeyEnc,
		},
		{
			keyType:     fdo.Secp384r1KeyType,
			keyEncoding: fdo.X5ChainKeyEnc,
		},
	} {
		t.Run("Key "+table.keyType.String()+" "+table.keyEncoding.String(), func(t *testing.T) {
			t.Run("Device Initialization", func(t *testing.T) {
				secret := make([]byte, 32)
				if _, err := rand.Read(secret); err != nil {
					t.Fatalf("error generating device secret: %v", err)
				}
				cli.Hmac = blob.Hmac(secret)

				var key crypto.Signer
				switch table.keyType {
				case fdo.Secp256r1KeyType:
					var err error
					key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					if err != nil {
						t.Fatalf("error generating device key: %v", err)
					}

				case fdo.Secp384r1KeyType:
					var err error
					key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
					if err != nil {
						t.Fatalf("error generating device key: %v", err)
					}

				case fdo.RsaPkcsKeyType:
					var err error
					key, err = rsa.GenerateKey(rand.Reader, 2048)
					if err != nil {
						t.Fatalf("error generating device key: %v", err)
					}

				case fdo.RsaPssKeyType:
					var err error
					key, err = rsa.GenerateKey(rand.Reader, 3072)
					if err != nil {
						t.Fatalf("error generating device key: %v", err)
					}
					cli.PSS = true

				default:
					panic("unsupported key type " + table.keyType.String())
				}
				cli.Key = key

				// Generate Java implementation-compatible mfg string
				csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
					Subject: pkix.Name{CommonName: "device.go-fdo"},
				}, key)
				if err != nil {
					t.Fatalf("error creating CSR for device certificate chain: %v", err)
				}
				csr, err := x509.ParseCertificateRequest(csrDER)
				if err != nil {
					t.Fatalf("error parsing CSR for device certificate chain: %v", err)
				}

				// Call the DI server
				serial := make([]byte, 10)
				if _, err := rand.Read(serial); err != nil {
					t.Fatalf("error generating serial: %v", err)
				}
				cred, err := cli.DeviceInitialize(context.TODO(), "", fdo.DeviceMfgInfo{
					KeyType:      table.keyType,
					KeyEncoding:  table.keyEncoding,
					SerialNumber: hex.EncodeToString(serial),
					DeviceInfo:   "gotest",
					CertInfo:     cbor.X509CertificateRequest(*csr),
				})
				if err != nil {
					t.Fatal(err)
				}
				cli.Cred = *cred

				t.Logf("Credential: %s", blob.DeviceCredential{
					Active:           true,
					DeviceCredential: *cred,
					HmacSecret:       []byte(cli.Hmac.(blob.Hmac)),
					PrivateKey:       blob.Pkcs8Key{PrivateKey: cli.Key},
				})
			})

			t.Run("Transfer Ownership 0", func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				if _, err := cli.TransferOwnership1(ctx, ""); !strings.HasSuffix(err.Error(), fdo.ErrNotFound.Error()) {
					t.Fatalf("expected TO1 to fail with no resource found, got %v", err)
				}
				ttl, err := to0.RegisterBlob(ctx, "", cli.Cred.GUID)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("RV Blob TTL: %d seconds", ttl)
			})

			t.Run("Transfer Ownership 1 and Transfer Ownership 2", func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				to1d, err := cli.TransferOwnership1(ctx, "")
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("RV Blob: %+v", to1d)

				newCred, err := cli.TransferOwnership2(ctx, "", to1d, nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("New credential: %s", blob.DeviceCredential{
					Active:           true,
					DeviceCredential: *newCred,
					HmacSecret:       []byte(cli.Hmac.(blob.Hmac)),
					PrivateKey:       blob.Pkcs8Key{PrivateKey: cli.Key},
				})
			})

			t.Run("Transfer Ownership 2 Only", func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				newCred, err := cli.TransferOwnership2(ctx, "", nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("New credential: %s", blob.DeviceCredential{
					Active:           true,
					DeviceCredential: *newCred,
					HmacSecret:       []byte(cli.Hmac.(blob.Hmac)),
					PrivateKey:       blob.Pkcs8Key{PrivateKey: cli.Key},
				})
			})

			t.Run("Transfer Ownership 2 w/ Modules", func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				newCred, err := cli.TransferOwnership2(ctx, "", nil, deviceModules)
				if customExpect != nil {
					customExpect(t, err)
					if err != nil {
						return
					}
				} else if err != nil {
					t.Fatal(err)
				}
				t.Logf("New credential: %s", blob.DeviceCredential{
					Active:           true,
					DeviceCredential: *newCred,
					HmacSecret:       []byte(cli.Hmac.(blob.Hmac)),
					PrivateKey:       blob.Pkcs8Key{PrivateKey: cli.Key},
				})
			})
		})
	}
}
