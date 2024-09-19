// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdotest

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
	"encoding/hex"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"math/big"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/blob"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/custom"
	"github.com/fido-device-onboard/go-fdo/fdotest/internal/memory"
	"github.com/fido-device-onboard/go-fdo/fdotest/internal/token"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

const timeout = 10 * time.Second

// OwnerModulesFunc creates an iterator of service info modules for a given
// device.
type OwnerModulesFunc func(ctx context.Context, replacementGUID protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule]

// RunClientTestSuite is used to test different implementations of server state
// methods at an almost end-to-end level (transport is mocked).
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

		state = struct {
			*token.Service
			*memory.State
		}{stateless, inMemory}
	}

	transport := &Transport{
		Tokens: state,
		DIResponder: &fdo.DIServer[custom.DeviceMfgInfo]{
			Session:  state,
			Vouchers: state,
			SignDeviceCertificate: func(info *custom.DeviceMfgInfo) ([]*x509.Certificate, error) {
				// Validate device info
				csr := x509.CertificateRequest(info.CertInfo)
				if err := csr.CheckSignature(); err != nil {
					return nil, fmt.Errorf("invalid CSR: %w", err)
				}

				// Sign CSR
				key, chain, err := state.ManufacturerKey(info.KeyType)
				if err != nil {
					var unsupportedErr fdo.ErrUnsupportedKeyType
					if errors.As(err, &unsupportedErr) {
						return nil, unsupportedErr
					}
					return nil, fmt.Errorf("error retrieving manufacturer key [type=%s]: %w", info.KeyType, err)
				}
				serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
				serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
				if err != nil {
					return nil, fmt.Errorf("error generating certificate serial number: %w", err)
				}
				template := &x509.Certificate{
					SerialNumber: serialNumber,
					Issuer:       chain[0].Subject,
					Subject:      csr.Subject,
					NotBefore:    time.Now(),
					NotAfter:     time.Now().Add(30 * 360 * 24 * time.Hour), // Matches Java impl
					KeyUsage:     x509.KeyUsageDigitalSignature,
				}
				der, err := x509.CreateCertificate(rand.Reader, template, chain[0], csr.PublicKey, key)
				if err != nil {
					return nil, fmt.Errorf("error signing CSR: %w", err)
				}
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					return nil, fmt.Errorf("error parsing signed device cert: %w", err)
				}
				chain = append([]*x509.Certificate{cert}, chain...)
				return chain, nil
			},
			AutoExtend: state,
			RvInfo: func(context.Context, *fdo.Voucher) ([][]protocol.RvInstruction, error) {
				return [][]protocol.RvInstruction{}, nil
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
			RvInfo: func(context.Context, fdo.Voucher) ([][]protocol.RvInstruction, error) {
				return [][]protocol.RvInstruction{}, nil
			},
			OwnerModules: func(ctx context.Context, replacementGUID protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
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
			VerifyVoucher: func(context.Context, fdo.Voucher) error { return nil },
		},
		T: t,
	}

	to0 := &fdo.TO0Client{
		Vouchers:  state,
		OwnerKeys: state,
	}

	for _, table := range []struct {
		keyType     protocol.KeyType
		keyEncoding protocol.KeyEncoding
	}{
		{
			keyType:     protocol.Secp256r1KeyType,
			keyEncoding: protocol.X509KeyEnc,
		},
		{
			keyType:     protocol.Secp384r1KeyType,
			keyEncoding: protocol.X509KeyEnc,
		},
		{
			keyType:     protocol.RsaPkcsKeyType,
			keyEncoding: protocol.X509KeyEnc,
		},
		{
			keyType:     protocol.RsaPssKeyType,
			keyEncoding: protocol.X509KeyEnc,
		},
		{
			keyType:     protocol.Secp256r1KeyType,
			keyEncoding: protocol.X5ChainKeyEnc,
		},
		{
			keyType:     protocol.Secp384r1KeyType,
			keyEncoding: protocol.X5ChainKeyEnc,
		},
	} {
		transport.DIResponder.DeviceInfo = func(context.Context, *custom.DeviceMfgInfo, []*x509.Certificate) (string, protocol.KeyType, protocol.KeyEncoding, error) {
			return "test_device", table.keyType, table.keyEncoding, nil
		}
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			t.Fatalf("error generating device secret: %v", err)
		}

		t.Run("Key "+table.keyType.String()+" "+table.keyEncoding.String(), func(t *testing.T) {
			var key crypto.Signer
			switch table.keyType {
			case protocol.Secp256r1KeyType:
				var err error
				key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("error generating device key: %v", err)
				}

			case protocol.Secp384r1KeyType:
				var err error
				key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					t.Fatalf("error generating device key: %v", err)
				}

			case protocol.RsaPkcsKeyType:
				var err error
				key, err = rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("error generating device key: %v", err)
				}

			case protocol.RsaPssKeyType:
				var err error
				key, err = rsa.GenerateKey(rand.Reader, 3072)
				if err != nil {
					t.Fatalf("error generating device key: %v", err)
				}

			default:
				panic("unsupported key type " + table.keyType.String())
			}

			var cred *fdo.DeviceCredential

			t.Run("Device Initialization", func(t *testing.T) {
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
				cred, err = fdo.DI(context.TODO(), transport, custom.DeviceMfgInfo{
					KeyType:      table.keyType,
					KeyEncoding:  table.keyEncoding,
					SerialNumber: hex.EncodeToString(serial),
					DeviceInfo:   "gotest",
					CertInfo:     cbor.X509CertificateRequest(*csr),
				}, fdo.DIConfig{
					HmacSha256: hmac.New(sha256.New, secret),
					HmacSha384: hmac.New(sha512.New384, secret),
					Key:        key,
					PSS:        table.keyType == protocol.RsaPssKeyType,
				})
				if err != nil {
					t.Fatal(err)
				}

				t.Logf("Credential: %s", blob.DeviceCredential{
					Active:           true,
					DeviceCredential: *cred,
					HmacSecret:       secret,
					PrivateKey:       blob.Pkcs8Key{PrivateKey: key},
				})
			})

			t.Run("Transfer Ownership 0", func(t *testing.T) {
				if cred == nil {
					t.Fatal("cred not set due to previous failure")
				}

				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				if _, err := fdo.TO1(ctx, transport, *cred, key, &fdo.TO1Options{
					PSS: table.keyType == protocol.RsaPssKeyType,
				}); !strings.HasSuffix(err.Error(), fdo.ErrNotFound.Error()) {
					t.Fatalf("expected TO1 to fail with no resource found, got %v", err)
				}
				dnsAddr := "owner.fidoalliance.org"
				ttl, err := to0.RegisterBlob(ctx, transport, cred.GUID, []protocol.RvTO2Addr{
					{
						DNSAddress:        &dnsAddr,
						Port:              8080,
						TransportProtocol: protocol.HTTPTransport,
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("RV Blob TTL: %d seconds", ttl)
			})

			t.Run("Transfer Ownership 1 and Transfer Ownership 2", func(t *testing.T) {
				if cred == nil {
					t.Fatal("cred not set due to previous failure")
				}

				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				to1d, err := fdo.TO1(ctx, transport, *cred, key, &fdo.TO1Options{
					PSS: table.keyType == protocol.RsaPssKeyType,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("RV Blob: %+v", to1d)

				cred, err = fdo.TO2(ctx, transport, to1d, fdo.TO2Config{
					Cred:       *cred,
					HmacSha256: hmac.New(sha256.New, secret),
					HmacSha384: hmac.New(sha512.New384, secret),
					Key:        key,
					PSS:        table.keyType == protocol.RsaPssKeyType,
					Devmod: serviceinfo.Devmod{
						Os:      runtime.GOOS,
						Arch:    runtime.GOARCH,
						Version: "Debian Bookworm",
						Device:  "go-validation",
						FileSep: ";",
						Bin:     runtime.GOARCH,
					},
					KeyExchange: kex.ECDH256Suite,
					CipherSuite: kex.A128GcmCipher,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("New credential: %s", blob.DeviceCredential{
					Active:           true,
					DeviceCredential: *cred,
					HmacSecret:       secret,
					PrivateKey:       blob.Pkcs8Key{PrivateKey: key},
				})
			})

			t.Run("Transfer Ownership 2 Only", func(t *testing.T) {
				if cred == nil {
					t.Fatal("cred not set due to previous failure")
				}

				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				var err error
				cred, err = fdo.TO2(ctx, transport, nil, fdo.TO2Config{
					Cred:       *cred,
					HmacSha256: hmac.New(sha256.New, secret),
					HmacSha384: hmac.New(sha512.New384, secret),
					Key:        key,
					PSS:        table.keyType == protocol.RsaPssKeyType,
					Devmod: serviceinfo.Devmod{
						Os:      runtime.GOOS,
						Arch:    runtime.GOARCH,
						Version: "Debian Bookworm",
						Device:  "go-validation",
						FileSep: ";",
						Bin:     runtime.GOARCH,
					},
					KeyExchange: kex.ECDH256Suite,
					CipherSuite: kex.A128GcmCipher,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("New credential: %s", blob.DeviceCredential{
					Active:           true,
					DeviceCredential: *cred,
					HmacSecret:       secret,
					PrivateKey:       blob.Pkcs8Key{PrivateKey: key},
				})
			})

			t.Run("Transfer Ownership 2 w/ Modules", func(t *testing.T) {
				if cred == nil {
					t.Fatal("cred not set due to previous failure")
				}

				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				newCred, err := fdo.TO2(ctx, transport, nil, fdo.TO2Config{
					Cred:       *cred,
					HmacSha256: hmac.New(sha256.New, secret),
					HmacSha384: hmac.New(sha512.New384, secret),
					Key:        key,
					PSS:        table.keyType == protocol.RsaPssKeyType,
					Devmod: serviceinfo.Devmod{
						Os:      runtime.GOOS,
						Arch:    runtime.GOARCH,
						Version: "Debian Bookworm",
						Device:  "go-validation",
						FileSep: ";",
						Bin:     runtime.GOARCH,
					},
					DeviceModules: deviceModules,
					KeyExchange:   kex.ECDH256Suite,
					CipherSuite:   kex.A128GcmCipher,
				})
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
					HmacSecret:       secret,
					PrivateKey:       blob.Pkcs8Key{PrivateKey: key},
				})
				cred = newCred
			})
		})
	}
}
