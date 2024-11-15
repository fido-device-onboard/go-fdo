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
	"hash"
	"io"
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

// Config provides options to
type Config struct {
	// If state is nil, then an in-memory implementation will be used. This is
	// useful for only testing service info modules.
	State AllServerState

	// If NewCredential is non-nil, then it will be used to create and format
	// the device credential. Otherwise the blob package will be used.
	NewCredential func(protocol.KeyType) (hmacSha256, hmacSha384 hash.Hash, key crypto.Signer, toDeviceCred func(fdo.DeviceCredential) any)

	// Use the Credential Reuse Protocol
	Reuse bool

	DeviceModules map[string]serviceinfo.DeviceModule
	OwnerModules  OwnerModulesFunc

	CustomExpect func(*testing.T, error)
}

// RunClientTestSuite is used to test different implementations of server state
// methods at an almost end-to-end level (transport is mocked).
//
//nolint:gocyclo
func RunClientTestSuite(t *testing.T, conf Config) {
	slog.SetDefault(slog.New(slog.NewTextHandler(TestingLog(t), &slog.HandlerOptions{Level: slog.LevelDebug})))

	if conf.State == nil {
		stateless, err := token.NewService()
		if err != nil {
			t.Fatal(err)
		}

		inMemory, err := memory.NewState()
		if err != nil {
			t.Fatal(err)
		}

		conf.State = struct {
			*token.Service
			*memory.State
		}{stateless, inMemory}
	}

	transport := &Transport{
		Tokens: conf.State,
		DIResponder: &fdo.DIServer[custom.DeviceMfgInfo]{
			Session:  conf.State,
			Vouchers: conf.State,
			SignDeviceCertificate: func(info *custom.DeviceMfgInfo) ([]*x509.Certificate, error) {
				// Validate device info
				csr := x509.CertificateRequest(info.CertInfo)
				if err := csr.CheckSignature(); err != nil {
					return nil, fmt.Errorf("invalid CSR: %w", err)
				}

				// Sign CSR
				key, chain, err := conf.State.ManufacturerKey(info.KeyType)
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
			AutoExtend: conf.State,
			RvInfo: func(context.Context, *fdo.Voucher) ([][]protocol.RvInstruction, error) {
				return [][]protocol.RvInstruction{}, nil
			},
		},
		TO0Responder: &fdo.TO0Server{
			Session: conf.State,
			RVBlobs: conf.State,
		},
		TO1Responder: &fdo.TO1Server{
			Session: conf.State,
			RVBlobs: conf.State,
		},
		TO2Responder: &fdo.TO2Server{
			Session:   conf.State,
			Vouchers:  conf.State,
			OwnerKeys: conf.State,
			RvInfo: func(context.Context, fdo.Voucher) ([][]protocol.RvInstruction, error) {
				return [][]protocol.RvInstruction{}, nil
			},
			OwnerModules: func(ctx context.Context, replacementGUID protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
				if conf.OwnerModules == nil {
					return func(yield func(string, serviceinfo.OwnerModule) bool) {}
				}

				mods := conf.OwnerModules(ctx, replacementGUID, info, chain, devmod, supportedMods)
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
			ReuseCredential: func(context.Context, fdo.Voucher) bool { return conf.Reuse },
			VerifyVoucher:   func(context.Context, fdo.Voucher) error { return nil },
		},
		T: t,
	}

	to0 := &fdo.TO0Client{
		Vouchers:  conf.State,
		OwnerKeys: conf.State,
	}

	for _, table := range []struct {
		keyType     protocol.KeyType
		keyEncoding protocol.KeyEncoding
		keyExchange kex.Suite
		cipherSuite kex.CipherSuiteID
	}{
		{
			keyType:     protocol.Secp256r1KeyType,
			keyEncoding: protocol.X5ChainKeyEnc,
			keyExchange: kex.ECDH256Suite,
			cipherSuite: kex.A128GcmCipher,
		},
		{
			keyType:     protocol.Secp384r1KeyType,
			keyEncoding: protocol.X509KeyEnc,
			keyExchange: kex.ECDH384Suite,
			cipherSuite: kex.A128GcmCipher,
		},
		{
			keyType:     protocol.Rsa2048RestrKeyType,
			keyEncoding: protocol.X509KeyEnc,
			keyExchange: kex.ASYMKEX2048Suite,
			cipherSuite: kex.A128GcmCipher,
		},
		{
			keyType:     protocol.RsaPssKeyType,
			keyEncoding: protocol.X509KeyEnc,
			keyExchange: kex.DHKEXid15Suite,
			cipherSuite: kex.A128GcmCipher,
		},
	} {
		t.Run(fmt.Sprintf("Key %q Encoding %q Exchange %q Cipher %q", table.keyType, table.keyEncoding, table.keyExchange, table.cipherSuite), func(t *testing.T) {
			transport.DIResponder.DeviceInfo = func(context.Context, *custom.DeviceMfgInfo, []*x509.Certificate) (string, protocol.KeyType, protocol.KeyEncoding, error) {
				return "test_device", table.keyType, table.keyEncoding, nil
			}

			newCredential := func(keyType protocol.KeyType) (hmacSha256, hmacSha384 hash.Hash, key crypto.Signer, toDeviceCred func(fdo.DeviceCredential) any) {
				secret := make([]byte, 32)
				if _, err := rand.Read(secret); err != nil {
					t.Fatalf("error generating device secret: %v", err)
				}
				hmacSha256 = hmac.New(sha256.New, secret)
				hmacSha384 = hmac.New(sha512.New384, secret)

				var err error
				switch table.keyType {
				case protocol.Secp256r1KeyType:
					key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				case protocol.Secp384r1KeyType:
					key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				case protocol.Rsa2048RestrKeyType:
					key, err = rsa.GenerateKey(rand.Reader, 2048)
				case protocol.RsaPkcsKeyType:
					key, err = rsa.GenerateKey(rand.Reader, 3072)
				case protocol.RsaPssKeyType:
					key, err = rsa.GenerateKey(rand.Reader, 3072)
				default:
					t.Fatalf("unsupported key type: %s", table.keyType)
				}
				if err != nil {
					t.Fatalf("error generating device key: %v", err)
				}

				return hmacSha256, hmacSha384, key, func(dc fdo.DeviceCredential) any {
					return blob.DeviceCredential{
						Active:           true,
						DeviceCredential: dc,
						HmacSecret:       secret,
						PrivateKey:       blob.Pkcs8Key{Signer: key},
					}
				}
			}
			if conf.NewCredential != nil {
				newCredential = conf.NewCredential
			}
			hmacSha256, hmacSha384, key, toDeviceCred := newCredential(table.keyType)

			// Keys and Hmacs may have a close method for resource management
			if closer, ok := hmacSha256.(io.Closer); ok {
				defer func() { _ = closer.Close() }()
			}
			if closer, ok := hmacSha384.(io.Closer); ok {
				defer func() { _ = closer.Close() }()
			}
			if closer, ok := key.(io.Closer); ok {
				defer func() { _ = closer.Close() }()
			}

			// Keys may only sign in the FDO-expected way, ignoring the signing
			// options
			var sigAlg x509.SignatureAlgorithm
			if table.keyType == protocol.RsaPssKeyType {
				sigAlg = x509.SHA256WithRSAPSS
			}

			var cred *fdo.DeviceCredential

			t.Run("Device Initialization", func(t *testing.T) {
				// Generate Java implementation-compatible mfg string
				csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
					Subject:            pkix.Name{CommonName: "device.go-fdo"},
					SignatureAlgorithm: sigAlg,
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
					HmacSha256: hmacSha256,
					HmacSha384: hmacSha384,
					Key:        key,
					PSS:        table.keyType == protocol.RsaPssKeyType,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("Credential: %s", toDeviceCred(*cred))
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
				},"")
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
					HmacSha256: hmacSha256,
					HmacSha384: hmacSha384,
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
					KeyExchange:          table.keyExchange,
					CipherSuite:          table.cipherSuite,
					AllowCredentialReuse: conf.Reuse,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("New credential: %s", toDeviceCred(*cred))
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
					HmacSha256: hmacSha256,
					HmacSha384: hmacSha384,
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
					KeyExchange:          table.keyExchange,
					CipherSuite:          table.cipherSuite,
					AllowCredentialReuse: conf.Reuse,
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("New credential: %s", toDeviceCred(*cred))
			})

			t.Run("Transfer Ownership 2 w/ Modules", func(t *testing.T) {
				if cred == nil {
					t.Fatal("cred not set due to previous failure")
				}

				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()
				newCred, err := fdo.TO2(ctx, transport, nil, fdo.TO2Config{
					Cred:       *cred,
					HmacSha256: hmacSha256,
					HmacSha384: hmacSha384,
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
					DeviceModules:        conf.DeviceModules,
					KeyExchange:          table.keyExchange,
					CipherSuite:          table.cipherSuite,
					AllowCredentialReuse: conf.Reuse,
				})
				if conf.CustomExpect != nil {
					conf.CustomExpect(t, err)
					if err != nil {
						return
					}
				} else if err != nil {
					t.Fatal(err)
				}
				t.Logf("New credential: %s", toDeviceCred(*cred))
				cred = newCred
			})
		})
	}
}
