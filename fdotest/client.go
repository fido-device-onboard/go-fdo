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
	"sync"
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

// Config provides options to modify how the test suite runs.
type Config struct {
	// If state is nil, then an in-memory implementation will be used. This is
	// useful for only testing service info modules.
	State AllServerState

	// If NewCredential is non-nil, then it will be used to create and format
	// the device credential. Otherwise the blob package will be used.
	NewCredential func(protocol.KeyType) (hmacSha256, hmacSha384 hash.Hash, key crypto.Signer, toDeviceCred func(fdo.DeviceCredential) any)

	// If NewTransport is non-nil, then it will be used in place of
	// fdo.Transport.
	NewTransport func(t *testing.T, tokens protocol.TokenService, di, to0, to1, to2 protocol.Responder) fdo.Transport

	// Use the Credential Reuse Protocol
	Reuse bool

	// If true, set the log level to info
	NoDebug bool

	// If DeviceModules is non-nil, then they will be reported as supported in
	// devmod and called if any owner modules are executed.
	DeviceModules map[string]serviceinfo.DeviceModule

	// If OwnerModules is non-nil, then it will be used to initialize owner
	// module state and owner services will be executed in order for each
	// module supported by the device (as reported in devmod).
	OwnerModules func(ctx context.Context, replacementGUID protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule]

	// If CustomExpect is non-nil, then it is used to validate the result of
	// TO2 with modules enabled
	CustomExpect func(*testing.T, error)
}

var internalStateOnce sync.Once
var internalState struct {
	*token.Service
	*memory.State
}

// RunClientTestSuite is used to test different implementations of server state
// methods at an almost end-to-end level (transport is mocked).
//
//nolint:gocyclo
func RunClientTestSuite(t *testing.T, conf Config) {
	level := slog.LevelDebug
	if conf.NoDebug {
		level = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(TestingLog(t), &slog.HandlerOptions{Level: level})))

	if conf.State == nil {
		internalStateOnce.Do(func() {
			stateless, err := token.NewService()
			if err != nil {
				t.Fatal(err)
			}
			internalState.Service = stateless

			inMemory, err := memory.NewState()
			if err != nil {
				t.Fatal(err)
			}
			internalState.State = inMemory
		})
		conf.State = internalState
	}

	startModules := conf.OwnerModules
	if conf.OwnerModules == nil {
		startModules = func(context.Context, protocol.GUID, string, []*x509.Certificate, serviceinfo.Devmod, []string) iter.Seq2[string, serviceinfo.OwnerModule] {
			return func(yield func(string, serviceinfo.OwnerModule) bool) {}
		}
	}

	diResponder := &fdo.DIServer[custom.DeviceMfgInfo]{
		Session:  conf.State,
		Vouchers: conf.State,
		SignDeviceCertificate: func(info *custom.DeviceMfgInfo) ([]*x509.Certificate, error) {
			// Validate device info
			csr := x509.CertificateRequest(info.CertInfo)
			if err := csr.CheckSignature(); err != nil {
				return nil, fmt.Errorf("invalid CSR: %w", err)
			}

			// Recommended configurations (see section 3.3.2) have matching
			// strengths between device and owner attestation keys and
			// therefore the RSA key size should match the device public key or
			// should be 2048 for secp256r1 and 3072 for secp384r1
			var rsaBits int
			if info.KeyType == protocol.Rsa2048RestrKeyType || info.KeyType == protocol.RsaPkcsKeyType || info.KeyType == protocol.RsaPssKeyType {
				switch pub := csr.PublicKey.(type) {
				case *rsa.PublicKey:
					rsaBits = pub.Size() * 8
				case *ecdsa.PublicKey:
					switch pub.Curve {
					case elliptic.P256():
						rsaBits = 2048
					case elliptic.P384():
						rsaBits = 3072
					default:
						return nil, fmt.Errorf("device key uses unsupported EC curve: %s", pub.Curve.Params().Name)
					}
				default:
					return nil, fmt.Errorf("device key type is unsupported")
				}
			}

			// Sign CSR
			key, chain, err := conf.State.ManufacturerKey(context.Background(), info.KeyType, rsaBits)
			if err != nil {
				var unsupportedErr fdo.ErrUnsupportedKeyType
				if errors.As(err, &unsupportedErr) {
					return nil, unsupportedErr
				}
				return nil, fmt.Errorf("error retrieving manufacturer key [type=%s,bits=%d]: %w", info.KeyType, rsaBits, err)
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
	}
	to0Responder := &fdo.TO0Server{
		Session: conf.State,
		RVBlobs: conf.State,
	}
	to1Responder := &fdo.TO1Server{
		Session: conf.State,
		RVBlobs: conf.State,
	}
	to2Responder := &fdo.TO2Server{
		Session: conf.State,
		Modules: &to2ModuleStateMachine{
			Session:  conf.State,
			Vouchers: conf.State,
			OwnerModules: func(ctx context.Context, replacementGUID protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, supportedMods []string) iter.Seq2[string, serviceinfo.OwnerModule] {
				mods := startModules(ctx, replacementGUID, info, chain, devmod, supportedMods)

				// Filter out modules not in supportedMods
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
		Vouchers:  conf.State,
		OwnerKeys: conf.State,
		RvInfo: func(context.Context, fdo.Voucher) ([][]protocol.RvInstruction, error) {
			return [][]protocol.RvInstruction{}, nil
		},
		ReuseCredential: func(context.Context, fdo.Voucher) bool { return conf.Reuse },
		VerifyVoucher:   func(context.Context, fdo.Voucher) error { return nil },
	}

	var transport fdo.Transport = &Transport{
		Tokens:       conf.State,
		DIResponder:  diResponder,
		TO0Responder: to0Responder,
		TO1Responder: to1Responder,
		TO2Responder: to2Responder,
		T:            t,
	}
	if conf.NewTransport != nil {
		transport = conf.NewTransport(t, conf.State, diResponder, to0Responder, to1Responder, to2Responder)
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
			diResponder.DeviceInfo = func(context.Context, *custom.DeviceMfgInfo, []*x509.Certificate) (string, protocol.KeyType, protocol.KeyEncoding, error) {
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
				}); err == nil || !strings.HasSuffix(err.Error(), fdo.ErrNotFound.Error()) {
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

// Store a single module state at a time, initializing it with OwnerModules and
// relying on CleanupModules to be called to clear the state before the next
// usage.
type to2ModuleStateMachine struct {
	Session      fdo.TO2SessionState
	Vouchers     fdo.OwnerVoucherPersistentState
	OwnerModules func(ctx context.Context, guid protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, modules []string) iter.Seq2[string, serviceinfo.OwnerModule]

	module *moduleStateMachineState
}

type moduleStateMachineState struct {
	Name string
	Impl serviceinfo.OwnerModule
	Next func() (string, serviceinfo.OwnerModule, bool)
	Stop func()
}

func (s *to2ModuleStateMachine) Module(ctx context.Context) (string, serviceinfo.OwnerModule, error) {
	if s.module == nil {
		return "", nil, fmt.Errorf("NextModule never called")
	}
	if s.module.Impl == nil {
		return "", nil, fmt.Errorf("NextModule already returned false")
	}
	return s.module.Name, s.module.Impl, nil
}

func (s *to2ModuleStateMachine) NextModule(ctx context.Context) (bool, error) {
	if s.module != nil {
		var valid bool
		s.module.Name, s.module.Impl, valid = s.module.Next()
		return valid, nil
	}

	guid, err := s.Session.GUID(ctx)
	if err != nil {
		return false, fmt.Errorf("error retrieving associated device GUID of TO2 session: %w", err)
	}

	ov, err := s.Vouchers.Voucher(ctx, guid)
	if err != nil {
		return false, fmt.Errorf("error retrieving voucher for device %x: %w", guid, err)
	}
	info := ov.Header.Val.DeviceInfo

	replacementGUID, err := s.Session.ReplacementGUID(ctx)
	if errors.Is(err, fdo.ErrNotFound) {
		// replacement GUID is not found when using the Credential Reuse Protocol
		replacementGUID = guid
	} else if err != nil {
		return false, fmt.Errorf("error retrieving replacement GUID for device: %w", err)
	}

	devmod, modules, devmodComplete, err := s.Session.Devmod(ctx)
	if err == nil && !devmodComplete {
		return false, fmt.Errorf("devmod did not complete")
	}
	if err != nil {
		return false, fmt.Errorf("error retrieving devmod info for device %x: %w", guid, err)
	}

	var deviceCertChain []*x509.Certificate
	if ov.CertChain != nil {
		deviceCertChain = make([]*x509.Certificate, len(*ov.CertChain))
		for i, cert := range *ov.CertChain {
			deviceCertChain[i] = (*x509.Certificate)(cert)
		}
	}

	// Start iterator
	nextModule, stopIter := iter.Pull2(s.OwnerModules(ctx, replacementGUID, info, deviceCertChain, devmod, modules))
	name, impl, valid := nextModule()
	s.module = &moduleStateMachineState{
		Name: name,
		Impl: impl,
		Next: nextModule,
		Stop: stopIter,
	}
	return valid, nil
}

func (s *to2ModuleStateMachine) CleanupModules(ctx context.Context) {
	if s.module != nil {
		s.module.Stop()
		s.module = nil
	}
}
