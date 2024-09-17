// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"iter"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/fsim"
	transport "github.com/fido-device-onboard/go-fdo/http"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

var serverFlags = flag.NewFlagSet("server", flag.ContinueOnError)

var (
	useTLS     bool
	addr       string
	dbPath     string
	dbPass     string
	extAddr    string
	to0Addr    string
	to0GUID    string
	resaleGUID string
	resaleKey  string
	rvBypass   bool
	downloads  stringList
	uploadDir  string
	uploadReqs stringList
)

type stringList []string

func (list *stringList) Set(v string) error {
	*list = append(*list, v)
	return nil
}

func (list *stringList) String() string {
	return fmt.Sprintf("[%s]", strings.Join(*list, ","))
}

func init() {
	serverFlags.StringVar(&dbPath, "db", "", "SQLite database file path")
	serverFlags.StringVar(&dbPass, "db-pass", "", "SQLite database encryption-at-rest passphrase")
	serverFlags.BoolVar(&debug, "debug", debug, "Print HTTP contents")
	serverFlags.StringVar(&to0Addr, "to0", "", "Rendezvous server `addr`ess to register RV blobs (disables self-registration)")
	serverFlags.StringVar(&to0GUID, "to0-guid", "", "Device `guid` to immediately register an RV blob (requires to0 flag)")
	serverFlags.StringVar(&extAddr, "ext-http", "", "External `addr`ess devices should connect to (default \"127.0.0.1:${LISTEN_PORT}\")")
	serverFlags.StringVar(&addr, "http", "localhost:8080", "The `addr`ess to listen on")
	serverFlags.StringVar(&resaleGUID, "resale-guid", "", "Voucher `guid` to extend for resale")
	serverFlags.StringVar(&resaleKey, "resale-key", "", "The `path` to a PEM-encoded x.509 public key for the next owner")
	serverFlags.BoolVar(&insecureTLS, "insecure-tls", false, "Listen with a self-signed TLS certificate")
	serverFlags.BoolVar(&rvBypass, "rv-bypass", false, "Skip TO1")
	serverFlags.Var(&downloads, "download", "Use fdo.download FSIM for each `file` (flag may be used multiple times)")
	serverFlags.StringVar(&uploadDir, "upload-dir", "uploads", "The directory `path` to put file uploads")
	serverFlags.Var(&uploadReqs, "upload", "Use fdo.upload FSIM for each `file` (flag may be used multiple times)")
}

func server() error {
	if debug {
		level.Set(slog.LevelDebug)
	}

	if dbPath == "" {
		return errors.New("db flag is required")
	}
	state, err := sqlite.New(dbPath, dbPass)
	if err != nil {
		return err
	}

	useTLS = insecureTLS

	// RV Info
	prot := fdo.RVProtHTTP
	if useTLS {
		prot = fdo.RVProtHTTPS
	}
	rvInfo := [][]fdo.RvInstruction{{{Variable: fdo.RVProtocol, Value: mustMarshal(prot)}}}
	if extAddr == "" {
		extAddr = addr
	}
	host, portStr, err := net.SplitHostPort(extAddr)
	if err != nil {
		return fmt.Errorf("invalid external addr: %w", err)
	}
	if host == "" {
		rvInfo[0] = append(rvInfo[0], fdo.RvInstruction{Variable: fdo.RVIPAddress, Value: mustMarshal(net.IP{127, 0, 0, 1})})
	} else if hostIP := net.ParseIP(host); hostIP.To4() != nil || hostIP.To16() != nil {
		rvInfo[0] = append(rvInfo[0], fdo.RvInstruction{Variable: fdo.RVIPAddress, Value: mustMarshal(hostIP)})
	} else {
		rvInfo[0] = append(rvInfo[0], fdo.RvInstruction{Variable: fdo.RVDns, Value: mustMarshal(host)})
	}
	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid external port: %w", err)
	}
	port := uint16(portNum)
	rvInfo[0] = append(rvInfo[0], fdo.RvInstruction{Variable: fdo.RVDevPort, Value: mustMarshal(port)})
	if rvBypass {
		rvInfo[0] = append(rvInfo[0], fdo.RvInstruction{Variable: fdo.RVBypass})
	}

	// Invoke TO0 client if a GUID is specified
	if to0GUID != "" {
		return registerRvBlob(host, port, state)
	}

	// Invoke resale protocol if a GUID is specified
	if resaleGUID != "" {
		return resell(state)
	}

	return serveHTTP(rvInfo, state)
}

func serveHTTP(rvInfo [][]fdo.RvInstruction, state *sqlite.DB) error {
	// Create FDO responder
	handler, err := newHandler(rvInfo, state)
	if err != nil {
		return err
	}

	// Handle messages
	mux := http.NewServeMux()
	mux.Handle("POST /fdo/101/msg/{msg}", handler)
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}

	// Listen and serve
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer func() { _ = lis.Close() }()
	slog.Info("Listening", "local", lis.Addr().String(), "external", extAddr)

	if useTLS {
		cert, err := tlsCert(state.DB())
		if err != nil {
			return err
		}
		srv.TLSConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{*cert},
		}
		return srv.ServeTLS(lis, "", "")
	}
	return srv.Serve(lis)
}

func registerRvBlob(host string, port uint16, state *sqlite.DB) error {
	if to0Addr == "" {
		return fmt.Errorf("to0-guid depends on to0 flag being set")
	}

	// Parse to0-guid flag
	guidBytes, err := hex.DecodeString(strings.ReplaceAll(to0GUID, "-", ""))
	if err != nil {
		return fmt.Errorf("error parsing GUID of device to register RV blob: %w", err)
	}
	if len(guidBytes) != 16 {
		return fmt.Errorf("error parsing GUID of device to register RV blob: must be 16 bytes")
	}
	var guid fdo.GUID
	copy(guid[:], guidBytes)

	proto := fdo.HTTPTransport
	if useTLS {
		proto = fdo.HTTPSTransport
	}

	refresh, err := (&fdo.TO0Client{
		Transport: tlsTransport(nil),
		Addrs: []fdo.RvTO2Addr{
			{
				DNSAddress:        &host,
				Port:              port,
				TransportProtocol: proto,
			},
		},
		Vouchers:  state,
		OwnerKeys: state,
	}).RegisterBlob(context.Background(), to0Addr, guid)
	if err != nil {
		return fmt.Errorf("error performing to0: %w", err)
	}
	slog.Info("RV blob registered", "ttl", time.Duration(refresh)*time.Second)

	return nil
}

func resell(state *sqlite.DB) error {
	// Parse resale-guid flag
	guidBytes, err := hex.DecodeString(strings.ReplaceAll(resaleGUID, "-", ""))
	if err != nil {
		return fmt.Errorf("error parsing GUID of voucher to resell: %w", err)
	}
	if len(guidBytes) != 16 {
		return fmt.Errorf("error parsing GUID of voucher to resell: must be 16 bytes")
	}
	var guid fdo.GUID
	copy(guid[:], guidBytes)

	// Parse next owner key
	if resaleKey == "" {
		return fmt.Errorf("resale-guid depends on resale-key flag being set")
	}
	keyBytes, err := os.ReadFile(filepath.Clean(resaleKey))
	if err != nil {
		return fmt.Errorf("error reading next owner key file: %w", err)
	}
	blk, _ := pem.Decode(keyBytes)
	if blk == nil {
		return fmt.Errorf("invalid PEM file: %s", resaleKey)
	}
	nextOwner, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing x.509 public key: %w", err)
	}

	// Perform resale protocol
	extended, err := (&fdo.TO2Server{
		Vouchers:  state,
		OwnerKeys: state,
	}).Resell(context.TODO(), guid, nextOwner, nil)
	if err != nil {
		return fmt.Errorf("resale protocol: %w", err)
	}
	ovBytes, err := cbor.Marshal(extended)
	if err != nil {
		return fmt.Errorf("resale protocol: error marshaling voucher: %w", err)
	}
	return pem.Encode(os.Stdout, &pem.Block{
		Type:  "OWNERSHIP VOUCHER",
		Bytes: ovBytes,
	})
}

func mustMarshal(v any) []byte {
	data, err := cbor.Marshal(v)
	if err != nil {
		panic(err.Error())
	}
	return data
}

//nolint:gocyclo
func newHandler(rvInfo [][]fdo.RvInstruction, state *sqlite.DB) (*transport.Handler[fdo.DeviceMfgInfo], error) {
	// Generate manufacturing component keys
	rsaMfgKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	ec256MfgKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	ec384MfgKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	generateCA := func(key crypto.Signer) ([]*x509.Certificate, error) {
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
	rsaChain, err := generateCA(rsaMfgKey)
	if err != nil {
		return nil, err
	}
	ec256Chain, err := generateCA(ec256MfgKey)
	if err != nil {
		return nil, err
	}
	ec384Chain, err := generateCA(ec384MfgKey)
	if err != nil {
		return nil, err
	}
	if err := state.AddManufacturerKey(fdo.RsaPkcsKeyType, rsaMfgKey, rsaChain); err != nil {
		return nil, err
	}
	if err := state.AddManufacturerKey(fdo.RsaPssKeyType, rsaMfgKey, rsaChain); err != nil {
		return nil, err
	}
	if err := state.AddManufacturerKey(fdo.Secp256r1KeyType, ec256MfgKey, ec256Chain); err != nil {
		return nil, err
	}
	if err := state.AddManufacturerKey(fdo.Secp384r1KeyType, ec384MfgKey, ec384Chain); err != nil {
		return nil, err
	}

	// Generate owner keys
	rsaOwnerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	ec256OwnerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	ec384OwnerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := state.AddOwnerKey(fdo.RsaPkcsKeyType, rsaOwnerKey, nil); err != nil {
		return nil, err
	}
	if err := state.AddOwnerKey(fdo.RsaPssKeyType, rsaOwnerKey, nil); err != nil {
		return nil, err
	}
	if err := state.AddOwnerKey(fdo.Secp256r1KeyType, ec256OwnerKey, nil); err != nil {
		return nil, err
	}
	if err := state.AddOwnerKey(fdo.Secp384r1KeyType, ec384OwnerKey, nil); err != nil {
		return nil, err
	}

	// Sign device certificate
	signDeviceCertificate := func(info *fdo.DeviceMfgInfo) ([]*x509.Certificate, error) {
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
	}

	// Auto-register RV blob so that TO1 can be tested unless a TO0 address is
	// given or RV bypass is set
	var autoTO0 interface {
		OwnerKey(keyType fdo.KeyType) (crypto.Signer, []*x509.Certificate, error)
		SetRVBlob(context.Context, *fdo.Voucher, *cose.Sign1[fdo.To1d, []byte], time.Time) error
	}
	var autoTO0Addrs []fdo.RvTO2Addr
	if to0Addr == "" && !rvBypass {
		autoTO0 = state

		to1URLs, _ := fdo.BaseHTTP(rvInfo)
		to1URL, err := url.Parse(to1URLs[0])
		if err != nil {
			return nil, fmt.Errorf("error parsing TO1 URL to use for TO2 addr: %w", err)
		}
		to1Host := to1URL.Hostname()
		to1Port, err := strconv.ParseUint(to1URL.Port(), 10, 16)
		if err != nil {
			return nil, fmt.Errorf("error parsing TO1 port to use for TO2: %w", err)
		}
		proto := fdo.HTTPTransport
		if useTLS {
			proto = fdo.HTTPSTransport
		}

		autoTO0Addrs = []fdo.RvTO2Addr{
			{
				DNSAddress:        &to1Host,
				Port:              uint16(to1Port),
				TransportProtocol: proto,
			},
		}
	}

	return &transport.Handler[fdo.DeviceMfgInfo]{
		Tokens: state,
		DIResponder: &fdo.DIServer[fdo.DeviceMfgInfo]{
			Session:               state,
			Vouchers:              state,
			SignDeviceCertificate: signDeviceCertificate,
			DeviceInfo: func(_ context.Context, info *fdo.DeviceMfgInfo, _ []*x509.Certificate) (string, fdo.KeyType, fdo.KeyEncoding, error) {
				return info.DeviceInfo, info.KeyType, info.KeyEncoding, nil
			},
			AutoExtend:   state,
			AutoTO0:      autoTO0,
			AutoTO0Addrs: autoTO0Addrs,
			RvInfo:       func(context.Context, *fdo.Voucher) ([][]fdo.RvInstruction, error) { return rvInfo, nil },
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
			Session:      state,
			Vouchers:     state,
			OwnerKeys:    state,
			RvInfo:       func(context.Context, fdo.Voucher) ([][]fdo.RvInstruction, error) { return rvInfo, nil },
			OwnerModules: ownerModules,
		},
	}, nil
}

func ownerModules(ctx context.Context, guid fdo.GUID, info string, chain []*x509.Certificate, devmod fdo.Devmod, modules []string) iter.Seq2[string, serviceinfo.OwnerModule] {
	return func(yield func(string, serviceinfo.OwnerModule) bool) {
		if slices.Contains(modules, "fdo.download") {
			for _, name := range downloads {
				f, err := os.Open(filepath.Clean(name))
				if err != nil {
					log.Fatalf("error opening %q for download FSIM: %v", name, err)
				}
				defer func() { _ = f.Close() }()

				if !yield("fdo.download", &fsim.DownloadContents[*os.File]{
					Name:         name,
					Contents:     f,
					MustDownload: true,
				}) {
					return
				}
			}
		}

		if slices.Contains(modules, "fdo.upload") {
			for _, name := range uploadReqs {
				if !yield("fdo.upload", &fsim.UploadRequest{
					Dir:  uploadDir,
					Name: name,
				}) {
					return
				}
			}
		}
	}
}

func tlsCert(db *sql.DB) (*tls.Certificate, error) {
	// Ensure that the https table exists
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS https
		( cert BLOB NOT NULL
		, key BLOB NOT NULL
		)`); err != nil {
		return nil, err
	}

	// Load a TLS cert and key from the database
	row := db.QueryRow("SELECT cert, key FROM https LIMIT 1")
	var certDer, keyDer []byte
	if err := row.Scan(&certDer, &keyDer); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if len(keyDer) > 0 {
		key, err := x509.ParsePKCS8PrivateKey(keyDer)
		if err != nil {
			return nil, fmt.Errorf("bad HTTPS key stored: %w", err)
		}
		return &tls.Certificate{
			Certificate: [][]byte{certDer},
			PrivateKey:  key,
		}, nil
	}

	// Generate a new self-signed TLS CA
	tlsKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, tlsKey.Public(), tlsKey)
	if err != nil {
		return nil, err
	}
	tlsCA, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	// Store TLS cert and key to the database
	keyDER, err := x509.MarshalPKCS8PrivateKey(tlsKey)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec("INSERT INTO https (cert, key) VALUES (?, ?)", caDER, keyDER); err != nil {
		return nil, err
	}

	// Use CA to serve TLS
	return &tls.Certificate{
		Certificate: [][]byte{tlsCA.Raw},
		PrivateKey:  tlsKey,
	}, nil
}
