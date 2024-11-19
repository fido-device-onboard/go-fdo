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
	"bytes"
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
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/custom"
	"github.com/fido-device-onboard/go-fdo/fsim"
	transport "github.com/fido-device-onboard/go-fdo/http"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

var serverFlags = flag.NewFlagSet("server", flag.ContinueOnError)

var (
	useTLS                bool
	addr                  string
	dbPath                string
	dbPass                string
	extAddr               string
	to0Addr               string
	to0GUID               string
	resaleGUID            string
	resaleKey             string
	reuseCred             bool
	rvDelegate            string
	onboardDelegate       string
	rvBypass              bool
	rvDelay               int
	printOwnerPubKey      string
	printOwnerPrivKey     string
	printOwnerChain       string
	printDelegateChain    string
	printDelegatePrivKey  string
	ownerCert             bool
	importVoucher         string
	downloads             stringList
	uploadDir             string
	uploadReqs            stringList
	wgets                 stringList
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
	serverFlags.StringVar(&rvDelegate, "rvDelegate", "", "Use delegate cert (name) for RV blob signing")
	serverFlags.StringVar(&onboardDelegate, "onboardDelegate", "", "Use delegate cert (name) for TO2")
	serverFlags.StringVar(&to0Addr, "to0", "", "Rendezvous server `addr`ess to register RV blobs (disables self-registration)")
	serverFlags.StringVar(&to0GUID, "to0-guid", "", "Device `guid` to immediately register an RV blob (requires to0 flag)")
	serverFlags.StringVar(&extAddr, "ext-http", "", "External `addr`ess devices should connect to (default \"127.0.0.1:${LISTEN_PORT}\")")
	serverFlags.StringVar(&addr, "http", "localhost:8080", "The `addr`ess to listen on")
	serverFlags.StringVar(&resaleGUID, "resale-guid", "", "Voucher `guid` to extend for resale")
	serverFlags.StringVar(&resaleKey, "resale-key", "", "The `path` to a PEM-encoded x.509 public key for the next owner")
	serverFlags.BoolVar(&reuseCred, "reuse-cred", false, "Perform the Credential Reuse Protocol in TO2")
	serverFlags.BoolVar(&insecureTLS, "insecure-tls", false, "Listen with a self-signed TLS certificate")
	serverFlags.BoolVar(&ownerCert, "owner-certs", false, "Generate Owner Certificatats (in addition to keys)")
	serverFlags.BoolVar(&rvBypass, "rv-bypass", false, "Skip TO1")
	serverFlags.IntVar(&rvDelay, "rv-delay", 0, "Delay TO1 by N `seconds`")
	serverFlags.StringVar(&printOwnerPubKey, "print-owner-public", "", "Print owner public key of `type` and exit")
	serverFlags.StringVar(&printOwnerPrivKey, "print-owner-private", "", "Print owner private key of `type` and exit")
	serverFlags.StringVar(&printOwnerChain, "print-owner-chain", "", "Print owner chain of `type` and exit")
	serverFlags.StringVar(&importVoucher, "import-voucher", "", "Import a PEM encoded voucher file at `path`")
	serverFlags.Var(&downloads, "download", "Use fdo.download FSIM for each `file` (flag may be used multiple times)")
	serverFlags.StringVar(&uploadDir, "upload-dir", "uploads", "The directory `path` to put file uploads")
	serverFlags.Var(&uploadReqs, "upload", "Use fdo.upload FSIM for each `file` (flag may be used multiple times)")
	serverFlags.Var(&wgets, "wget", "Use fdo.wget FSIM for each `url` (flag may be used multiple times)")
}

func server() error { //nolint:gocyclo
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

	// If printing owner public key, do so and exit
	if printOwnerPubKey != "" {
		return doPrintOwnerPubKey(state)
	}

	if printOwnerPrivKey != "" {
		return doPrintOwnerPrivKey(state)
	}

	if printOwnerChain != "" {
		return doPrintOwnerChain(state)
	}

	// If importing a voucher, do so and exit
	if importVoucher != "" {
		return doImportVoucher(state)
	}

	useTLS = insecureTLS

	// RV Info
	prot := protocol.RVProtHTTP
	if useTLS {
		prot = protocol.RVProtHTTPS
	}
	rvInfo := [][]protocol.RvInstruction{{{Variable: protocol.RVProtocol, Value: mustMarshal(prot)}}}
	if extAddr == "" {
		extAddr = addr
	}
	host, portStr, err := net.SplitHostPort(extAddr)
	if err != nil {
		return fmt.Errorf("invalid external addr: %w", err)
	}
	if host == "" {
		rvInfo[0] = append(rvInfo[0], protocol.RvInstruction{Variable: protocol.RVIPAddress, Value: mustMarshal(net.IP{127, 0, 0, 1})})
	} else if hostIP := net.ParseIP(host); hostIP.To4() != nil || hostIP.To16() != nil {
		rvInfo[0] = append(rvInfo[0], protocol.RvInstruction{Variable: protocol.RVIPAddress, Value: mustMarshal(hostIP)})
	} else {
		rvInfo[0] = append(rvInfo[0], protocol.RvInstruction{Variable: protocol.RVDns, Value: mustMarshal(host)})
	}
	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid external port: %w", err)
	}
	port := uint16(portNum)
	rvInfo[0] = append(rvInfo[0], protocol.RvInstruction{Variable: protocol.RVDevPort, Value: mustMarshal(port)})
	if rvBypass {
		rvInfo[0] = append(rvInfo[0], protocol.RvInstruction{Variable: protocol.RVBypass})
	}

	// Test RVDelay by introducing a delay before TO1
	rvInfo = append([][]protocol.RvInstruction{{{Variable: protocol.RVDelaysec, Value: mustMarshal(rvDelay)}}}, rvInfo...)

	// Invoke TO0 client if a GUID is specified
	if to0GUID != "" {
		return registerRvBlob(host, port, state, rvDelegate)
	}

	// Invoke resale protocol if a GUID is specified
	if resaleGUID != "" {
		return resell(state)
	}

	return serveHTTP(rvInfo, state)
}

func serveHTTP(rvInfo [][]protocol.RvInstruction, state *sqlite.DB) error {
	// Create FDO responder
	handler, err := newHandler(rvInfo, state)
	if err != nil {
		return err
	}

	// Handle messages
	mux := http.NewServeMux()
	mux.Handle("POST /fdo/{fdoVer}/msg/{msg}", handler)
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

func printCert(cert *x509.Certificate) {
	var pemData bytes.Buffer
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	if err := pem.Encode(&pemData, pemBlock); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encode certificate: %v\n", err)
		return 
	}

	fmt.Println(pemData.String())
}
func doPrintOwnerChain(state *sqlite.DB) error {
	keyType, err := protocol.ParseKeyType(printOwnerChain)
	if err != nil {
		return fmt.Errorf("%w: see usage", err)
	}
	_, chain, err := state.OwnerKey(keyType)
	if err != nil {
		return err
	}
	fmt.Println(fdo.CertChainToString("CERTIFICATE",chain))
	return nil
}

func doPrintOwnerPubKey(state *sqlite.DB) error {
	keyType, err := protocol.ParseKeyType(printOwnerPubKey)
	if err != nil {
		return fmt.Errorf("%w: see usage", err)
	}
	key, _, err := state.OwnerKey(keyType)
	if err != nil {
		return err
	}
        fmt.Printf("** OWNER %T %v PUBLIC %v\n",key,key,key.Public())
        fmt.Printf("%s\n",fdo.KeyToString(key.Public()))
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return err
	}
	return pem.Encode(os.Stdout, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
}

func doPrintOwnerPrivKey(state *sqlite.DB) error {
	var pemBlock *pem.Block
	keyType, err := protocol.ParseKeyType(printOwnerPrivKey)
	if err != nil {
		return fmt.Errorf("%w: see usage", err)
	}
	key, _, err := state.OwnerKey(keyType)
	fmt.Printf("Key is %T %V\n",key,key)
	if err != nil {
		return err
	}

	switch key.(type) {
		case *rsa.PrivateKey:
			der := x509.MarshalPKCS1PrivateKey(key.(*rsa.PrivateKey))
			pemBlock = &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: der,
			}
		case *ecdsa.PrivateKey:
			der, err := x509.MarshalECPrivateKey(key.(*ecdsa.PrivateKey))
			if err != nil {
				return err
			}
			pemBlock = &pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: der,
			}

		default:
			err =  fmt.Errorf("Unknown Owner key type %T", key)
			return err
	}

	print( pem.Encode(os.Stdout, pemBlock))
	return nil
}

func doImportVoucher(state *sqlite.DB) error {
	// Parse voucher
	pemVoucher, err := os.ReadFile(filepath.Clean(importVoucher))
	if err != nil {
		return err
	}
	blk, _ := pem.Decode(pemVoucher)
	if blk == nil {
		return fmt.Errorf("invalid PEM encoded file: %s", importVoucher)
	}
	if blk.Type != "OWNERSHIP VOUCHER" {
		return fmt.Errorf("expected PEM block of ownership voucher type, found %s", blk.Type)
	}
	var ov fdo.Voucher
	if err := cbor.Unmarshal(blk.Bytes, &ov); err != nil {
		return fmt.Errorf("error parsing voucher: %w", err)
	}

	// Check that voucher owner key matches
	expectedPubKey, err := ov.OwnerPublicKey()
	if err != nil {
		return fmt.Errorf("error parsing owner public key from voucher: %w", err)
	}
	ownerKey, _, err := state.OwnerKey(ov.Header.Val.ManufacturerKey.Type)
	if err != nil {
		return fmt.Errorf("error getting owner key: %w", err)
	}
	if !ownerKey.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(expectedPubKey) {
		return fmt.Errorf("owner key in database does not match the owner of the voucher")
	}

	// Store voucher
	return state.AddVoucher(context.Background(), &ov)
}

func registerRvBlob(host string, port uint16, state *sqlite.DB, delegate string) error {
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
	var guid protocol.GUID
	copy(guid[:], guidBytes)

	proto := protocol.HTTPTransport
	if useTLS {
		proto = protocol.HTTPSTransport
	}

	to2Addrs := []protocol.RvTO2Addr{
		{
			DNSAddress:        &host,
			Port:              port,
			TransportProtocol: proto,
		},
	}
	refresh, err := (&fdo.TO0Client{
		Vouchers:  state,
		OwnerKeys: state,
		DelegateKeys: state,
	}).RegisterBlob(context.Background(), tlsTransport(to0Addr, nil), guid, to2Addrs,rvDelegate)
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
	var guid protocol.GUID
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
		DelegateKeys: state,
		OnboardDelegate: onboardDelegate,
		RvDelegate: rvDelegate,
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
func newHandler(rvInfo [][]protocol.RvInstruction, state *sqlite.DB) (*transport.Handler, error) {
	var ec384OwnerCert []*x509.Certificate = nil
	var ec256OwnerCert []*x509.Certificate = nil
	var rsa3072OwnerCert []*x509.Certificate = nil
	var rsa2048OwnerCert []*x509.Certificate = nil

	// Generate manufacturing component keys
	rsa2048MfgKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	rsa3072MfgKey, err := rsa.GenerateKey(rand.Reader, 3072)
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

	rsa2048Chain, err := generateCA(rsa2048MfgKey)
	if err != nil {
		return nil, err
	}
	rsa3072Chain, err := generateCA(rsa3072MfgKey)
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
	if err := state.AddManufacturerKey(protocol.Rsa2048RestrKeyType, rsa2048MfgKey, rsa2048Chain); err != nil {
		return nil, err
	}
	if err := state.AddManufacturerKey(protocol.RsaPkcsKeyType, rsa3072MfgKey, rsa3072Chain); err != nil {
		return nil, err
	}
	if err := state.AddManufacturerKey(protocol.RsaPssKeyType, rsa3072MfgKey, rsa3072Chain); err != nil {
		return nil, err
	}
	if err := state.AddManufacturerKey(protocol.Secp256r1KeyType, ec256MfgKey, ec256Chain); err != nil {
		return nil, err
	}
	if err := state.AddManufacturerKey(protocol.Secp384r1KeyType, ec384MfgKey, ec384Chain); err != nil {
		return nil, err
	}

	// Generate owner keys
	rsa2048OwnerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	rsa3072OwnerKey, err := rsa.GenerateKey(rand.Reader, 3072)
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

	// Generate full owner Certificates, if requested

	if (ownerCert) {
		ec384OwnerCert, err = generateCA(ec384OwnerKey)
		if err != nil {
			return nil, err
		}

		ec256OwnerCert, err = generateCA(ec256OwnerKey)
		if err != nil {
			return nil, err
		}

		rsa3072OwnerCert, err = generateCA(rsa3072OwnerKey)
		if err != nil {
			return nil, err
		}

		rsa2048OwnerCert, err = generateCA(rsa2048OwnerKey)
		if err != nil {
			return nil, err
		}

	}


	if err := state.AddOwnerKey(protocol.Rsa2048RestrKeyType, rsa2048OwnerKey, rsa2048OwnerCert); err != nil {
		return nil, err
	}
	if err := state.AddOwnerKey(protocol.RsaPkcsKeyType, rsa3072OwnerKey, rsa3072OwnerCert); err != nil {
		return nil, err
	}
	if err := state.AddOwnerKey(protocol.RsaPssKeyType, rsa3072OwnerKey, rsa3072OwnerCert); err != nil {
		return nil, err
	}
	if err := state.AddOwnerKey(protocol.Secp256r1KeyType, ec256OwnerKey, ec256OwnerCert); err != nil {
		return nil, err
	}
	if err := state.AddOwnerKey(protocol.Secp384r1KeyType, ec384OwnerKey, ec384OwnerCert); err != nil {
		return nil, err
	}


	// Auto-register RV blob so that TO1 can be tested unless a TO0 address is
	// given or RV bypass is set
	var autoTO0 fdo.AutoTO0
	var autoTO0Addrs []protocol.RvTO2Addr
	if to0Addr == "" && !rvBypass {
		autoTO0 = state

		for _, directive := range protocol.ParseDeviceRvInfo(rvInfo) {
			if directive.Bypass {
				continue
			}

			for _, url := range directive.URLs {
				to1Host := url.Hostname()
				to1Port, err := strconv.ParseUint(url.Port(), 10, 16)
				if err != nil {
					return nil, fmt.Errorf("error parsing TO1 port to use for TO2: %w", err)
				}
				proto := protocol.HTTPTransport
				if useTLS {
					proto = protocol.HTTPSTransport
				}
				autoTO0Addrs = append(autoTO0Addrs, protocol.RvTO2Addr{
					DNSAddress:        &to1Host,
					Port:              uint16(to1Port),
					TransportProtocol: proto,
				})
			}
		}
	}

	return &transport.Handler{
		Tokens: state,
		DIResponder: &fdo.DIServer[custom.DeviceMfgInfo]{
			Session:               state,
			Vouchers:              state,
			SignDeviceCertificate: custom.SignDeviceCertificate(state),
			DeviceInfo: func(_ context.Context, info *custom.DeviceMfgInfo, _ []*x509.Certificate) (string, protocol.KeyType, protocol.KeyEncoding, error) {
				return info.DeviceInfo, info.KeyType, info.KeyEncoding, nil
			},
			AutoExtend:   state,
			AutoTO0:      autoTO0,
			AutoTO0Addrs: autoTO0Addrs,
			RvInfo:       func(context.Context, *fdo.Voucher) ([][]protocol.RvInstruction, error) { return rvInfo, nil },
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
			Session:         state,
			Vouchers:        state,
			OwnerKeys:       state,
			DelegateKeys:	 state,
			RvInfo:          func(context.Context, fdo.Voucher) ([][]protocol.RvInstruction, error) { return rvInfo, nil },
			OwnerModules:    ownerModules,
			ReuseCredential: func(context.Context, fdo.Voucher) bool { return reuseCred },
			OnboardDelegate: onboardDelegate,
			RvDelegate: rvDelegate,
		},
	}, nil
}

func ownerModules(ctx context.Context, guid protocol.GUID, info string, chain []*x509.Certificate, devmod serviceinfo.Devmod, modules []string) iter.Seq2[string, serviceinfo.OwnerModule] {
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

		if slices.Contains(modules, "fdo.wget") {
			for _, urlString := range wgets {
				url, err := url.Parse(urlString)
				if err != nil || url.Path == "" {
					continue
				}
				if !yield("fdo.wget", &fsim.WgetCommand{
					Name: path.Base(url.Path),
					URL:  url,
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
