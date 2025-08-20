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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/fs"
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
	useTLS           bool
	addr             string
	dbPath           string
	dbPass           string
	extAddr          string
	to0Addr          string
	to0GUID          string
	resaleGUID       string
	resaleKey        string
	reuseCred        bool
	rvBypass         bool
	rvDelay          int
	printOwnerPubKey string
	importVoucher    string
	cmdDate          bool
	downloads        stringList
	uploadDir        string
	uploadReqs       stringList
	wgets            stringList
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
	serverFlags.BoolVar(&reuseCred, "reuse-cred", false, "Perform the Credential Reuse Protocol in TO2")
	serverFlags.BoolVar(&insecureTLS, "insecure-tls", false, "Listen with a self-signed TLS certificate")
	serverFlags.BoolVar(&rvBypass, "rv-bypass", false, "Skip TO1")
	serverFlags.IntVar(&rvDelay, "rv-delay", 0, "Delay TO1 by N `seconds`")
	serverFlags.StringVar(&printOwnerPubKey, "print-owner-public", "", "Print owner public key of `type` and exit")
	serverFlags.StringVar(&importVoucher, "import-voucher", "", "Import a PEM encoded voucher file at `path`")
	serverFlags.BoolVar(&cmdDate, "command-date", false, "Use fdo.command FSIM to have device run \"date +%s\"")
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
	_, dbStatErr := os.Stat(dbPath)
	state, err := sqlite.Open(dbPath, dbPass)
	if err != nil {
		return err
	}

	// Generate keys only if the db wasn't already created
	if errors.Is(dbStatErr, fs.ErrNotExist) {
		if err := generateKeys(state); err != nil {
			return err
		}
	}

	// If printing owner public key, do so and exit
	if printOwnerPubKey != "" {
		return doPrintOwnerPubKey(state)
	}

	// If importing a voucher, do so and exit
	if importVoucher != "" {
		return doImportVoucher(state)
	}

	// Normalize address flags
	useTLS = insecureTLS
	if extAddr == "" {
		extAddr = addr
	}

	// RV Info
	var rvInfo [][]protocol.RvInstruction
	if to0Addr != "" {
		rvInfo, err = to0AddrToRvInfo()
	} else {
		rvInfo, err = extAddrToRvInfo()
	}
	if err != nil {
		return err
	}

	// Test RVDelay by introducing a delay before TO1
	rvInfo = append([][]protocol.RvInstruction{{{Variable: protocol.RVDelaysec, Value: mustMarshal(rvDelay)}}}, rvInfo...)

	// Invoke TO0 client if a GUID is specified
	if to0GUID != "" {
		return registerRvBlob(state)
	}

	// Invoke resale protocol if a GUID is specified
	if resaleGUID != "" {
		return resell(state)
	}

	return serveHTTP(rvInfo, state)
}

func generateKeys(state *sqlite.DB) error { //nolint:gocyclo
	// Generate manufacturing component keys
	rsa2048MfgKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	rsa3072MfgKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	ec256MfgKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	ec384MfgKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
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
		return err
	}
	rsa3072Chain, err := generateCA(rsa3072MfgKey)
	if err != nil {
		return err
	}
	ec256Chain, err := generateCA(ec256MfgKey)
	if err != nil {
		return err
	}
	ec384Chain, err := generateCA(ec384MfgKey)
	if err != nil {
		return err
	}
	if err := state.AddManufacturerKey(protocol.Rsa2048RestrKeyType, rsa2048MfgKey, rsa2048Chain); err != nil {
		return err
	}
	if err := state.AddManufacturerKey(protocol.RsaPkcsKeyType, rsa3072MfgKey, rsa3072Chain); err != nil {
		return err
	}
	if err := state.AddManufacturerKey(protocol.RsaPssKeyType, rsa3072MfgKey, rsa3072Chain); err != nil {
		return err
	}
	if err := state.AddManufacturerKey(protocol.Secp256r1KeyType, ec256MfgKey, ec256Chain); err != nil {
		return err
	}
	if err := state.AddManufacturerKey(protocol.Secp384r1KeyType, ec384MfgKey, ec384Chain); err != nil {
		return err
	}

	// Generate owner keys
	rsa2048OwnerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	rsa3072OwnerKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return err
	}
	ec256OwnerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	ec384OwnerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}
	if err := state.AddOwnerKey(protocol.Rsa2048RestrKeyType, rsa2048OwnerKey, nil); err != nil {
		return err
	}
	if err := state.AddOwnerKey(protocol.RsaPkcsKeyType, rsa3072OwnerKey, nil); err != nil {
		return err
	}
	if err := state.AddOwnerKey(protocol.RsaPssKeyType, rsa3072OwnerKey, nil); err != nil {
		return err
	}
	if err := state.AddOwnerKey(protocol.Secp256r1KeyType, ec256OwnerKey, nil); err != nil {
		return err
	}
	if err := state.AddOwnerKey(protocol.Secp384r1KeyType, ec384OwnerKey, nil); err != nil {
		return err
	}
	return nil
}

func serveHTTP(rvInfo [][]protocol.RvInstruction, state *sqlite.DB) error {
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
		return serveTLS(lis, srv, state.DB())
	}
	return srv.Serve(lis)
}

func doPrintOwnerPubKey(state *sqlite.DB) error {
	keyType, err := protocol.ParseKeyType(printOwnerPubKey)
	if err != nil {
		return fmt.Errorf("%w: see usage", err)
	}
	key, _, err := state.OwnerKey(context.Background(), keyType, 3072) // Always use 3072-bit for RSA PKCS/PSS
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return err
	}
	return pem.Encode(os.Stdout, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
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
	ownerKey, _, err := state.OwnerKey(context.Background(), ov.Header.Val.ManufacturerKey.Type, 3072) // Always use 3072-bit for RSA PKCS/PSS
	if err != nil {
		return fmt.Errorf("error getting owner key: %w", err)
	}
	if !ownerKey.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(expectedPubKey) {
		return fmt.Errorf("owner key in database does not match the owner of the voucher")
	}

	// Store voucher
	return state.AddVoucher(context.Background(), &ov)
}

func to0AddrToRvInfo() ([][]protocol.RvInstruction, error) {
	url, err := url.Parse(to0Addr)
	if err != nil {
		return nil, fmt.Errorf("cannot parse TO0 addr: %w", err)
	}
	prot := protocol.RVProtHTTP
	if url.Scheme == "https" {
		prot = protocol.RVProtHTTPS
	}
	rvInfo := [][]protocol.RvInstruction{{{Variable: protocol.RVProtocol, Value: mustMarshal(prot)}}}
	host, portStr, err := net.SplitHostPort(url.Host)
	if err != nil {
		host = url.Host
	}
	if portStr == "" {
		portStr = "80"
		if url.Scheme == "https" {
			portStr = "443"
		}
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
		return nil, fmt.Errorf("invalid TO0 port: %w", err)
	}
	port := uint16(portNum)
	rvInfo[0] = append(rvInfo[0], protocol.RvInstruction{Variable: protocol.RVDevPort, Value: mustMarshal(port)})
	if rvBypass {
		rvInfo[0] = append(rvInfo[0], protocol.RvInstruction{Variable: protocol.RVBypass})
	}
	return rvInfo, nil
}

func extAddrToRvInfo() ([][]protocol.RvInstruction, error) {
	prot := protocol.RVProtHTTP
	if useTLS {
		prot = protocol.RVProtHTTPS
	}
	rvInfo := [][]protocol.RvInstruction{{{Variable: protocol.RVProtocol, Value: mustMarshal(prot)}}}
	host, portStr, err := net.SplitHostPort(extAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid external addr: %w", err)
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
		return nil, fmt.Errorf("invalid external port: %w", err)
	}
	port := uint16(portNum)
	rvInfo[0] = append(rvInfo[0], protocol.RvInstruction{Variable: protocol.RVDevPort, Value: mustMarshal(port)})
	if rvBypass {
		rvInfo[0] = append(rvInfo[0], protocol.RvInstruction{Variable: protocol.RVBypass})
	}
	return rvInfo, nil
}

func registerRvBlob(state *sqlite.DB) error {
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

	// Construct TO2 addr
	proto := protocol.HTTPTransport
	if useTLS {
		proto = protocol.HTTPSTransport
	}
	host, portStr, err := net.SplitHostPort(extAddr)
	if err != nil {
		return fmt.Errorf("invalid external addr: %w", err)
	}
	if host == "" {
		host = "localhost"
	}
	portNum, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid external port: %w", err)
	}
	port := uint16(portNum)
	to2Addrs := []protocol.RvTO2Addr{
		{
			DNSAddress:        &host,
			Port:              port,
			TransportProtocol: proto,
		},
	}

	// Register RV blob with RV server
	refresh, err := (&fdo.TO0Client{
		Vouchers:  state,
		OwnerKeys: state,
	}).RegisterBlob(context.Background(), tlsTransport(to0Addr, nil), guid, to2Addrs)
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

func newHandler(rvInfo [][]protocol.RvInstruction, state *sqlite.DB) (*transport.Handler, error) {
	aio := fdo.AllInOne{
		DIAndOwner:         state,
		RendezvousAndOwner: withOwnerAddrs{state, rvInfo},
	}
	autoExtend := aio.Extend

	// Auto-register RV blob so that TO1 can be tested unless a TO0 address is
	// given or RV bypass is set
	var autoTO0 func(context.Context, fdo.Voucher) error
	if to0Addr == "" && !rvBypass {
		autoTO0 = aio.RegisterOwnerAddr
	}

	return &transport.Handler{
		Tokens: state,
		DIResponder: &fdo.DIServer[custom.DeviceMfgInfo]{
			Session:               state,
			Vouchers:              state,
			SignDeviceCertificate: custom.SignDeviceCertificate(useManufacturerKeyAsDeviceCA{state}),
			DeviceInfo: func(_ context.Context, info *custom.DeviceMfgInfo, _ []*x509.Certificate) (string, protocol.KeyType, protocol.KeyEncoding, error) {
				return info.DeviceInfo, info.KeyType, info.KeyEncoding, nil
			},
			BeforeVoucherPersist: autoExtend,
			AfterVoucherPersist:  autoTO0,
			RvInfo:               func(context.Context, *fdo.Voucher) ([][]protocol.RvInstruction, error) { return rvInfo, nil },
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
			Modules:         moduleStateMachines{DB: state, states: make(map[string]*moduleStateMachineState)},
			Vouchers:        state,
			OwnerKeys:       state,
			RvInfo:          func(context.Context, fdo.Voucher) ([][]protocol.RvInstruction, error) { return rvInfo, nil },
			ReuseCredential: func(context.Context, fdo.Voucher) (bool, error) { return reuseCred, nil },
		},
	}, nil
}

type useManufacturerKeyAsDeviceCA struct {
	DB *sqlite.DB
}

func (ca useManufacturerKeyAsDeviceCA) DeviceCAKey(ctx context.Context, keyType protocol.KeyType, rsaBits int) (crypto.Signer, []*x509.Certificate, error) {
	return ca.DB.ManufacturerKey(ctx, keyType, rsaBits)
}

type withOwnerAddrs struct {
	*sqlite.DB
	RVInfo [][]protocol.RvInstruction
}

func (s withOwnerAddrs) OwnerAddrs(context.Context, fdo.Voucher) ([]protocol.RvTO2Addr, time.Duration, error) {
	var autoTO0Addrs []protocol.RvTO2Addr
	for _, directive := range protocol.ParseDeviceRvInfo(s.RVInfo) {
		if directive.Bypass {
			continue
		}

		for _, url := range directive.URLs {
			to1Host := url.Hostname()
			to1Port, err := strconv.ParseUint(url.Port(), 10, 16)
			if err != nil {
				return nil, 0, fmt.Errorf("error parsing TO1 port to use for TO2: %w", err)
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
	return autoTO0Addrs, 0, nil
}

type moduleStateMachines struct {
	DB *sqlite.DB
	// current module state machine state for all sessions (indexed by token)
	states map[string]*moduleStateMachineState
}

type moduleStateMachineState struct {
	Name string
	Impl serviceinfo.OwnerModule
	Next func() (string, serviceinfo.OwnerModule, bool)
	Stop func()
}

func (s moduleStateMachines) Module(ctx context.Context) (string, serviceinfo.OwnerModule, error) {
	token, ok := s.DB.TokenFromContext(ctx)
	if !ok {
		return "", nil, fmt.Errorf("invalid context: no token")
	}
	module, ok := s.states[token]
	if !ok {
		return "", nil, fmt.Errorf("NextModule not called")
	}
	return module.Name, module.Impl, nil
}

func (s moduleStateMachines) NextModule(ctx context.Context) (bool, error) {
	token, ok := s.DB.TokenFromContext(ctx)
	if !ok {
		return false, fmt.Errorf("invalid context: no token")
	}
	module, ok := s.states[token]
	if !ok {
		// Create a new module state machine
		_, modules, _, err := s.DB.Devmod(ctx)
		if err != nil {
			return false, fmt.Errorf("error getting devmod: %w", err)
		}
		next, stop := iter.Pull2(ownerModules(modules))
		module = &moduleStateMachineState{
			Next: next,
			Stop: stop,
		}
		s.states[token] = module
	}

	var valid bool
	module.Name, module.Impl, valid = module.Next()
	return valid, nil
}

func (s moduleStateMachines) CleanupModules(ctx context.Context) {
	token, ok := s.DB.TokenFromContext(ctx)
	if !ok {
		return
	}
	module, ok := s.states[token]
	if !ok {
		return
	}
	module.Stop()
	delete(s.states, token)
}

func ownerModules(modules []string) iter.Seq2[string, serviceinfo.OwnerModule] { //nolint:gocyclo
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

		if cmdDate && slices.Contains(modules, "fdo.command") {
			if !yield("fdo.command", &fsim.RunCommand{
				Command: "date",
				Args:    []string{"+%s"},
				Stdout:  os.Stdout,
				Stderr:  os.Stderr,
			}) {
				return
			}
		}
	}
}
