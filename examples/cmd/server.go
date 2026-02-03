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
	"encoding/json"
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
	useTLS               bool
	addr                 string
	dbPath               string
	dbPass               string
	extAddr              string
	to0Addr              string
	to0GUID              string
	rvDelegate           string
	onboardDelegate      string
	resaleGUID           string
	resaleKey            string
	reuseCred            bool
	rvBypass             bool
	rvDelay              int
	rvReplacementPolicy  string
	printOwnerPubKey     string
	printOwnerPrivKey    string
	printOwnerChain      string
	printDelegateChain   string
	printDelegatePrivKey string
	ownerCert            bool
	importVoucher        string
	cmdDate              bool
	downloads            stringList
	uploadDir            string
	uploadReqs           stringList
	wgets                stringList
	sysconfig            stringList
	payloadFile          string
	payloadMimeType      string
	bmoFile              string
	bmoImageType         string
	bmoFiles             stringList // Multiple BMO files with types (format: type:file)
	payloadFiles         stringList // Multiple payload files with types (format: type:file)
	wifiConfigFile       string
	credentials          stringList
	pubkeyRequests       stringList
	initOnly             bool
	singleSidedWiFi      bool
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
	serverFlags.StringVar(&rvReplacementPolicy, "rv-replacement-policy", "allow-any", "RV voucher replacement `policy`: allow-any (0), manufacturer-key-consistency (1), first-registration-lock (2), owner-key-consistency (3)")
	serverFlags.StringVar(&printOwnerPubKey, "print-owner-public", "", "Print owner public key of `type` and exit")
	serverFlags.StringVar(&printOwnerPrivKey, "print-owner-private", "", "Print owner private key of `type` and exit")
	serverFlags.StringVar(&printOwnerChain, "print-owner-chain", "", "Print owner chain of `type` and exit")
	serverFlags.StringVar(&importVoucher, "import-voucher", "", "Import a PEM encoded voucher file at `path`")
	serverFlags.BoolVar(&cmdDate, "command-date", false, "Use fdo.command FSIM to have device run \"date +%s\"")
	serverFlags.Var(&downloads, "download", "Use fdo.download FSIM for each `file` (flag may be used multiple times)")
	serverFlags.StringVar(&uploadDir, "upload-dir", "uploads", "The directory `path` to put file uploads")
	serverFlags.Var(&uploadReqs, "upload", "Use fdo.upload FSIM for each `file` (flag may be used multiple times)")
	serverFlags.Var(&wgets, "wget", "Use fdo.wget FSIM for each `url` (flag may be used multiple times)")
	serverFlags.Var(&sysconfig, "sysconfig", "Use fdo.sysconfig FSIM with `key=value` pairs (flag may be used multiple times)")
	serverFlags.StringVar(&payloadFile, "payload-file", "", "Use fdo.payload FSIM to send `file` to device")
	serverFlags.StringVar(&payloadMimeType, "payload-mime", "application/octet-stream", "MIME type for payload file")
	serverFlags.StringVar(&bmoFile, "bmo-file", "", "Use fdo.bmo FSIM to send boot image `file` to device")
	serverFlags.StringVar(&bmoImageType, "bmo-type", "application/x-iso9660-image", "Image type for BMO file")
	serverFlags.Var(&bmoFiles, "bmo", "Use fdo.bmo FSIM with `type:file` format with RequireAck (flag may be used multiple times for NAK testing)")
	serverFlags.Var(&payloadFiles, "payload", "Use fdo.payload FSIM with `type:file` format with RequireAck (flag may be used multiple times for NAK testing)")
	serverFlags.StringVar(&wifiConfigFile, "wifi-config", "", "Use fdo.wifi FSIM with network config from JSON `file`")
	serverFlags.Var(&credentials, "credential", "Use fdo.credentials FSIM with `type:id:data[:endpoint_url]` format (flag may be used multiple times)")
	serverFlags.Var(&pubkeyRequests, "request-pubkey", "Request public key from device with `type:id[:endpoint_url]` format (flag may be used multiple times)")
	serverFlags.BoolVar(&initOnly, "initOnly", false, "Initialize initialization (db/key/voucher creation)")
	serverFlags.BoolVar(&singleSidedWiFi, "single-sided-wifi", false, "Run as single-sided WiFi setup service (owner not verified by device)")
}

func server(ctx context.Context) error { //nolint:gocyclo
	fmt.Println("=== STUPID DEBUG: SERVER FUNCTION CALLED ===")

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
		return doPrintOwnerPubKey(ctx, state)
	}

	if printOwnerPrivKey != "" {
		return doPrintOwnerPrivKey(ctx, state)
	}

	if printOwnerChain != "" {
		return doPrintOwnerChain(ctx, state)
	}

	// If importing a voucher, do so and exit
	if importVoucher != "" {
		return doImportVoucher(ctx, state)
	}

	// Normalize address flags
	useTLS = insecureTLS
	if extAddr == "" {
		extAddr = addr
	}

	// Parse RV replacement policy
	replacementPolicy, err := fdo.ParseVoucherReplacementPolicy(rvReplacementPolicy)
	if err != nil {
		return fmt.Errorf("invalid rv-replacement-policy: %w", err)
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
		return registerRvBlob(ctx, state)
	}

	// Invoke resale protocol if a GUID is specified
	if resaleGUID != "" {
		return resell(ctx, state)
	}

	return serveHTTP(ctx, rvInfo, state, replacementPolicy)
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

	// Generate owner certificates if requested
	var rsa2048OwnerCert, rsa3072OwnerCert, ec256OwnerCert, ec384OwnerCert []*x509.Certificate
	if ownerCert {
		rsa2048OwnerCert, err = generateCA(rsa2048OwnerKey)
		if err != nil {
			return err
		}
		rsa3072OwnerCert, err = generateCA(rsa3072OwnerKey)
		if err != nil {
			return err
		}
		ec256OwnerCert, err = generateCA(ec256OwnerKey)
		if err != nil {
			return err
		}
		ec384OwnerCert, err = generateCA(ec384OwnerKey)
		if err != nil {
			return err
		}
	}

	if err := state.AddOwnerKey(protocol.Rsa2048RestrKeyType, rsa2048OwnerKey, rsa2048OwnerCert); err != nil {
		return err
	}
	if err := state.AddOwnerKey(protocol.RsaPkcsKeyType, rsa3072OwnerKey, rsa3072OwnerCert); err != nil {
		return err
	}
	if err := state.AddOwnerKey(protocol.RsaPssKeyType, rsa3072OwnerKey, rsa3072OwnerCert); err != nil {
		return err
	}
	if err := state.AddOwnerKey(protocol.Secp256r1KeyType, ec256OwnerKey, ec256OwnerCert); err != nil {
		return err
	}
	if err := state.AddOwnerKey(protocol.Secp384r1KeyType, ec384OwnerKey, ec384OwnerCert); err != nil {
		return err
	}
	return nil
}

func serveHTTP(ctx context.Context, rvInfo [][]protocol.RvInstruction, state *sqlite.DB, replacementPolicy fdo.VoucherReplacementPolicy) error {
	// Create FDO responder
	handler, err := newHandler(ctx, rvInfo, state, replacementPolicy)
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

	// Start server in goroutine to monitor context cancellation
	errChan := make(chan error, 1)
	go func() {
		if useTLS {
			errChan <- serveTLS(lis, srv, state.DB())
		} else {
			errChan <- srv.Serve(lis)
		}
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		// Graceful shutdown on Ctrl+C
		slog.Info("Shutting down server...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("Server shutdown error", "error", err)
			return err
		}
		slog.Info("Server stopped")
		return ctx.Err()
	case err := <-errChan:
		return err
	}
}

func doPrintOwnerChain(ctx context.Context, state *sqlite.DB) error {
	keyType, err := protocol.ParseKeyType(printOwnerChain)
	if err != nil {
		return fmt.Errorf("%w: see usage", err)
	}
	_, chain, err := state.OwnerKey(ctx, keyType, 3072)
	if err != nil {
		return err
	}
	fmt.Println(fdo.CertChainToString("CERTIFICATE", chain))
	return nil
}

func doPrintOwnerPubKey(ctx context.Context, state *sqlite.DB) error {
	keyType, err := protocol.ParseKeyType(printOwnerPubKey)
	if err != nil {
		return fmt.Errorf("%w: see usage", err)
	}
	key, _, err := state.OwnerKey(ctx, keyType, 3072) // Always use 3072-bit for RSA PKCS/PSS
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", fdo.KeyToString(key.Public()))
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return err
	}
	return pem.Encode(os.Stdout, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
}

func doPrintOwnerPrivKey(ctx context.Context, state *sqlite.DB) error {
	var pemBlock *pem.Block
	keyType, err := protocol.ParseKeyType(printOwnerPrivKey)
	if err != nil {
		return fmt.Errorf("%w: see usage", err)
	}
	key, _, err := state.OwnerKey(ctx, keyType, 3072)
	if err != nil {
		return err
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		der := x509.MarshalPKCS1PrivateKey(k)
		pemBlock = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		}
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return err
		}
		pemBlock = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: der,
		}
	default:
		return fmt.Errorf("unknown owner key type %T", key)
	}

	return pem.Encode(os.Stdout, pemBlock)
}

func doImportVoucher(ctx context.Context, state *sqlite.DB) error {
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
	ownerKey, _, err := state.OwnerKey(ctx, ov.Header.Val.ManufacturerKey.Type, 3072) // Always use 3072-bit for RSA PKCS/PSS
	if err != nil {
		return fmt.Errorf("error getting owner key: %w", err)
	}
	if !ownerKey.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(expectedPubKey) {
		return fmt.Errorf("owner key in database does not match the owner of the voucher")
	}

	// Store voucher
	return state.AddVoucher(ctx, &ov)
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

func registerRvBlob(ctx context.Context, state *sqlite.DB) error {
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
		Vouchers:     state,
		OwnerKeys:    state,
		DelegateKeys: state,
	}).RegisterBlob(ctx, tlsTransport(to0Addr, nil), guid, to2Addrs, rvDelegate)
	if err != nil {
		return fmt.Errorf("error performing to0: %w", err)
	}
	slog.Info("RV blob registered", "ttl", time.Duration(refresh)*time.Second)

	return nil
}

func resell(ctx context.Context, state *sqlite.DB) error {
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
		Vouchers:        state,
		OwnerKeys:       state,
		DelegateKeys:    state,
		OnboardDelegate: onboardDelegate,
		RvDelegate:      rvDelegate,
	}).Resell(ctx, guid, nextOwner, nil)
	if err != nil {
		// TODO: If extended != nil, then call AddVoucher to restore state
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
func newHandler(ctx context.Context, rvInfo [][]protocol.RvInstruction, state *sqlite.DB, replacementPolicy fdo.VoucherReplacementPolicy) (*transport.Handler, error) {
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

	// Use Manufacturer key as device certificate authority
	deviceCAKey, deviceCAChain, err := state.ManufacturerKey(ctx, protocol.Secp384r1KeyType, 0)
	if err != nil {
		return nil, fmt.Errorf("error getting manufacturer key for use as device certificate authority: %w", err)
	}

	return &transport.Handler{
		Tokens: state,
		DIResponder: &fdo.DIServer[custom.DeviceMfgInfo]{
			Session:               state,
			Vouchers:              state,
			SignDeviceCertificate: custom.SignDeviceCertificate(deviceCAKey, deviceCAChain),
			DeviceInfo: func(ctx context.Context, info *custom.DeviceMfgInfo, _ []*x509.Certificate) (string, protocol.PublicKey, error) {
				// Always use RSA 3072 for non 2048 restricted key type. In a
				// real implementation, the manufacturing server must ensure
				// that the device has the capability to process such crypto
				// (including SHA-384 hashes).
				mfgKey, mfgChain, err := state.ManufacturerKey(ctx, info.KeyType, 3072)
				if err != nil {
					return "", protocol.PublicKey{}, err
				}
				mfgPubKey, err := encodePublicKey(info.KeyType, info.KeyEncoding, mfgKey.Public(), mfgChain)
				if err != nil {
					return "", protocol.PublicKey{}, err
				}
				return info.DeviceInfo, *mfgPubKey, nil
			},
			BeforeVoucherPersist: autoExtend,
			AfterVoucherPersist:  autoTO0,
			RvInfo:               func(context.Context, *fdo.Voucher) ([][]protocol.RvInstruction, error) { return rvInfo, nil },
		},
		TO0Responder: &fdo.TO0Server{
			Session:                  state,
			RVBlobs:                  state,
			VoucherReplacementPolicy: replacementPolicy,
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
			DelegateKeys:    state,
			RvInfo:          func(context.Context, fdo.Voucher) ([][]protocol.RvInstruction, error) { return rvInfo, nil },
			OnboardDelegate: onboardDelegate,
			RvDelegate:      rvDelegate,
			ReuseCredential: func(context.Context, fdo.Voucher) (bool, error) { return reuseCred, nil },
			SingleSidedMode: singleSidedWiFi,
		},
	}, nil
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

func encodePublicKey(keyType protocol.KeyType, keyEncoding protocol.KeyEncoding, pub crypto.PublicKey, chain []*x509.Certificate) (*protocol.PublicKey, error) {
	if pub == nil && len(chain) > 0 {
		pub = chain[0].PublicKey
	}
	if pub == nil {
		return nil, fmt.Errorf("no key to encode")
	}

	switch keyEncoding {
	case protocol.X509KeyEnc, protocol.CoseKeyEnc:
		// Intentionally panic if pub is not the correct key type
		switch keyType {
		case protocol.Secp256r1KeyType, protocol.Secp384r1KeyType:
			return protocol.NewPublicKey(keyType, pub.(*ecdsa.PublicKey), keyEncoding == protocol.CoseKeyEnc)
		case protocol.Rsa2048RestrKeyType, protocol.RsaPkcsKeyType, protocol.RsaPssKeyType:
			return protocol.NewPublicKey(keyType, pub.(*rsa.PublicKey), keyEncoding == protocol.CoseKeyEnc)
		default:
			return nil, fmt.Errorf("unsupported key type: %s", keyType)
		}
	case protocol.X5ChainKeyEnc:
		return protocol.NewPublicKey(keyType, chain, false)
	default:
		return nil, fmt.Errorf("unsupported key encoding: %s", keyEncoding)
	}
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
		fmt.Printf("[DEBUG] Device declared modules: %v\n", modules)
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

		if slices.Contains(modules, "fdo.sysconfig") && len(sysconfig) > 0 {
			sysconfigOwner := &fsim.SysConfigOwner{}
			for _, param := range sysconfig {
				parts := strings.SplitN(param, "=", 2)
				if len(parts) != 2 {
					log.Fatalf("invalid sysconfig parameter %q: expected key=value format", param)
				}
				sysconfigOwner.AddParameter(parts[0], parts[1])
			}
			if !yield("fdo.sysconfig", sysconfigOwner) {
				return
			}
		}

		if slices.Contains(modules, "fdo.payload") && (payloadFile != "" || len(payloadFiles) > 0) {
			payloadOwner := &fsim.PayloadOwner{}

			// Handle multi-file NAK testing mode (with RequireAck)
			if len(payloadFiles) > 0 {
				for _, payloadSpec := range payloadFiles {
					parts := strings.SplitN(payloadSpec, ":", 2)
					if len(parts) != 2 {
						log.Fatalf("invalid payload specification %q: expected type:file format", payloadSpec)
					}
					mimeType, filePath := parts[0], parts[1]
					data, err := os.ReadFile(filePath)
					if err != nil {
						log.Fatalf("error reading payload file %q: %v", filePath, err)
					}
					payloadOwner.AddPayloadWithAck(mimeType, filepath.Base(filePath), data, nil)
					log.Printf("Payload: Added payload with RequireAck: type=%s, file=%s", mimeType, filePath)
				}
			} else {
				// Single file mode (no RequireAck)
				data, err := os.ReadFile(payloadFile)
				if err != nil {
					log.Fatalf("error reading payload file %q: %v", payloadFile, err)
				}
				payloadOwner.AddPayload(payloadMimeType, filepath.Base(payloadFile), data, nil)
			}

			if !yield("fdo.payload", payloadOwner) {
				return
			}
		}

		if slices.Contains(modules, "fdo.bmo") && (bmoFile != "" || len(bmoFiles) > 0) {
			bmoOwner := &fsim.BMOOwner{}

			// Handle multi-file NAK testing mode (with RequireAck)
			if len(bmoFiles) > 0 {
				for _, bmoSpec := range bmoFiles {
					parts := strings.SplitN(bmoSpec, ":", 2)
					if len(parts) != 2 {
						log.Fatalf("invalid BMO specification %q: expected type:file format", bmoSpec)
					}
					imageType, filePath := parts[0], parts[1]
					data, err := os.ReadFile(filePath)
					if err != nil {
						log.Fatalf("error reading BMO file %q: %v", filePath, err)
					}
					bmoOwner.AddImageWithAck(imageType, filepath.Base(filePath), data, nil)
					log.Printf("BMO: Added image with RequireAck: type=%s, file=%s", imageType, filePath)
				}
			} else {
				// Single file mode (no RequireAck)
				data, err := os.ReadFile(bmoFile)
				if err != nil {
					log.Fatalf("error reading BMO file %q: %v", bmoFile, err)
				}
				bmoOwner.AddImage(bmoImageType, filepath.Base(bmoFile), data, nil)
			}

			if !yield("fdo.bmo", bmoOwner) {
				return
			}
		}

		if slices.Contains(modules, "fdo.wifi") && wifiConfigFile != "" {
			wifiOwner, err := loadWiFiConfig(wifiConfigFile)
			if err != nil {
				log.Fatalf("error loading WiFi config from %q: %v", wifiConfigFile, err)
			}
			if !yield("fdo.wifi", wifiOwner) {
				return
			}
		}

		if slices.Contains(modules, "fdo.credentials") {
			var provisionedCreds []fsim.ProvisionedCredential
			for _, credSpec := range credentials {
				parts := strings.SplitN(credSpec, ":", 4)
				if len(parts) < 3 {
					log.Fatalf("invalid credential specification %q: expected type:id:data[:endpoint_url] format", credSpec)
				}
				credType, _, credData := parts[0], parts[1], parts[2]
				var endpointURL string
				if len(parts) == 4 {
					endpointURL = parts[3]
				}

				// Convert string credential type to integer
				var credTypeInt int
				switch credType {
				case "password":
					credTypeInt = fsim.CredentialTypePassword
				case "api_key", "oauth2_client_secret", "bearer_token":
					credTypeInt = fsim.CredentialTypeSecret
				default:
					log.Fatalf("invalid credential type %q: must be one of password, api_key, oauth2_client_secret, bearer_token", credType)
				}

				// For password type, create metadata with username
				var data []byte
				var metadata map[string]any
				if credType == "password" {
					// credData format for password: "username:password"
					userPass := strings.SplitN(credData, ":", 2)
					if len(userPass) == 2 {
						metadata = map[string]any{"username": userPass[0]}
						data = []byte(userPass[1])
					} else {
						data = []byte(credData)
					}
				} else {
					data = []byte(credData)
				}

				provisionedCreds = append(provisionedCreds, fsim.ProvisionedCredential{
					CredentialID:   credTypeInt,
					CredentialData: data,
					Metadata:       metadata,
					EndpointURL:    endpointURL,
				})
			}

			credentialsOwner := fsim.NewCredentialsOwner(provisionedCreds)

			// Add public key requests (Registered Credentials flow)
			for _, reqSpec := range pubkeyRequests {
				parts := strings.SplitN(reqSpec, ":", 3)
				if len(parts) < 2 {
					log.Fatalf("invalid pubkey request specification %q: expected type:id[:endpoint_url] format", reqSpec)
				}
				credType, credID := parts[0], parts[1]
				var endpointURL string
				if len(parts) == 3 {
					endpointURL = parts[2]
				}
				// Convert SSH key type to integer
				var credTypeInt int
				switch credType {
				case "ssh-rsa":
					credTypeInt = fsim.CredentialTypeSSHPublicKey
				default:
					credTypeInt = fsim.CredentialTypeSSHPublicKey
				}
				credentialsOwner.PublicKeyRequests = append(credentialsOwner.PublicKeyRequests, fsim.PublicKeyRequest{
					CredentialID: credTypeInt,
					Metadata:     map[string]any{"credential_id": credID},
					EndpointURL:  endpointURL,
				})
			}

			// Add handler for receiving public keys from device
			credentialsOwner.OnPublicKeyReceived = func(credentialID string, credentialType int, publicKey []byte, metadata map[string]any) error {
				fmt.Printf("[fdo.credentials] Received public key registration:\n")
				fmt.Printf("  ID:   %s\n", credentialID)
				fmt.Printf("  Type: %d\n", credentialType)
				if metadata != nil {
					fmt.Printf("  Metadata: %v\n", metadata)
				}
				fmt.Printf("  Key:  %s (length: %d bytes)\n", string(publicKey), len(publicKey))
				return nil
			}

			// Add handler for enrollment requests (CSR signing, etc.)
			credentialsOwner.OnEnrollmentRequest = func(credentialID string, credentialType int, requestData []byte, metadata map[string]any) (responseData []byte, responseMetadata map[string]any, err error) {
				fmt.Printf("[fdo.credentials] SERVER received CSR:\n")
				fmt.Printf("  ID:   %s\n", credentialID)
				fmt.Printf("  Type: %d\n", credentialType)
				fmt.Printf("  CSR:  %s\n", string(requestData))

				// For demo purposes, return a fake signed certificate + CA bundle
				fakeCert := fmt.Sprintf("-----BEGIN CERTIFICATE-----\nSigned certificate for %s\n-----END CERTIFICATE-----\n", credentialID)
				fakeCA := "-----BEGIN CERTIFICATE-----\nFake CA Certificate\n-----END CERTIFICATE-----\n"
				responseData = []byte(fakeCert + fakeCA)

				fmt.Printf("[fdo.credentials] SERVER sending signed cert + CA:\n")
				fmt.Printf("  Cert: %d bytes\n", len(fakeCert))
				fmt.Printf("  CA:   %d bytes\n", len(fakeCA))

				responseMeta := map[string]any{
					"cert_format":        "pem",
					"ca_bundle_included": true,
				}
				return responseData, responseMeta, nil
			}
			if !yield("fdo.credentials", credentialsOwner) {
				return
			}
		}

		if slices.Contains(modules, "fdo.command") {
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

// WiFiConfigEntry represents a single WiFi network in the JSON config file
type WiFiConfigEntry struct {
	Version    string `json:"version"`
	NetworkID  string `json:"network_id"`
	SSID       string `json:"ssid"`
	AuthType   int    `json:"auth_type"`
	Password   string `json:"password"`
	TrustLevel int    `json:"trust_level"`
	NeedsCert  bool   `json:"needs_cert"`
}

// loadWiFiConfig loads WiFi network configurations from a JSON file
func loadWiFiConfig(filePath string) (*fsim.WiFiOwner, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read WiFi config file: %w", err)
	}

	var entries []WiFiConfigEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse WiFi config JSON: %w", err)
	}

	wifiOwner := &fsim.WiFiOwner{}
	for _, entry := range entries {
		network := &fsim.WiFiNetwork{
			Version:    entry.Version,
			NetworkID:  entry.NetworkID,
			SSID:       entry.SSID,
			AuthType:   entry.AuthType,
			Password:   []byte(entry.Password),
			TrustLevel: entry.TrustLevel,
		}
		wifiOwner.AddNetwork(network)

		// If this is an enterprise network that needs a certificate, add a fake cert and CA bundle
		if entry.NeedsCert && entry.AuthType == 3 {
			fakeCert := []byte("-----BEGIN CERTIFICATE-----\n" +
				"MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKKzMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\n" +
				"BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\n" +
				"aWRnaXRzIFB0eSBMdGQwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjBF\n" +
				"-----END CERTIFICATE-----\n")

			cert := fsim.WiFiCertificate{
				NetworkID: entry.NetworkID,
				SSID:      entry.SSID,
				CertRole:  0, // client certificate
				CertData:  fakeCert,
				Metadata: map[string]any{
					"cert_type": "x509",
					"format":    "pem",
				},
			}
			wifiOwner.AddCertificate(cert)

			// Add fake CA bundle (root CA certificate)
			fakeCA := []byte("-----BEGIN CERTIFICATE-----\n" +
				"MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\n" +
				"ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\n" +
				"b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL\n" +
				"MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv\n" +
				"-----END CERTIFICATE-----\n")

			caBundle := fsim.WiFiCABundle{
				NetworkID: entry.NetworkID,
				BundleID:  "root-ca",
				CAData:    fakeCA,
				Metadata: map[string]any{
					"cert_type": "x509",
					"format":    "pem",
				},
			}
			wifiOwner.AddCABundle(caBundle)
		}
	}

	return wifiOwner, nil
}
