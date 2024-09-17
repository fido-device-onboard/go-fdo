// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"math"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/blob"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/fsim"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

var clientFlags = flag.NewFlagSet("client", flag.ContinueOnError)

var (
	blobPath    string
	diURL       string
	diEC256     bool
	diKeyEnc    string
	kexSuite    string
	cipherSuite string
	printDevice bool
	rvOnly      bool
	dlDir       string
	uploads     = make(fsVar)
)

type fsVar map[string]string

func (files fsVar) String() string {
	if len(files) == 0 {
		return "[]"
	}
	paths := "["
	for path := range files {
		paths += path + ","
	}
	return paths[:len(paths)-1] + "]"
}

func (files fsVar) Set(paths string) error {
	for _, path := range strings.Split(paths, ",") {
		abs, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("[%q]: %w", path, err)
		}
		files[pathToName(path, abs)] = abs
	}
	return nil
}

// The name of the directory or file is its cleaned path, if absolute. If the
// path given is relative, then remove all ".." and "." at the start. If the
// path given is only 1 or more ".." or ".", then use the name of the absolute
// path.
func pathToName(path, abs string) string {
	cleaned := filepath.Clean(path)
	if rooted := path[:1] == "/"; rooted {
		return cleaned
	}
	pathparts := strings.Split(cleaned, string(filepath.Separator))
	for len(pathparts) > 0 && (pathparts[0] == ".." || pathparts[0] == ".") {
		pathparts = pathparts[1:]
	}
	if len(pathparts) == 0 && abs != "" {
		pathparts = []string{filepath.Base(abs)}
	}
	return filepath.Join(pathparts...)
}

// Open implements fs.FS
func (files fsVar) Open(path string) (fs.File, error) {
	if !fs.ValidPath(path) {
		return nil, &fs.PathError{
			Op:   "open",
			Path: path,
			Err:  fs.ErrInvalid,
		}
	}

	// TODO: Enforce chroot-like security
	if _, rootAccess := files["/"]; rootAccess {
		return os.Open(filepath.Clean(path))
	}

	name := pathToName(path, "")
	if abs, ok := files[name]; ok {
		return os.Open(filepath.Clean(abs))
	}
	for dir := filepath.Dir(name); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		if abs, ok := files[dir]; ok {
			return os.Open(filepath.Clean(abs))
		}
	}
	return nil, &fs.PathError{
		Op:   "open",
		Path: path,
		Err:  fs.ErrNotExist,
	}
}

func init() {
	clientFlags.StringVar(&blobPath, "blob", "cred.bin", "File path of device credential blob")
	clientFlags.BoolVar(&debug, "debug", debug, "Print HTTP contents")
	clientFlags.BoolVar(&insecureTLS, "insecure-tls", false, "Skip TLS certificate verification")
	clientFlags.StringVar(&dlDir, "download", "", "A `dir` to download files into (FSIM disabled if empty)")
	clientFlags.StringVar(&diURL, "di", "", "HTTP base `URL` for DI server")
	clientFlags.BoolVar(&diEC256, "di-ec256", false, "Use Secp256r1 EC key for device credential")
	clientFlags.StringVar(&diKeyEnc, "di-key-enc", "x509", "Public key encoding to use for manufacturer key [x509,x5chain,cose]")
	clientFlags.StringVar(&kexSuite, "kex", "ECDH384", "Name of cipher `suite` to use for key exchange (see usage)")
	clientFlags.StringVar(&cipherSuite, "cipher", "A128GCM", "Name of cipher `suite` to use for encryption (see usage)")
	clientFlags.BoolVar(&printDevice, "print", false, "Print device credential blob and stop")
	clientFlags.BoolVar(&rvOnly, "rv-only", false, "Perform TO1 then stop")
	clientFlags.Var(&uploads, "upload", "List of dirs and `files` to upload files from, "+
		"comma-separated and/or flag provided multiple times (FSIM disabled if empty)")
}

func client() error {
	if debug {
		level.Set(slog.LevelDebug)
	}

	kexCipherSuiteID, ok := kex.CipherSuiteByName(cipherSuite)
	if !ok {
		return fmt.Errorf("invalid key exchange cipher suite: %s", cipherSuite)
	}

	cli := &fdo.Client{
		Transport: tlsTransport(nil),
		Cred:      fdo.DeviceCredential{Version: 101},
		Devmod: fdo.Devmod{
			Os:      runtime.GOOS,
			Arch:    runtime.GOARCH,
			Version: "Debian Bookworm",
			Device:  "go-validation",
			FileSep: ";",
			Bin:     runtime.GOARCH,
		},
		KeyExchange: kex.Suite(kexSuite),
		CipherSuite: kexCipherSuiteID,
	}

	// Perform DI if given a URL
	if diURL != "" {
		return di(cli)
	}

	// Read device credential blob to configure client for TO1/TO2
	blobFile, err := os.Open(filepath.Clean(blobPath))
	if err != nil {
		return fmt.Errorf("error opening blob credential %q: %w", blobPath, err)
	}
	defer func() { _ = blobFile.Close() }()

	var cred blob.DeviceCredential
	if err := cbor.NewDecoder(blobFile).Decode(&cred); err != nil {
		_ = blobFile.Close()
		return fmt.Errorf("error parsing blob credential %q: %w", blobPath, err)
	}
	_ = blobFile.Close()
	cli.Cred = cred.DeviceCredential
	cli.Hmac = cred.HmacSecret
	cli.Key = cred.PrivateKey

	// If print option was given, stop here
	if printDevice {
		fmt.Printf("%+v\n", cred)
		return nil
	}

	// Try TO1+TO2
	newDC := transferOwnership(cli, cred.RvInfo)
	if rvOnly {
		return nil
	}
	if newDC == nil {
		return fmt.Errorf("transfer of ownership not successful")
	}

	// Store new credential
	cred.DeviceCredential = *newDC
	return saveBlob(cred)
}

func saveBlob(dc blob.DeviceCredential) error {
	// Encode device credential to temp file
	tmp, err := os.CreateTemp(".", "fdo_cred_*")
	if err != nil {
		return fmt.Errorf("error creating temp file for device credential: %w", err)
	}
	defer func() { _ = tmp.Close() }()

	if err := cbor.NewEncoder(tmp).Encode(dc); err != nil {
		return err
	}

	// Rename temp file to given blob path
	_ = tmp.Close()
	if err := os.Rename(tmp.Name(), blobPath); err != nil {
		return fmt.Errorf("error renaming temp blob credential to %q: %w", blobPath, err)
	}

	return nil
}

func di(cli *fdo.Client) error {
	// Generate new key and secret
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("error generating device secret: %w", err)
	}
	cli.Hmac = blob.Hmac(secret)

	curve := elliptic.P384()
	if diEC256 {
		curve = elliptic.P256()
	}
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return fmt.Errorf("error generating device key: %w", err)
	}
	cli.Key = key

	// Generate Java implementation-compatible mfg string
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "device.go-fdo"},
	}, key)
	if err != nil {
		return fmt.Errorf("error creating CSR for device certificate chain: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return fmt.Errorf("error parsing CSR for device certificate chain: %w", err)
	}

	// Call the DI server
	sn, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return fmt.Errorf("error generating random serial number: %w", err)
	}
	keyType := fdo.Secp384r1KeyType
	if diEC256 {
		keyType = fdo.Secp256r1KeyType
	}
	var keyEncoding fdo.KeyEncoding
	switch {
	case strings.EqualFold(diKeyEnc, "x509"):
		keyEncoding = fdo.X509KeyEnc
	case strings.EqualFold(diKeyEnc, "x5chain"):
		keyEncoding = fdo.X5ChainKeyEnc
	case strings.EqualFold(diKeyEnc, "cose"):
		keyEncoding = fdo.CoseKeyEnc
	default:
		return fmt.Errorf("unsupported key encoding: %s", diKeyEnc)
	}
	cred, err := cli.DeviceInitialize(context.TODO(), diURL, fdo.DeviceMfgInfo{
		KeyType:      keyType,
		KeyEncoding:  keyEncoding,
		SerialNumber: strconv.FormatInt(sn.Int64(), 10),
		DeviceInfo:   "gotest",
		CertInfo:     cbor.X509CertificateRequest(*csr),
	})
	if err != nil {
		return err
	}

	return saveBlob(blob.DeviceCredential{
		Active:           true,
		DeviceCredential: *cred,
		HmacSecret:       secret,
		PrivateKey:       blob.Pkcs8Key{PrivateKey: key},
	})
}

func transferOwnership(cli *fdo.Client, rvInfo [][]fdo.RvInstruction) *fdo.DeviceCredential {
	to1URLs, to2URLs := fdo.BaseHTTP(rvInfo)

	// Try TO1 on each address only once
	var to1d *cose.Sign1[fdo.To1d, []byte]
	for _, baseURL := range to1URLs {
		var err error
		to1d, err = cli.TransferOwnership1(context.TODO(), baseURL)
		if err != nil {
			slog.Error("TO1 failed", "base URL", baseURL, "error", err)
			continue
		}
		break
	}
	if to1d != nil {
		for _, to2Addr := range to1d.Payload.Val.RV {
			var host string
			switch {
			case to2Addr.DNSAddress != nil:
				host = *to2Addr.DNSAddress
			case to2Addr.IPAddress != nil:
				host = to2Addr.IPAddress.String()
			default:
				// invalid to1d: cannot have addr with null DNS and IP addresses
				continue
			}

			var scheme, port string
			switch to2Addr.TransportProtocol {
			case fdo.HTTPTransport:
				scheme, port = "http://", "80"
			case fdo.HTTPSTransport:
				scheme, port = "https://", "443"
			default:
				continue
			}
			if to2Addr.Port != 0 {
				port = strconv.Itoa(int(to2Addr.Port))
			}

			to2URLs = append(to2URLs, scheme+net.JoinHostPort(host, port))
		}
	}

	// Print TO2 addrs if RV-only
	if rvOnly {
		if to1d != nil {
			fmt.Printf("TO1 Blob: %+v\n", to1d.Payload.Val)
		}
		return nil
	}

	// Try TO2 on each address only once
	for _, baseURL := range to2URLs {
		newDC := transferOwnership2(cli, baseURL, to1d)
		if newDC != nil {
			return newDC
		}
	}

	return nil
}

func transferOwnership2(cli *fdo.Client, baseURL string, to1d *cose.Sign1[fdo.To1d, []byte]) *fdo.DeviceCredential {
	fsims := map[string]serviceinfo.DeviceModule{
		"fido_alliance": &fsim.Interop{},
	}
	if dlDir != "" {
		fsims["fdo.download"] = &fsim.Download{
			NameToPath: func(name string) string {
				// TODO: Enforce chroot-like security
				return filepath.Join(dlDir, name)
			},
		}
	}
	if len(uploads) > 0 {
		fsims["fdo.upload"] = &fsim.Upload{
			FS: uploads,
		}
	}

	cred, err := cli.TransferOwnership2(context.TODO(), baseURL, to1d, fsims)
	if err != nil {
		slog.Error("TO2 failed", "base URL", baseURL, "error", err)
		return nil
	}
	return cred
}
