// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package main

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
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"math"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/blob"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/custom"
	"github.com/fido-device-onboard/go-fdo/fsim"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
	"github.com/fido-device-onboard/go-fdo/tpm"
)

var clientFlags = flag.NewFlagSet("client", flag.ContinueOnError)

var (
	blobPath    string
	diURL       string
	diKey       string
	diKeyEnc    string
	kexSuite    string
	cipherSuite string
	tpmPath     string
	printDevice bool
	rvOnly      bool
	dlDir       string
	uploads     = make(fsVar)
	wgetDir     string
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
	clientFlags.StringVar(&diKey, "di-key", "ec384", "Key for device credential [options: ec256, ec384, rsa2048, rsa3072]")
	clientFlags.StringVar(&diKeyEnc, "di-key-enc", "x509", "Public key encoding to use for manufacturer key [x509,x5chain,cose]")
	clientFlags.StringVar(&kexSuite, "kex", "ECDH384", "Name of cipher `suite` to use for key exchange (see usage)")
	clientFlags.StringVar(&tpmPath, "tpm", "", "Use a TPM at `path` for device credential secrets")
	clientFlags.StringVar(&cipherSuite, "cipher", "A128GCM", "Name of cipher `suite` to use for encryption (see usage)")
	clientFlags.BoolVar(&printDevice, "print", false, "Print device credential blob and stop")
	clientFlags.BoolVar(&rvOnly, "rv-only", false, "Perform TO1 then stop")
	clientFlags.Var(&uploads, "upload", "List of dirs and `files` to upload files from, "+
		"comma-separated and/or flag provided multiple times (FSIM disabled if empty)")
	clientFlags.StringVar(&wgetDir, "wget-dir", "", "A `dir` to wget files into (FSIM disabled if empty)")
}

func client() error {
	if debug {
		level.Set(slog.LevelDebug)
	}

	// Catch interrupts
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	go func() {
		defer signal.Stop(sigs)

		select {
		case <-ctx.Done():
		case <-sigs:
			cancel()
		}
	}()

	// Perform DI if given a URL
	if diURL != "" {
		return di()
	}

	// Read device credential blob to configure client for TO1/TO2
	dc, hmacSha256, hmacSha384, privateKey, cleanup, err := readCred()
	if err == nil && cleanup != nil {
		defer func() { _ = cleanup() }()
	}
	if err != nil || printDevice {
		return err
	}

	// Try TO1+TO2
	kexCipherSuiteID, ok := kex.CipherSuiteByName(cipherSuite)
	if !ok {
		return fmt.Errorf("invalid key exchange cipher suite: %s", cipherSuite)
	}
	newDC := transferOwnership(ctx, dc.RvInfo, fdo.TO2Config{
		Cred:       *dc,
		HmacSha256: hmacSha256,
		HmacSha384: hmacSha384,
		Key:        privateKey,
		Devmod: serviceinfo.Devmod{
			Os:      runtime.GOOS,
			Arch:    runtime.GOARCH,
			Version: "Debian Bookworm",
			Device:  "go-validation",
			FileSep: ";",
			Bin:     runtime.GOARCH,
		},
		KeyExchange: kex.Suite(kexSuite),
		CipherSuite: kexCipherSuiteID,
	})
	if rvOnly {
		return nil
	}
	if newDC == nil {
		return fmt.Errorf("transfer of ownership not successful")
	}

	// Store new credential
	return updateCred(*newDC)
}

func di() (err error) { //nolint:gocyclo
	// Generate new key and secret
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("error generating device secret: %w", err)
	}
	hmacSha256, hmacSha384 := hmac.New(sha256.New, secret), hmac.New(sha512.New384, secret)

	var keyType protocol.KeyType
	var key crypto.Signer
	switch diKey {
	case "ec256":
		keyType = protocol.Secp256r1KeyType
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ec384":
		keyType = protocol.Secp384r1KeyType
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "rsa2048":
		keyType = protocol.Rsa2048RestrKeyType
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case "rsa3072":
		keyType = protocol.RsaPkcsKeyType
		key, err = rsa.GenerateKey(rand.Reader, 3072)
	default:
		return fmt.Errorf("unknown key type: %s", diKey)
	}
	if err != nil {
		return fmt.Errorf("error generating device key: %w", err)
	}

	// If using a TPM, swap key/hmac for that
	if tpmPath != "" {
		var cleanup func() error
		hmacSha256, hmacSha384, key, cleanup, err = tpmCred()
		if err != nil {
			return err
		}
		defer func() { _ = cleanup() }()
	}

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
	var keyEncoding protocol.KeyEncoding
	switch {
	case strings.EqualFold(diKeyEnc, "x509"):
		keyEncoding = protocol.X509KeyEnc
	case strings.EqualFold(diKeyEnc, "x5chain"):
		keyEncoding = protocol.X5ChainKeyEnc
	case strings.EqualFold(diKeyEnc, "cose"):
		keyEncoding = protocol.CoseKeyEnc
	default:
		return fmt.Errorf("unsupported key encoding: %s", diKeyEnc)
	}
	cred, err := fdo.DI(context.TODO(), tlsTransport(diURL, nil), custom.DeviceMfgInfo{
		KeyType:      keyType,
		KeyEncoding:  keyEncoding,
		SerialNumber: strconv.FormatInt(sn.Int64(), 10),
		DeviceInfo:   "gotest",
		CertInfo:     cbor.X509CertificateRequest(*csr),
	}, fdo.DIConfig{
		HmacSha256: hmacSha256,
		HmacSha384: hmacSha384,
		Key:        key,
	})
	if err != nil {
		return err
	}

	if tpmPath != "" {
		return saveCred(tpm.DeviceCredential{
			DeviceCredential: *cred,
			DeviceKey:        tpm.FdoDeviceKey,
		})
	}
	return saveCred(blob.DeviceCredential{
		Active:           true,
		DeviceCredential: *cred,
		HmacSecret:       secret,
		PrivateKey:       blob.Pkcs8Key{Signer: key},
	})
}

func transferOwnership(ctx context.Context, rvInfo [][]protocol.RvInstruction, conf fdo.TO2Config) *fdo.DeviceCredential { //nolint:gocyclo
	var to2URLs []string
	directives := protocol.ParseDeviceRvInfo(rvInfo)
	for _, directive := range directives {
		if !directive.Bypass {
			continue
		}
		for _, url := range directive.URLs {
			to2URLs = append(to2URLs, url.String())
		}
	}

	// Try TO1 on each address only once
	var to1d *cose.Sign1[protocol.To1d, []byte]
TO1:
	for _, directive := range directives {
		if directive.Bypass {
			continue
		}

		for _, url := range directive.URLs {
			var err error
			to1d, err = fdo.TO1(context.TODO(), tlsTransport(url.String(), nil), conf.Cred, conf.Key, nil)
			if err != nil {
				slog.Error("TO1 failed", "base URL", url.String(), "error", err)
				continue
			}
			break TO1
		}

		if directive.Delay != 0 {
			// A 25% plus or minus jitter is allowed by spec
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(directive.Delay):
			}
		}
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
			case protocol.HTTPTransport:
				scheme, port = "http://", "80"
			case protocol.HTTPSTransport:
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
		newDC := transferOwnership2(tlsTransport(baseURL, nil), to1d, conf)
		if newDC != nil {
			return newDC
		}
	}

	return nil
}

func transferOwnership2(transport fdo.Transport, to1d *cose.Sign1[protocol.To1d, []byte], conf fdo.TO2Config) *fdo.DeviceCredential {
	fsims := map[string]serviceinfo.DeviceModule{
		"fido_alliance": &fsim.Interop{},
	}
	if dlDir != "" {
		fsims["fdo.download"] = &fsim.Download{
			CreateTemp: func() (*os.File, error) {
				return os.CreateTemp(dlDir, ".fdo.download_*")
			},
			NameToPath: func(name string) string {
				// If the path tries to escape the directory, just use the file name
				if !filepath.IsLocal(name) {
					name = filepath.Base(name)
				}
				return filepath.Join(dlDir, filepath.Clean(name))
			},
		}
	}
	if len(uploads) > 0 {
		fsims["fdo.upload"] = &fsim.Upload{
			FS: uploads,
		}
	}
	if wgetDir != "" {
		fsims["fdo.wget"] = &fsim.Wget{
			CreateTemp: func() (*os.File, error) {
				return os.CreateTemp(wgetDir, ".fdo.wget_*")
			},
			NameToPath: func(name string) string {
				// If the path tries to escape the directory, just use the file name
				if !filepath.IsLocal(name) {
					name = filepath.Base(name)
				}
				return filepath.Join(wgetDir, filepath.Clean(name))
			},
			Timeout: 10 * time.Second,
		}
	}
	conf.DeviceModules = fsims

	cred, err := fdo.TO2(context.TODO(), transport, to1d, conf)
	if err != nil {
		slog.Error("TO2 failed", "error", err)
		return nil
	}
	return cred
}
