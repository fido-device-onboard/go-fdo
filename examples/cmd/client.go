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
	blobPath              string
	diURL                 string
	diKey                 string
	diKeyEnc              string
	kexSuite              string
	cipherSuite           string
	tpmPath               string
	printDevice           bool
	rvOnly                bool
	dlDir                 string
	echoCmds              bool
	uploads               = make(fsVar)
	wgetDir               string
	fdoVersion            int
	registerSSHKey        string // SSH public key to register with owner
	enrollCSR             string // CSR enrollment request (format: id:csrdata)
	bmoSupportedTypes     string // Comma-separated list of supported BMO MIME types (empty = accept all)
	payloadSupportedTypes string // Comma-separated list of supported Payload MIME types (empty = accept all)
	allowSingleSided      bool   // Allow single-sided attestation (WiFi-only mode)
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
	for path := range strings.SplitSeq(paths, ",") {
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
	clientFlags.StringVar(&cipherSuite, "cipher", "A128GCM", "Name of cipher `suite` to use for encryption (see usage)")
	clientFlags.BoolVar(&debug, "debug", debug, "Print HTTP contents")
	clientFlags.StringVar(&dlDir, "download", "", "A `dir` to download files into (FSIM disabled if empty)")
	clientFlags.StringVar(&diURL, "di", "", "HTTP base `URL` for DI server")
	clientFlags.StringVar(&diKey, "di-key", "ec384", "Key for device credential [options: ec256, ec384, rsa2048, rsa3072]")
	clientFlags.StringVar(&diKeyEnc, "di-key-enc", "x509", "Public key encoding to use for manufacturer key [x509,x5chain,cose]")
	clientFlags.BoolVar(&echoCmds, "echo-commands", false, "Echo all commands received to stdout (FSIM disabled if false)")
	clientFlags.StringVar(&kexSuite, "kex", "ECDH384", "Name of cipher `suite` to use for key exchange (see usage)")
	clientFlags.BoolVar(&insecureTLS, "insecure-tls", false, "Skip TLS certificate verification")
	clientFlags.BoolVar(&printDevice, "print", false, "Print device credential blob and stop")
	clientFlags.BoolVar(&rvOnly, "rv-only", false, "Perform TO1 then stop")
	clientFlags.StringVar(&tpmPath, "tpm", "", "Use a TPM at `path` for device credential secrets")
	clientFlags.Var(&uploads, "upload", "List of dirs and `files` to upload files from, "+
		"comma-separated and/or flag provided multiple times (FSIM disabled if empty)")
	clientFlags.StringVar(&wgetDir, "wget-dir", "", "A `dir` to wget files into (FSIM disabled if empty)")
	clientFlags.IntVar(&fdoVersion, "fdo-version", 101, "FDO protocol version (101 or 200)")
	clientFlags.StringVar(&registerSSHKey, "register-ssh-key", "", "SSH public `key` to register with owner (format: id:keydata)")
	clientFlags.StringVar(&enrollCSR, "enroll-csr", "", "CSR enrollment `request` (format: id:csrdata)")
	clientFlags.StringVar(&bmoSupportedTypes, "bmo-supported-types", "", "Comma-separated list of supported BMO MIME `types` (empty = accept all)")
	clientFlags.StringVar(&payloadSupportedTypes, "payload-supported-types", "", "Comma-separated list of supported Payload MIME `types` (empty = accept all)")
	clientFlags.BoolVar(&allowSingleSided, "allow-single-sided", false, "Allow single-sided attestation (WiFi-only mode, owner not verified)")
}

func client(ctx context.Context) error {
	if debug {
		level.Set(slog.LevelDebug)
	}

	// Perform DI if given a URL
	if diURL != "" {
		return di(ctx)
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
	newDC, err := transferOwnership(ctx, dc.RvInfo, fdo.TO2Config{
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
		KeyExchange:          kex.Suite(kexSuite),
		CipherSuite:          kexCipherSuiteID,
		AllowCredentialReuse: true,
		AllowSingleSided:     allowSingleSided,
	})
	if rvOnly {
		return nil
	}
	if err != nil {
		return fmt.Errorf("transfer ownership failed: %w", err)
	}
	if newDC == nil {
		// Credential reuse - this is a success case
		fmt.Println("Credential reuse - credential not updated")
		return nil
	}

	// Store new credential
	fmt.Println("Success")
	return updateCred(*newDC)
}

func di(ctx context.Context) (err error) { //nolint:gocyclo
	// Generate new key and secret
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("error generating device secret: %w", err)
	}
	hmacSha256, hmacSha384 := hmac.New(sha256.New, secret), hmac.New(sha512.New384, secret)

	var sigAlg x509.SignatureAlgorithm
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
		sigAlg = x509.SHA384WithRSA
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
		Subject:            pkix.Name{CommonName: "device.go-fdo"},
		SignatureAlgorithm: sigAlg,
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
	cred, err := fdo.DI(ctx, tlsTransport(diURL, nil), custom.DeviceMfgInfo{
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

func transferOwnership(ctx context.Context, rvInfo [][]protocol.RvInstruction, conf fdo.TO2Config) (*fdo.DeviceCredential, error) { //nolint:gocyclo
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
			to1d, err = fdo.TO1(ctx, tlsTransport(url.String(), nil), conf.Cred, conf.Key, nil)
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
				return nil, ctx.Err()
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
		return nil, nil
	}

	// Try TO2 on each address only once
	for _, baseURL := range to2URLs {
		// Use version-aware transport for TO2
		if fdoVersion < 0 || fdoVersion > 65535 {
			slog.Error("invalid FDO version", "version", fdoVersion)
			return nil, fmt.Errorf("invalid FDO version: %d", fdoVersion)
		}
		version := protocol.Version(fdoVersion) //#nosec G115 -- bounds checked above
		transport := tlsTransportWithVersion(baseURL, nil, version)
		newDC, err := transferOwnership2(ctx, transport, to1d, conf)
		if err != nil {
			// TO2 failed - continue to next URL, but remember the error
			continue
		}
		if newDC != nil {
			return newDC, nil
		}
		// newDC == nil && err == nil means credential reuse
		return nil, nil
	}

	return nil, fmt.Errorf("TO2 failed on all addresses")
}

// payloadHandler implements fsim.UnifiedPayloadHandler to save received payloads.
// The framework handles all chunking transparently - we just receive the complete payload.
type payloadHandler struct{}

func (h *payloadHandler) HandlePayload(ctx context.Context, mimeType, name string, size uint64, metadata map[string]any, payload []byte) (statusCode int, message string, err error) {
	fmt.Printf("[fdo.payload] HandlePayload called: name=%s, mime=%s, size=%d, received=%d bytes\n", name, mimeType, size, len(payload))

	// Save payload to file
	filename := name
	if filename == "" {
		filename = "received_payload.bin"
	}
	if err := os.WriteFile(filename, payload, 0644); err != nil {
		fmt.Printf("[fdo.payload] ERROR: failed to save file: %v\n", err)
		return 2, fmt.Sprintf("failed to save payload: %v", err), err
	}
	fmt.Printf("[fdo.payload] Saved payload to: %s (%d bytes)\n", filename, len(payload))
	return 0, fmt.Sprintf("saved to %s", filename), nil
}

// bmoHandler implements fsim.UnifiedImageHandler to receive boot images.
// The framework handles all chunking transparently - we just receive the complete image.
type bmoHandler struct{}

func (h *bmoHandler) HandleImage(ctx context.Context, imageType, name string, size uint64, metadata map[string]any, image []byte) (statusCode int, message string, err error) {
	fmt.Printf("[fdo.bmo] HandleImage called: name=%s, type=%s, size=%d, received=%d bytes\n", name, imageType, size, len(image))

	// Save image to file
	filename := name
	if filename == "" {
		filename = "received_image.bin"
	}
	if err := os.WriteFile(filename, image, 0600); err != nil {
		fmt.Printf("[fdo.bmo] ERROR: failed to save file: %v\n", err)
		return 2, fmt.Sprintf("failed to save image: %v", err), err
	}
	fmt.Printf("[fdo.bmo] Saved image to: %s (%d bytes)\n", filename, len(image))
	return 0, fmt.Sprintf("saved to %s", filename), nil
}

// bmoAckHandler implements fsim.ImageAckHandler to accept/reject images based on MIME type.
type bmoAckHandler struct {
	supportedTypes []string
}

func (h *bmoAckHandler) AcceptImage(imageType, name string, size uint64, metadata map[string]any) (accepted bool, reasonCode int, message string) {
	fmt.Printf("[fdo.bmo] AcceptImage called: type=%s, name=%s, size=%d\n", imageType, name, size)

	// Check if this image type is in our supported list
	for _, supported := range h.supportedTypes {
		if imageType == supported {
			fmt.Printf("[fdo.bmo] Image type %s is supported, accepting\n", imageType)
			return true, 0, ""
		}
	}

	fmt.Printf("[fdo.bmo] Image type %s is NOT supported (supported: %v), rejecting\n", imageType, h.supportedTypes)
	return false, 1, fmt.Sprintf("unsupported image type: %s", imageType)
}

// payloadAckHandler implements fsim.PayloadAckHandler to accept/reject payloads based on MIME type.
type payloadAckHandler struct {
	supportedTypes []string
}

func (h *payloadAckHandler) AcceptPayload(mimeType, name string, size uint64, metadata map[string]any) (accepted bool, reasonCode int, message string) {
	fmt.Printf("[fdo.payload] AcceptPayload called: type=%s, name=%s, size=%d\n", mimeType, name, size)

	// Check if this MIME type is in our supported list
	for _, supported := range h.supportedTypes {
		if mimeType == supported {
			fmt.Printf("[fdo.payload] MIME type %s is supported, accepting\n", mimeType)
			return true, 0, ""
		}
	}

	fmt.Printf("[fdo.payload] MIME type %s is NOT supported (supported: %v), rejecting\n", mimeType, h.supportedTypes)
	return false, 1, fmt.Sprintf("unsupported MIME type: %s", mimeType)
}

// wifiHandler implements fsim.WiFiHandler to display WiFi network configuration.
// For this simple test, we just display the networks received from the server.
type wifiHandler struct {
	lastNetworkID string
	lastSSID      string
}

func (h *wifiHandler) AddNetwork(network *fsim.WiFiNetwork) error {
	fmt.Printf("[fdo.wifi] Received network configuration:\n")
	fmt.Printf("  Version:     %s\n", network.Version)
	fmt.Printf("  NetworkID:   %s\n", network.NetworkID)
	fmt.Printf("  SSID:        %s\n", network.SSID)
	fmt.Printf("  AuthType:    %d", network.AuthType)
	switch network.AuthType {
	case 0:
		fmt.Printf(" (open)")
	case 1:
		fmt.Printf(" (wpa2-psk)")
	case 2:
		fmt.Printf(" (wpa3-psk)")
	case 3:
		fmt.Printf(" (wpa3-enterprise)")
		fmt.Printf("\n[fdo.wifi] Enterprise network detected - will generate CSR")
	}
	fmt.Printf("\n")
	if len(network.Password) > 0 {
		fmt.Printf("  Password:    %s\n", string(network.Password))
	}
	fmt.Printf("  TrustLevel:  %d", network.TrustLevel)
	switch network.TrustLevel {
	case 0:
		fmt.Printf(" (onboard-only)")
	case 1:
		fmt.Printf(" (full-access)")
	}
	fmt.Printf("\n")

	// Store network info for CSR generation
	h.lastNetworkID = network.NetworkID
	h.lastSSID = network.SSID

	return nil
}

func (h *wifiHandler) GenerateCSR(networkID, ssid string) (csrData []byte, metadata map[string]any, err error) {
	// Generate fake CSR data for testing
	fmt.Printf("[fdo.wifi] Generating fake CSR for network %s (%s)\n", networkID, ssid)

	// Create fake CSR data (just some bytes that look like a CSR)
	fakeCSR := []byte("-----BEGIN CERTIFICATE REQUEST-----\n" +
		"MIICvDCCAaQCAQAwdzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx\n" +
		"FjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBFRlc3QxDTALBgNVBAsM\n" +
		"BFRlc3QxHTAbBgNVBAMMFHRlc3QtZGV2aWNlLmxvY2FsLmNvbTCCASIwDQYJKoZI\n" +
		"-----END CERTIFICATE REQUEST-----\n")

	meta := map[string]any{
		"csr_type": "pkcs10",
		"key_type": "rsa2048",
	}

	fmt.Printf("[fdo.wifi] Generated fake CSR (%d bytes)\n", len(fakeCSR))
	return fakeCSR, meta, nil
}

func (h *wifiHandler) InstallCertificate(networkID, ssid string, certData []byte, metadata map[string]any) (statusCode int, message string, err error) {
	fmt.Printf("[fdo.wifi] Received certificate for network %s (%s)\n", networkID, ssid)
	fmt.Printf("[fdo.wifi] Certificate size: %d bytes\n", len(certData))
	if metadata != nil {
		fmt.Printf("[fdo.wifi] Certificate metadata: %v\n", metadata)
	}
	fmt.Printf("[fdo.wifi] Certificate installed successfully (fake)\n")
	return 0, "Certificate installed", nil
}

func (h *wifiHandler) InstallCACerts(networkID, bundleID string, caData []byte, metadata map[string]any) (statusCode int, message string, err error) {
	fmt.Printf("[fdo.wifi] Received CA bundle for network %s\n", networkID)
	fmt.Printf("[fdo.wifi] Bundle ID: %s\n", bundleID)
	fmt.Printf("[fdo.wifi] CA bundle size: %d bytes\n", len(caData))
	if metadata != nil {
		fmt.Printf("[fdo.wifi] CA bundle metadata: %+v\n", metadata)
	}
	fmt.Printf("[fdo.wifi] CA bundle installed successfully (fake)\n")
	return 0, "CA bundle installed successfully", nil
}

func transferOwnership2(ctx context.Context, transport fdo.Transport, to1d *cose.Sign1[protocol.To1d, []byte], conf fdo.TO2Config) (*fdo.DeviceCredential, error) {
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
	if echoCmds {
		fsims["fdo.command"] = &fsim.Command{
			Timeout: time.Second,
			Transform: func(cmd string, args []string) (string, []string) {
				return "sh", []string{"-c",
					fmt.Sprintf("echo %q", strings.Join(append([]string{cmd}, args...), " "))}
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
	fsims["fdo.sysconfig"] = &fsim.SysConfig{
		SetParameter: func(parameter, value string) error {
			fmt.Printf("[fdo.sysconfig] Received parameter: %s = %s\n", parameter, value)
			return nil
		},
	}

	// Add payload handler to receive and save payloads
	// Using UnifiedHandler - the framework handles chunking transparently
	payloadFSIM := &fsim.Payload{
		UnifiedHandler: &payloadHandler{},
	}
	// Add AckHandler if supported types are specified (for NAK testing)
	if payloadSupportedTypes != "" {
		types := strings.Split(payloadSupportedTypes, ",")
		payloadFSIM.AckHandler = &payloadAckHandler{supportedTypes: types}
		fmt.Printf("[fdo.payload] NAK mode enabled, supported types: %v\n", types)
	}
	fsims["fdo.payload"] = payloadFSIM

	// Add BMO handler to receive boot images
	// Using UnifiedHandler - the framework handles chunking transparently
	bmoFSIM := &fsim.BMO{
		UnifiedHandler: &bmoHandler{},
	}
	// Add AckHandler if supported types are specified (for NAK testing)
	if bmoSupportedTypes != "" {
		types := strings.Split(bmoSupportedTypes, ",")
		bmoFSIM.AckHandler = &bmoAckHandler{supportedTypes: types}
		fmt.Printf("[fdo.bmo] NAK mode enabled, supported types: %v\n", types)
	}
	fsims["fdo.bmo"] = bmoFSIM

	// Add WiFi handler to display network configuration
	fsims["fdo.wifi"] = &fsim.WiFi{
		Handler: &wifiHandler{},
	}

	// Add credentials handler to receive and display credentials (using chunked protocol)
	credDevice := fsim.NewCredentialsDevice(func(id, credType string, data []byte, metadata map[string]any) error {
		fmt.Printf("[fdo.credentials] Received credential:\n")
		fmt.Printf("  ID:   %s\n", id)
		fmt.Printf("  Type: %s\n", credType)
		if metadata != nil {
			fmt.Printf("  Metadata: %v\n", metadata)
		}
		fmt.Printf("  Data: %s (length: %d bytes)\n", string(data), len(data))
		return nil
	})

	// Add callback for public key requests (owner-driven Registered Credentials flow)
	if registerSSHKey != "" {
		// Format: id:keydata (e.g., device-config-key:ssh-ed25519 AAAA...)
		parts := strings.SplitN(registerSSHKey, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid -register-ssh-key format: expected id:keydata")
		}
		credID, keyData := parts[0], parts[1]
		// Store the key data for the callback
		sshKeyData := []byte(keyData)
		credDevice.OnPublicKeyRequested = func(reqCredID, reqCredType string, metadata map[string]any) ([]byte, error) {
			fmt.Printf("[fdo.credentials] Owner requested public key: %s (type: %s)\n", reqCredID, reqCredType)
			// Return the configured SSH key if IDs match, or for any request
			if reqCredID == credID || credID == "*" {
				fmt.Printf("[fdo.credentials] Returning SSH key: %s\n", credID)
				return sshKeyData, nil
			}
			return nil, fmt.Errorf("no public key available for credential_id: %s", reqCredID)
		}
		fmt.Printf("[fdo.credentials] Configured SSH key: %s\n", credID)
	}

	// Add enrollment requests (device-initiated Enrolled Credentials flow)
	if enrollCSR != "" {
		// Format: id:csrdata (e.g., device-mtls-cert:-----BEGIN CERTIFICATE REQUEST-----)
		parts := strings.SplitN(enrollCSR, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid -enroll-csr format: expected id:csrdata")
		}
		credID, csrData := parts[0], parts[1]
		credDevice.EnrollmentRequests = append(credDevice.EnrollmentRequests, fsim.EnrollmentRequest{
			CredentialID:   credID,
			CredentialType: "x509_cert",
			RequestData:    []byte(csrData),
		})
		credDevice.OnEnrolledCredentialReceived = func(credentialID, credentialType string, data []byte, metadata map[string]any) error {
			fmt.Printf("[fdo.credentials] CLIENT received signed cert + CA:\n")
			fmt.Printf("  ID:       %s\n", credentialID)
			fmt.Printf("  Type:     %s\n", credentialType)
			if metadata != nil {
				if caIncluded, ok := metadata["ca_bundle_included"].(bool); ok && caIncluded {
					fmt.Printf("  CA included: yes\n")
				}
			}
			fmt.Printf("  Response:\n%s\n", string(data))
			return nil
		}
		fmt.Printf("[fdo.credentials] Configured CSR enrollment: %s\n", credID)
	}
	fsims["fdo.credentials"] = credDevice

	conf.DeviceModules = fsims

	// Call version-specific TO2 function
	var cred *fdo.DeviceCredential
	var err error
	if fdoVersion == 200 {
		cred, err = fdo.TO2v200(ctx, transport, to1d, conf)
	} else {
		cred, err = fdo.TO2(ctx, transport, to1d, conf)
	}
	if err != nil {
		slog.Error("TO2 failed", "error", err)
		return nil, err
	}
	return cred, nil
}
