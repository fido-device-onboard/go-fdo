// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/blob"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/http"
	"github.com/fido-device-onboard/go-fdo/kex"
)

var clientFlags = flag.NewFlagSet("client", flag.ContinueOnError)

var (
	blobPath    string
	diAddr      string
	printDevice bool
	rvOnly      bool
)

func init() {
	clientFlags.StringVar(&blobPath, "blob", "cred.bin", "File path of device credential blob")
	clientFlags.StringVar(&diAddr, "di", "", "HTTP base `URL` for DI server")
	clientFlags.BoolVar(&printDevice, "print", false, "Print device credential blob and stop")
	clientFlags.BoolVar(&rvOnly, "rv-only", false, "Perform TO1 then stop")
}

func client() error {
	cli := &fdo.Client{
		Transport: new(http.Transport),
		Cred:      fdo.DeviceCredential{Version: 101},
		Devmod: fdo.Devmod{
			Os:      runtime.GOOS,
			Arch:    runtime.GOARCH,
			Device:  "go-validation",
			FileSep: ";",
			Bin:     runtime.GOARCH,
		},
		KeyExchange: kex.ECDH384Suite,
		CipherSuite: kex.A256GcmCipher,
	}

	if diAddr != "" {
		return di(cli)
	}

	// TODO: TO1/TO2

	return nil
}

func di(cli *fdo.Client) error {
	// Generate Java implementation-compatible mfg string
	certChainKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("error generating cert chain key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "device.go-fdo"},
	}, certChainKey)
	if err != nil {
		return fmt.Errorf("error creating CSR for device certificate chain: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return fmt.Errorf("error parsing CSR for device certificate chain: %w", err)
	}

	// Generate new key and secret
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("error generating device secret: %w", err)
	}
	cli.Hmac = blob.Hmac(secret)

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return fmt.Errorf("error generating device key: %w", err)
	}
	cli.Key = key

	// Call the DI server
	cred, err := cli.DeviceInitialize(context.TODO(), diAddr, fdo.DeviceMfgInfo{
		KeyType:      fdo.RsaPkcsKeyType,                // KeyType
		KeyEncoding:  fdo.X5ChainKeyEnc,                 // KeyEncoding
		KeyHashAlg:   fdo.Sha384Hash,                    // HashAlg
		SerialNumber: "12345",                           // string
		DeviceInfo:   "gotest",                          // string
		CertInfo:     cbor.X509CertificateRequest(*csr), // cbor.X509CertificateRequest
	})
	if err != nil {
		return err
	}

	// Encode device credential to temp file
	tmp, err := os.CreateTemp("", "fdo_cred_*")
	if err != nil {
		return fmt.Errorf("error creating temp file for device credential: %w", err)
	}
	defer func() { _ = tmp.Close() }()

	if err := cbor.NewEncoder(tmp).Encode(blob.DeviceCredential{
		Active:           true,
		DeviceCredential: *cred,
		HmacSecret:       secret,
		PrivateKey:       blob.Pkcs8Key{Signer: key},
	}); err != nil {
		return err
	}

	// Rename temp file to given blob path
	_ = tmp.Close()
	if err := os.Rename(tmp.Name(), blobPath); err != nil {
		return fmt.Errorf("error renaming temp blob credential to %q: %w", blobPath, err)
	}

	return nil
}
