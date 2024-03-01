// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"runtime"
	"testing"
	"testing/fstest"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/blob"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/fsim"
	"github.com/fido-device-onboard/go-fdo/internal/memory"
	"github.com/fido-device-onboard/go-fdo/internal/token"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

func TestClient(t *testing.T) {
	stateless, err := token.NewService()
	if err != nil {
		t.Fatal(err)
	}
	inMemory, err := memory.NewState()
	if err != nil {
		t.Fatal(err)
	}
	inMemory.AutoExtend = stateless
	inMemory.PreserveReplacedVouchers = true

	var fsims fsimList

	server := &fdo.Server{
		State:        stateless,
		NewDevices:   stateless,
		Proofs:       stateless,
		Replacements: stateless,
		KeyExchange:  stateless,
		Nonces:       stateless,
		ServiceInfo:  stateless,
		Devices:      inMemory,
		OwnerKeys:    inMemory,
		StartFSIMs: func(context.Context, fdo.GUID, string, []*x509.Certificate, fdo.Devmod, []string) serviceinfo.OwnerModuleList {
			return &fsims
		},
	}

	cli := &fdo.Client{
		Transport: &Transport{Responder: server, T: t},
		Cred:      fdo.DeviceCredential{Version: 101},
		Devmod: fdo.Devmod{
			Os:      runtime.GOOS,
			Arch:    runtime.GOARCH,
			Version: "Debian Bookworm",
			Device:  "go-validation",
			FileSep: ";",
			Bin:     runtime.GOARCH,
		},
		KeyExchange: kex.ECDH256Suite,
		CipherSuite: kex.A128GcmCipher,
	}

	t.Run("Device Initialization", func(t *testing.T) {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			t.Fatalf("error generating device secret: %v", err)
		}
		cli.Hmac = blob.Hmac(secret)

		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("error generating device key: %v", err)
		}
		cli.Key = key

		// Generate Java implementation-compatible mfg string
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "device.go-fdo"},
		}, key)
		if err != nil {
			t.Fatalf("error creating CSR for device certificate chain: %v", err)
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			t.Fatalf("error parsing CSR for device certificate chain: %v", err)
		}

		// Call the DI server
		cred, err := cli.DeviceInitialize(context.TODO(), "", fdo.DeviceMfgInfo{
			KeyType:      fdo.Secp384r1KeyType, // Must match the key used to generate the CSR
			KeyEncoding:  fdo.X5ChainKeyEnc,
			SerialNumber: "123456",
			DeviceInfo:   "gotest",
			CertInfo:     cbor.X509CertificateRequest(*csr),
		})
		if err != nil {
			t.Fatal(err)
		}
		cli.Cred = *cred

		t.Logf("Credential: %s", blob.DeviceCredential{
			Active:           true,
			DeviceCredential: *cred,
			HmacSecret:       []byte(cli.Hmac.(blob.Hmac)),
			PrivateKey:       blob.Pkcs8Key{PrivateKey: cli.Key},
		})
	})

	t.Run("Transfer Ownership 2 - No FSIMs", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		newCred, err := cli.TransferOwnership2(ctx, "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("New credential: %s", blob.DeviceCredential{
			Active:           true,
			DeviceCredential: *newCred,
			HmacSecret:       []byte(cli.Hmac.(blob.Hmac)),
			PrivateKey:       blob.Pkcs8Key{PrivateKey: cli.Key},
		})
	})

	t.Run("Transfer Ownership 2 - Download FSIM", func(t *testing.T) {
		fsims = append(fsims, &fsim.DownloadContents[*bytes.Reader]{
			Name:         "download.test",
			Contents:     bytes.NewReader([]byte("Hello world!")),
			MustDownload: true,
		})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		newCred, err := cli.TransferOwnership2(ctx, "", nil, map[string]serviceinfo.DeviceModule{
			"fdo.download": &fsim.Download{},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("New credential: %s", blob.DeviceCredential{
			Active:           true,
			DeviceCredential: *newCred,
			HmacSecret:       []byte(cli.Hmac.(blob.Hmac)),
			PrivateKey:       blob.Pkcs8Key{PrivateKey: cli.Key},
		})
	})

	t.Run("Transfer Ownership 2 - Upload FSIM", func(t *testing.T) {
		fsims = append(fsims, &fsim.UploadRequest{
			Dir:  ".",
			Name: "bigfile.test",
		})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		newCred, err := cli.TransferOwnership2(ctx, "", nil, map[string]serviceinfo.DeviceModule{
			"fdo.upload": &fsim.Upload{FS: fstest.MapFS{
				"bigfile.test": &fstest.MapFile{
					Data: bytes.Repeat([]byte("Hello World!\n"), 1024),
					Mode: 0777,
				},
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("New credential: %s", blob.DeviceCredential{
			Active:           true,
			DeviceCredential: *newCred,
			HmacSecret:       []byte(cli.Hmac.(blob.Hmac)),
			PrivateKey:       blob.Pkcs8Key{PrivateKey: cli.Key},
		})
	})
}

type fsimList []serviceinfo.OwnerModule

func (list *fsimList) Next() serviceinfo.OwnerModule {
	if list == nil || len(*list) == 0 {
		return nil
	}
	head, tail := (*list)[0], (*list)[1:]
	*list = tail
	return head
}
