// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdotest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/blob"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/fsim"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// FSIMList is a simple one-time-use server FSIM execution list.
type FSIMList []serviceinfo.OwnerModule

// Next implements serviceinfo.OwnerModuleList.
func (list *FSIMList) Next() serviceinfo.OwnerModule {
	if list == nil || len(*list) == 0 {
		return nil
	}
	head, tail := (*list)[0], (*list)[1:]
	*list = tail
	return head
}

// TestClient is used to test different implementations of server state
// methods at an almost end-to-end level (transport is mocked).
//
//nolint:gocyclo
func TestClient(cli *fdo.Client, to0 *fdo.TO0Client, addFSIM func(serviceinfo.OwnerModule), t *testing.T) {
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

	t.Run("Transfer Ownership 0", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := cli.TransferOwnership1(ctx, ""); !strings.HasSuffix(err.Error(), fdo.ErrNotFound.Error()) {
			t.Fatalf("expected TO1 to fail with no resource found, got %v", err)
		}
		ttl, err := to0.RegisterBlob(ctx, "", cli.Cred.GUID)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("RV Blob TTL: %d seconds", ttl)
	})

	t.Run("Transfer Ownership 1 and Transfer Ownership 2", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		to1d, err := cli.TransferOwnership1(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("RV Blob: %+v", to1d)

		newCred, err := cli.TransferOwnership2(ctx, "", to1d, nil)
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
		addFSIM(&fsim.DownloadContents[*bytes.Reader]{
			Name:         "download.test",
			Contents:     bytes.NewReader([]byte("Hello world!")),
			MustDownload: true,
		})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		newCred, err := cli.TransferOwnership2(ctx, "", nil, map[string]serviceinfo.DeviceModule{
			"fdo.download": &fsim.Download{
				CreateTemp: func() (*os.File, error) {
					return os.CreateTemp(".", "fdo.download_*")
				},
			},
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
		addFSIM(&fsim.UploadRequest{
			Dir:  ".",
			Name: "bigfile.test",
			CreateTemp: func() (*os.File, error) {
				return os.CreateTemp(".", "fdo.upload_*")
			},
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
