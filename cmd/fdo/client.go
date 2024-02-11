// Copyright 2023 Intel Corporation
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
	"net"
	"os"
	"runtime"
	"strconv"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/blob"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/http"
	"github.com/fido-device-onboard/go-fdo/kex"
)

var clientFlags = flag.NewFlagSet("client", flag.ContinueOnError)

var (
	blobPath    string
	debug       bool
	diURL       string
	printDevice bool
	rvOnly      bool
)

func init() {
	clientFlags.StringVar(&blobPath, "blob", "cred.bin", "File path of device credential blob")
	clientFlags.BoolVar(&debug, "debug", false, "Print HTTP contents")
	clientFlags.StringVar(&diURL, "di", "", "HTTP base `URL` for DI server")
	clientFlags.BoolVar(&printDevice, "print", false, "Print device credential blob and stop")
	clientFlags.BoolVar(&rvOnly, "rv-only", false, "Perform TO1 then stop")
}

func client() error {
	cli := &fdo.Client{
		Transport: &http.Transport{Debug: debug},
		Cred:      fdo.DeviceCredential{Version: 101},
		Devmod: fdo.Devmod{
			Os:      runtime.GOOS,
			Arch:    runtime.GOARCH,
			Device:  "go-validation",
			FileSep: ";",
			Bin:     runtime.GOARCH,
		},
		KeyExchange: kex.ECDH256Suite,
		CipherSuite: kex.A128GcmCipher,
	}

	// Perform DI if given a URL
	if diURL != "" {
		return di(cli)
	}

	// Read device credential blob to configure client for TO1/TO2
	blobFile, err := os.Open(blobPath)
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
	tmp, err := os.CreateTemp("", "fdo_cred_*")
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

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
	cred, err := cli.DeviceInitialize(context.TODO(), diURL, fdo.DeviceMfgInfo{
		KeyType:      fdo.Secp256r1KeyType,              // KeyType
		KeyEncoding:  fdo.X5ChainKeyEnc,                 // KeyEncoding
		SerialNumber: "12345",                           // string
		DeviceInfo:   "gotest",                          // string
		CertInfo:     cbor.X509CertificateRequest(*csr), // cbor.X509CertificateRequest
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

//nolint:gocyclo
func transferOwnership(cli *fdo.Client, rvInfo [][]fdo.RvInstruction) *fdo.DeviceCredential {
	// Try TO1 on each RVAddr only once
	for _, directive := range rvInfo {
		m := make(map[fdo.RvVar][]byte)
		for _, instruction := range directive {
			m[instruction.Variable] = instruction.Value
		}

		// Check the protocol is HTTP
		protVal, ok := m[fdo.RVProtocol]
		if !ok {
			fmt.Fprintf(os.Stderr, "Skipping TO1 directive with no protocol: %+v\n", m)
			continue
		}
		var prot fdo.RvProt
		if err := cbor.Unmarshal(protVal, &prot); err != nil {
			fmt.Fprintf(os.Stderr, "error parsing protocol instruction value: %v\n", err)
			fmt.Fprintf(os.Stderr, "Skipping TO1 directive with non-uint8 protocol value: %+v\n", m)
			continue
		}
		if prot != fdo.RVProtHTTP {
			fmt.Fprintf(os.Stderr, "Skipping non-HTTP TO1 directive: %+v\n", m)
			continue
		}

		// Parse the TO1 server addr
		dnsAddrVal, isDNS := m[fdo.RVDns]
		var dnsAddr string
		if isDNS {
			if err := cbor.Unmarshal(dnsAddrVal, &dnsAddr); err != nil {
				fmt.Fprintf(os.Stderr, "error parsing DNS instruction value: %v\n", err)
				isDNS = false
			}
		}
		ipAddrVal, isIP := m[fdo.RVIPAddress]
		var ipAddr net.IP
		if isIP {
			if err := cbor.Unmarshal(ipAddrVal, &ipAddr); err != nil {
				fmt.Fprintf(os.Stderr, "error parsing IP instruction value: %v\n", err)
				isIP = false
			}
		}
		portVal, hasPort := m[fdo.RVDevPort]
		var port uint16
		if hasPort {
			if err := cbor.Unmarshal(portVal, &port); err != nil {
				fmt.Fprintf(os.Stderr, "error parsing port instruction value: %v\n", err)
				hasPort = false
			}
		}
		if !hasPort {
			port = 80
		}

		// Try DNS then IP
		if !isDNS && !isIP {
			fmt.Fprintf(os.Stderr, "Skipping TO1 directive with no IP or DNS instructions: %+v\n", m)
			continue
		}
		var to1d *cose.Sign1[fdo.To1d, []byte]
		if isDNS {
			baseURL := "http://" + net.JoinHostPort(dnsAddr, strconv.Itoa(int(port)))
			var err error
			to1d, err = cli.TransferOwnership1(context.TODO(), baseURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error running TO1 on %q: %v\n", baseURL, err)
				continue
			}
		}
		if to1d == nil && isIP {
			baseURL := "http://" + net.JoinHostPort(ipAddr.String(), strconv.Itoa(int(port)))
			var err error
			to1d, err = cli.TransferOwnership1(context.TODO(), baseURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error running TO1 on %q: %v\n", baseURL, err)
				continue
			}
		}
		if to1d == nil {
			fmt.Fprintf(os.Stderr, "Skipping TO1 directive with no found TO2 addrs: %+v\n", m)
			continue
		}

		// Print TO2 addrs if RV-only
		if rvOnly {
			fmt.Printf("TO1 Blob: %+v\n", to1d.Payload.Val)
			return nil
		}

		// Try TO2
		for _, addr := range to1d.Payload.Val.RV {
			newDC := transferOwnership2(cli, addr, to1d)
			if newDC != nil {
				return newDC
			}
		}
	}

	return nil
}

func transferOwnership2(cli *fdo.Client, addr fdo.RvTO2Addr, to1d *cose.Sign1[fdo.To1d, []byte]) *fdo.DeviceCredential {
	var host string
	switch {
	case addr.DNSAddress != nil:
		host = *addr.DNSAddress
	case addr.IPAddress != nil:
		host = addr.IPAddress.String()
	default:
		panic("invalid to1d: cannot have addr with null DNS and IP addresses")
	}
	port := addr.Port
	if port == 0 {
		port = 80
	}
	baseURL := "http://" + net.JoinHostPort(host, strconv.Itoa(int(port)))
	cred, err := cli.TransferOwnership2(context.TODO(), baseURL, to1d, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TO2 failed for %q: %v\n", baseURL, err)
		return nil
	}
	return cred
}
