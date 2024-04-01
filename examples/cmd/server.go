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
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/fsim"
	transport "github.com/fido-device-onboard/go-fdo/http"
	"github.com/fido-device-onboard/go-fdo/internal/memory"
	"github.com/fido-device-onboard/go-fdo/internal/token"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

var serverFlags = flag.NewFlagSet("server", flag.ContinueOnError)

var (
	addr       string
	dbPath     string
	extAddr    string
	rvBypass   bool
	downloads  stringList
	uploadDir  string
	uploadReqs stringList
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
	serverFlags.StringVar(&dbPath, "db", "", "SQLite database file path (defaults to in-memory)")
	serverFlags.BoolVar(&debug, "debug", false, "Print HTTP contents")
	serverFlags.StringVar(&extAddr, "ext-http", "", "External `addr`ess devices should connect to (default \"127.0.0.1:${LISTEN_PORT}\")")
	serverFlags.StringVar(&addr, "http", "localhost:8080", "The `addr`ess to listen on")
	serverFlags.BoolVar(&rvBypass, "rv-bypass", false, "Skip TO1")
	serverFlags.Var(&downloads, "download", "Use fdo.download FSIM for each `file` (flag may be used multiple times)")
	serverFlags.StringVar(&uploadDir, "upload-dir", "uploads", "The directory `path` to put file uploads")
	serverFlags.Var(&uploadReqs, "upload", "Use fdo.upload FSIM for each `file` (flag may be used multiple times)")
}

func server() error {
	// RV Info
	rvInfo := [][]fdo.RvInstruction{{{Variable: fdo.RVProtocol, Value: mustMarshal(fdo.RVProtHTTP)}}}
	if extAddr == "" {
		extAddr = addr
	}
	host, port, err := net.SplitHostPort(extAddr)
	if err != nil {
		return fmt.Errorf("invalid external addr: %w", err)
	}
	if host == "" {
		rvInfo[0] = append(rvInfo[0], fdo.RvInstruction{Variable: fdo.RVIPAddress, Value: mustMarshal(net.IP{127, 0, 0, 1})})
	} else if hostIP := net.ParseIP(host); hostIP.To4() != nil || hostIP.To16() != nil {
		rvInfo[0] = append(rvInfo[0], fdo.RvInstruction{Variable: fdo.RVIPAddress, Value: mustMarshal(hostIP)})
	} else {
		rvInfo[0] = append(rvInfo[0], fdo.RvInstruction{Variable: fdo.RVDns, Value: mustMarshal(host)})
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid external port: %w", err)
	}
	rvInfo[0] = append(rvInfo[0], fdo.RvInstruction{Variable: fdo.RVDevPort, Value: mustMarshal(portNum)})
	if rvBypass {
		rvInfo[0] = append(rvInfo[0], fdo.RvInstruction{Variable: fdo.RVBypass})
	}

	// Create FDO responder
	srv, err := newServer(rvInfo, startFSIMs)
	if err != nil {
		return err
	}

	// Listen and serve
	handler := http.NewServeMux()
	handler.Handle("POST /fdo/101/msg/{msg}", &transport.Handler{
		Debug:     debug,
		Responder: srv,
	})
	return (&http.Server{
		Addr:    addr,
		Handler: handler,
	}).ListenAndServe()
}

func mustMarshal(v any) []byte {
	data, err := cbor.Marshal(v)
	if err != nil {
		panic(err.Error())
	}
	return data
}

func newServer(
	rvInfo [][]fdo.RvInstruction,
	startFSIMs func(context.Context, fdo.GUID, string, []*x509.Certificate, fdo.Devmod, []string) serviceinfo.OwnerModuleList,
) (*fdo.Server, error) {
	if dbPath != "" {
		return newPersistentServer(rvInfo, startFSIMs)
	}

	stateless, err := token.NewService()
	if err != nil {
		return nil, err
	}
	inMemory, err := memory.NewState()
	if err != nil {
		return nil, err
	}
	inMemory.AutoExtend = stateless

	return &fdo.Server{
		State:        stateless,
		NewDevices:   stateless,
		Proofs:       stateless,
		Replacements: stateless,
		KeyExchange:  stateless,
		Nonces:       stateless,
		ServiceInfo:  stateless,
		Devices:      inMemory,
		OwnerKeys:    inMemory,
		RvInfo:       rvInfo,
		StartFSIMs:   startFSIMs,
	}, nil
}

//nolint:gocyclo
func newPersistentServer(
	rvInfo [][]fdo.RvInstruction,
	startFSIMs func(context.Context, fdo.GUID, string, []*x509.Certificate, fdo.Devmod, []string) serviceinfo.OwnerModuleList,
) (*fdo.Server, error) {
	state, err := sqlite.New(dbPath)
	if err != nil {
		return nil, err
	}
	state.AutoExtend = true
	state.PreserveReplacedVouchers = true

	// Generate manufacturing component keys
	rsaMfgKey, err := rsa.GenerateKey(rand.Reader, 2048)
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
	rsaChain, err := generateCA(rsaMfgKey)
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
	if err := state.AddManufacturerKey(fdo.RsaPkcsKeyType, rsaMfgKey, rsaChain); err != nil {
		return nil, err
	}
	if err := state.AddManufacturerKey(fdo.RsaPssKeyType, rsaMfgKey, rsaChain); err != nil {
		return nil, err
	}
	if err := state.AddManufacturerKey(fdo.Secp256r1KeyType, ec256MfgKey, ec256Chain); err != nil {
		return nil, err
	}
	if err := state.AddManufacturerKey(fdo.Secp384r1KeyType, ec384MfgKey, ec384Chain); err != nil {
		return nil, err
	}

	// Generate owner keys
	rsaOwnerKey, err := rsa.GenerateKey(rand.Reader, 2048)
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
	if err := state.AddOwnerKey(fdo.RsaPkcsKeyType, rsaOwnerKey, nil); err != nil {
		return nil, err
	}
	if err := state.AddOwnerKey(fdo.RsaPssKeyType, rsaOwnerKey, nil); err != nil {
		return nil, err
	}
	if err := state.AddOwnerKey(fdo.Secp256r1KeyType, ec256OwnerKey, nil); err != nil {
		return nil, err
	}
	if err := state.AddOwnerKey(fdo.Secp384r1KeyType, ec384OwnerKey, nil); err != nil {
		return nil, err
	}

	return &fdo.Server{
		State:        state,
		NewDevices:   state,
		Proofs:       state,
		Replacements: state,
		KeyExchange:  state,
		Nonces:       state,
		ServiceInfo:  state,
		Devices:      state,
		OwnerKeys:    state,
		RvInfo:       rvInfo,
		StartFSIMs:   startFSIMs,
	}, nil
}

func startFSIMs(ctx context.Context, guid fdo.GUID, info string, chain []*x509.Certificate, devmod fdo.Devmod, modules []string) serviceinfo.OwnerModuleList {
	var list fsimList
	if slices.Contains(modules, "fdo.download") {
		for _, name := range downloads {
			f, err := os.Open(name)
			if err != nil {
				log.Fatalf("error opening %q for download FSIM: %v", name, err)
			}
			defer func() { _ = f.Close() }()

			list = append(list, &fsim.DownloadContents[*os.File]{
				Name:         name,
				Contents:     f,
				MustDownload: true,
			})
		}
	}
	if slices.Contains(modules, "fdo.upload") {
		for _, name := range uploadReqs {
			list = append(list, &fsim.UploadRequest{
				Dir:  uploadDir,
				Name: name,
			})
		}
	}
	return &list
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
