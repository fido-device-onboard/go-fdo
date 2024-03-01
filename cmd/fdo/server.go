// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/fsim"
	transport "github.com/fido-device-onboard/go-fdo/http"
	"github.com/fido-device-onboard/go-fdo/internal/memory"
	"github.com/fido-device-onboard/go-fdo/internal/token"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

var serverFlags = flag.NewFlagSet("server", flag.ContinueOnError)

var (
	addr      string
	extAddr   string
	rvBypass  bool
	downloads stringList
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
	serverFlags.BoolVar(&debug, "debug", false, "Print HTTP contents")
	serverFlags.StringVar(&extAddr, "ext-http", "", "External `addr`ess devices should connect to (default \"127.0.0.1:${LISTEN_PORT}\")")
	serverFlags.StringVar(&addr, "http", "localhost:8080", "The `addr`ess to listen on")
	serverFlags.BoolVar(&rvBypass, "rv-bypass", false, "Skip TO1")
	serverFlags.Var(&downloads, "download", "Use fdo.download FSIM for each `file` (flag may be used multiple times)")
}

func server() error {
	// Configure state
	stateless, err := token.NewService()
	if err != nil {
		return err
	}
	inMemory, err := memory.NewState()
	if err != nil {
		return err
	}
	inMemory.AutoExtend = stateless

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

	// Prepare FSIMs
	var list fsimList
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

	// Listen and serve
	return (&http.Server{
		Addr: addr,
		Handler: &transport.Handler{
			Responder: &fdo.Server{
				State:        stateless,
				NewDevices:   stateless,
				Proofs:       stateless,
				Replacements: stateless,
				KeyExchange:  stateless,
				Nonces:       stateless,
				ServiceInfo:  stateless,

				Devices:   inMemory,
				OwnerKeys: inMemory,

				RvInfo: rvInfo,

				StartFSIMs: func(ctx context.Context, guid fdo.GUID, info string, chain []*x509.Certificate, devmod fdo.Devmod, modules []string) serviceinfo.OwnerModuleList {
					fmt.Printf("GUID: %x\n", guid)
					fmt.Printf("Device info: %s\n", info)
					fmt.Printf("Devmod: %s\n", devmod)
					fmt.Printf("Modules: %v\n", modules)
					return &list
				},
			},
			Debug: debug,
		},
	}).ListenAndServe()
}

func mustMarshal(v any) []byte {
	data, err := cbor.Marshal(v)
	if err != nil {
		panic(err.Error())
	}
	return data
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
