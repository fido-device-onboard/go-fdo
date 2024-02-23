// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	transport "github.com/fido-device-onboard/go-fdo/http"
	"github.com/fido-device-onboard/go-fdo/internal/memory"
	"github.com/fido-device-onboard/go-fdo/internal/token"
)

var serverFlags = flag.NewFlagSet("server", flag.ContinueOnError)

var (
	addr     string
	extAddr  string
	rvBypass bool
)

func init() {
	serverFlags.BoolVar(&debug, "debug", false, "Print HTTP contents")
	serverFlags.StringVar(&extAddr, "ext-http", "", "External `addr`ess devices should connect to (default \"127.0.0.1:${LISTEN_PORT}\")")
	serverFlags.StringVar(&addr, "http", ":8080", "The `addr`ess to listen on")
	serverFlags.BoolVar(&rvBypass, "rv-bypass", false, "Skip TO1")
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

	// Listen and serve
	return (&http.Server{
		Addr: addr,
		Handler: &transport.Handler{
			Responder: &fdo.Server{
				State:       stateless,
				NewDevices:  stateless,
				Proofs:      stateless,
				KeyExchange: stateless,
				Nonces:      stateless,

				Devices:   inMemory,
				OwnerKeys: inMemory,

				RvInfo: rvInfo,
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
