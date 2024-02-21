// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
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
	"github.com/fido-device-onboard/go-fdo/kex"
)

var serverFlags = flag.NewFlagSet("server", flag.ContinueOnError)

var (
	addr string
)

func init() {
	serverFlags.StringVar(&addr, "http", ":8080", "Address to listen on")
	serverFlags.BoolVar(&debug, "debug", false, "Print HTTP contents")
}

func server() error {
	// Parse listening address
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid addr: %w", err)
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}

	// Configure state
	stateless, err := token.NewService()
	if err != nil {
		return err
	}
	inMemory := memory.NewState()

	// Listen and serve
	return (&http.Server{
		Addr: addr,
		Handler: &transport.Handler{
			Responder: &fdo.Server{
				State:      stateless,
				Devices:    inMemory,
				NewDevices: stateless,
				RvInfo: [][]fdo.RvInstruction{
					{
						{
							Variable: fdo.RVProtocol,
							Value:    mustMarshal(fdo.RVProtHTTP),
						},
						{
							Variable: fdo.RVIPAddress,
							Value:    mustMarshal(net.IP{127, 0, 0, 1}),
						},
						{
							Variable: fdo.RVDevPort,
							Value:    mustMarshal(portNum),
						},
					},
				},
			},
			Session: func(ctx context.Context, token string) (kex.Session, error) {
				// TODO: When implementing TO2
				return nil, nil
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
