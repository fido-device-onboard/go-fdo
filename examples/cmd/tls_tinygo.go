// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build tinygo

package main

import (
	"crypto/tls"
	"database/sql"
	"net"
	net_http "net/http"
	"strings"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/http"
)

var insecureTLS bool

func tlsTransport(baseURL string, conf *tls.Config) fdo.Transport {
	if conf != nil || strings.HasPrefix(baseURL, "https") {
		panic("TLS unsupported by TinyGo")
	}
	return &http.Transport{
		BaseURL: baseURL,
		Client:  &net_http.Client{Transport: net_http.DefaultTransport},
	}
}

func serveTLS(lis net.Listener, srv *net_http.Server, db *sql.DB) error {
	panic("TLS unsupported by TinyGo")
}
