// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"crypto/tls"
	"net"
	net_http "net/http"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/http"
)

var insecureTLS bool

func tlsTransport(conf *tls.Config) fdo.Transport {
	if conf == nil {
		conf = &tls.Config{
			InsecureSkipVerify: insecureTLS, //nolint:gosec
		}
	}

	return &http.Transport{
		Client: &net_http.Client{Transport: &net_http.Transport{
			Proxy: net_http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSClientConfig:       conf,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}},
	}
}
