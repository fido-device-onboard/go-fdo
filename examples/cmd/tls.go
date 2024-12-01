// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build !tinygo

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"net"
	net_http "net/http"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/http"
)

var insecureTLS bool

func tlsTransport(baseURL string, conf *tls.Config) fdo.Transport {
	if conf == nil {
		conf = &tls.Config{
			InsecureSkipVerify: insecureTLS, //nolint:gosec
		}
	}

	return &http.Transport{
		BaseURL: baseURL,
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

func serveTLS(lis net.Listener, srv *net_http.Server, db *sql.DB) error {
	cert, err := tlsCert(db)
	if err != nil {
		return err
	}
	srv.TLSConfig = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*cert},
	}
	return srv.ServeTLS(lis, "", "")
}

func tlsCert(db *sql.DB) (*tls.Certificate, error) {
	// Ensure that the https table exists
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS https
		( cert BLOB NOT NULL
		, key BLOB NOT NULL
		)`); err != nil {
		return nil, err
	}

	// Load a TLS cert and key from the database
	row := db.QueryRow("SELECT cert, key FROM https LIMIT 1")
	var certDer, keyDer []byte
	if err := row.Scan(&certDer, &keyDer); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if len(keyDer) > 0 {
		key, err := x509.ParsePKCS8PrivateKey(keyDer)
		if err != nil {
			return nil, fmt.Errorf("bad HTTPS key stored: %w", err)
		}
		return &tls.Certificate{
			Certificate: [][]byte{certDer},
			PrivateKey:  key,
		}, nil
	}

	// Generate a new self-signed TLS CA
	tlsKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, tlsKey.Public(), tlsKey)
	if err != nil {
		return nil, err
	}
	tlsCA, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	// Store TLS cert and key to the database
	keyDER, err := x509.MarshalPKCS8PrivateKey(tlsKey)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec("INSERT INTO https (cert, key) VALUES (?, ?)", caDER, keyDER); err != nil {
		return nil, err
	}

	// Use CA to serve TLS
	return &tls.Certificate{
		Certificate: [][]byte{tlsCA.Raw},
		PrivateKey:  tlsKey,
	}, nil
}
