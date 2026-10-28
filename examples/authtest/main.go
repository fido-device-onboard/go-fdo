// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

// Package main implements a test server for FDOKeyAuth integration testing.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/transfer"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9998", "Address to listen on")
	flag.Parse()

	// Generate a server key for signing challenges
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate server key: %v", err)
	}

	// Create session store
	sessions := transfer.NewSessionStore(5*time.Minute, 100)

	// Create FDOKeyAuth server
	authServer := &transfer.FDOKeyAuthServer{
		ServerKey: serverKey,
		Sessions:  sessions,
		IssueToken: func(callerKey protocol.PublicKey) (string, time.Time, error) {
			// Return fixed token for testing
			return "integration-test-token-12345", time.Now().Add(time.Hour), nil
		},
	}

	// Register handlers at the default path prefix
	mux := http.NewServeMux()
	authServer.RegisterHandlers(mux) // Uses default "/api/v1/pull/vouchers" prefix

	fmt.Printf("Listening on %s\n", *addr)
	server := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
