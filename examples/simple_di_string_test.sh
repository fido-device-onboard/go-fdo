#!/bin/bash
# Simple DI server that accepts string device info for Rust client testing

set -e

DB_FILE="${1:-/tmp/simple_di_test.db}"
HTTP_ADDR="${2:-127.0.0.1:8888}"

echo "Starting simple string-based DI server..."
echo "Database: $DB_FILE"
echo "Address: $HTTP_ADDR"
echo ""
echo "This server accepts STRING device info (not DeviceMfgInfo struct)"
echo "Compatible with Rust FDO client"
echo ""

# Create a minimal Go program inline
cat >/tmp/simple_di_server_main.go <<'EOF'
package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"log"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/sqlite"
	"github.com/fido-device-onboard/go-fdo/transport"
)

func main() {
	httpAddr := flag.String("http", "127.0.0.1:8080", "HTTP listen address")
	dbPath := flag.String("db", "simple_di.db", "SQLite database path")
	debug := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()

	ctx := context.Background()
	db, err := sqlite.Open(*dbPath, "")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	if err := db.InitializeManufacturerKeyIfNotExist(ctx); err != nil {
		log.Fatalf("Failed to initialize: %v", err)
	}

	mfgKey, mfgChain, err := db.ManufacturerKey(ctx, protocol.Secp384r1KeyType, 0)
	if err != nil {
		log.Fatalf("Failed to get key: %v", err)
	}

	// STRING-based DI server (not DeviceMfgInfo)
	diServer := &fdo.DIServer[string]{
		Session:  db,
		Vouchers: db,
		DeviceInfo: func(ctx context.Context, info *string, _ []*x509.Certificate) (string, protocol.PublicKey, error) {
			deviceInfo := "unknown"
			if info != nil {
				deviceInfo = *info
			}
			mfgPubKey, err := protocol.EncodeKey(protocol.X509KeyEnc, mfgKey.Public(), mfgChain)
			if err != nil {
				return "", protocol.PublicKey{}, err
			}
			return deviceInfo, *mfgPubKey, nil
		},
		SignDeviceCertificate: func(info *string) ([]*x509.Certificate, error) {
			return mfgChain, nil
		},
		RvInfo: func(ctx context.Context, v *fdo.Voucher) ([][]protocol.RvInstruction, error) {
			return [][]protocol.RvInstruction{{{Variable: protocol.RVOwnerOnly, Value: true}}}, nil
		},
	}

	handler := &transport.Handler{Tokens: db, DIResponder: diServer}
	if *debug {
		transport.DebugResponses = true
		transport.DebugRequests = true
	}

	log.Printf("String-based DI server listening on %s (accepts string device info)", *httpAddr)
	if err := transport.ListenAndServe(*httpAddr, *httpAddr, handler, nil); err != nil {
		log.Fatal(err)
	}
}
EOF

# Run the server
cd /tmp
go mod init simple_di_server 2>/dev/null || true
go get github.com/fido-device-onboard/go-fdo@latest 2>/dev/null || true
go run simple_di_server_main.go -http "$HTTP_ADDR" -db "$DB_FILE" -debug
