// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"crypto"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"hermannm.dev/devlog"

	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/transfer"
)

var authFlags = flag.NewFlagSet("auth", flag.ContinueOnError)

var (
	authURL        string
	authKeyFile    string
	authHashAlg    string
	authPathPrefix string
	authVerbose    bool
)

func init() {
	authFlags.StringVar(&authURL, "url", "", "Base `URL` of the FDOKeyAuth service (required)")
	authFlags.StringVar(&authKeyFile, "key", "", "Path to PEM-encoded private key `file` (use \"-\" for stdin)")
	authFlags.StringVar(&authHashAlg, "hash", "sha256", "Hash algorithm: sha256 or sha384")
	authFlags.StringVar(&authPathPrefix, "path-prefix", "", "Service Root path prefix (default: /api/v1/pull/vouchers)")
	authFlags.BoolVar(&authVerbose, "verbose", false, "Print full result details (expiry, fingerprint, voucher count)")
	authFlags.BoolVar(&insecureTLS, "insecure-tls", false, "Skip TLS certificate verification")
	authFlags.BoolVar(&debug, "debug", debug, "Enable debug logging")
}

func auth() error {
	// Redirect slog to stderr so token output on stdout stays clean for piping
	slog.SetDefault(slog.New(devlog.NewHandler(os.Stderr, &devlog.Options{
		Level: &level,
	})))

	if debug {
		level.Set(slog.LevelDebug)
	}

	if authURL == "" {
		return fmt.Errorf("auth: -url is required")
	}
	if authKeyFile == "" {
		return fmt.Errorf("auth: -key is required")
	}

	// Load private key from PEM file or stdin
	key, err := loadPrivateKey(authKeyFile)
	if err != nil {
		return fmt.Errorf("auth: %w", err)
	}

	// Determine hash algorithm
	hashAlg, err := parseHashAlg(authHashAlg)
	if err != nil {
		return err
	}

	// Build HTTP client
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecureTLS, //nolint:gosec
			},
		},
	}

	// Build FDOKeyAuth client
	client := &transfer.FDOKeyAuthClient{
		CallerKey:  key,
		HashAlg:    hashAlg,
		HTTPClient: httpClient,
		BaseURL:    authURL,
		PathPrefix: authPathPrefix,
	}

	slog.Debug("starting FDOKeyAuth handshake", "url", authURL, "path_prefix", authPathPrefix)

	result, err := client.Authenticate()
	if err != nil {
		return fmt.Errorf("auth: authentication failed: %w", err)
	}

	// Print token to stdout (primary output, suitable for piping)
	fmt.Println(result.SessionToken)

	// Print additional details to stderr if verbose
	if authVerbose {
		expiresAt := time.Unix(int64(result.TokenExpiresAt), 0) //nolint:gosec // token expiry is within reasonable time range
		fmt.Fprintf(os.Stderr, "Status:          authenticated\n")
		fmt.Fprintf(os.Stderr, "Token expires:   %s\n", expiresAt.Format(time.RFC3339))
		fmt.Fprintf(os.Stderr, "Key fingerprint: %s\n", hex.EncodeToString(result.KeyFingerprint))
		if result.VoucherCount > 0 {
			fmt.Fprintf(os.Stderr, "Voucher count:   %d\n", result.VoucherCount)
		}
	}

	return nil
}

// loadPrivateKey reads a PEM-encoded private key from a file path or stdin ("-").
func loadPrivateKey(path string) (crypto.Signer, error) {
	var pemData []byte
	var err error

	if path == "-" {
		pemData, err = io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("failed to read key from stdin: %w", err)
		}
	} else {
		pemData, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %q: %w", path, err)
		}
	}

	return parsePrivateKeyPEM(pemData)
}

// parseHashAlg converts a string hash algorithm name to protocol.HashAlg.
func parseHashAlg(name string) (protocol.HashAlg, error) {
	switch name {
	case "sha256", "SHA256", "SHA-256":
		return protocol.Sha256Hash, nil
	case "sha384", "SHA384", "SHA-384":
		return protocol.Sha384Hash, nil
	default:
		return 0, fmt.Errorf("auth: unsupported hash algorithm %q (use sha256 or sha384)", name)
	}
}
