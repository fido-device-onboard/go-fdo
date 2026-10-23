// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPrivateKey_ECFile(t *testing.T) {
	// Generate a test EC key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Write it as PEM to a temp file
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	path := filepath.Join(t.TempDir(), "test-key.pem")
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		t.Fatal(err)
	}

	// Load it back
	loaded, err := loadPrivateKey(path)
	if err != nil {
		t.Fatalf("loadPrivateKey(%q): %v", path, err)
	}

	ecLoaded, ok := loaded.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", loaded)
	}
	if !ecLoaded.Equal(key) {
		t.Error("loaded key does not match original")
	}
}

func TestLoadPrivateKey_PKCS8File(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	path := filepath.Join(t.TempDir(), "test-key.pem")
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		t.Fatal(err)
	}

	loaded, err := loadPrivateKey(path)
	if err != nil {
		t.Fatalf("loadPrivateKey(%q): %v", path, err)
	}

	ecLoaded, ok := loaded.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", loaded)
	}
	if !ecLoaded.Equal(key) {
		t.Error("loaded key does not match original")
	}
}

func TestLoadPrivateKey_Stdin(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	// Create a temp file to simulate stdin
	tmpFile, err := os.CreateTemp(t.TempDir(), "stdin-key-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmpFile.Write(pemData); err != nil {
		t.Fatal(err)
	}
	if _, err := tmpFile.Seek(0, 0); err != nil {
		t.Fatal(err)
	}

	// Replace os.Stdin temporarily
	oldStdin := os.Stdin
	os.Stdin = tmpFile
	defer func() { os.Stdin = oldStdin }()

	loaded, err := loadPrivateKey("-")
	if err != nil {
		t.Fatalf("loadPrivateKey(\"-\"): %v", err)
	}

	ecLoaded, ok := loaded.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", loaded)
	}
	if !ecLoaded.Equal(key) {
		t.Error("loaded key does not match original")
	}
}

func TestLoadPrivateKey_MissingFile(t *testing.T) {
	_, err := loadPrivateKey("/nonexistent/path/to/key.pem")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadPrivateKey_InvalidPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad-key.pem")
	if err := os.WriteFile(path, []byte("not a pem file"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := loadPrivateKey(path)
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestParseHashAlg(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"sha256", false},
		{"SHA256", false},
		{"SHA-256", false},
		{"sha384", false},
		{"SHA384", false},
		{"SHA-384", false},
		{"md5", true},
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := parseHashAlg(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseHashAlg(%q): err=%v, wantErr=%v", tt.input, err, tt.wantErr)
			}
		})
	}
}
