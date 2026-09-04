// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fido-device-onboard/go-fdo/fsim"
)

var metaFlags = flag.NewFlagSet("meta", flag.ContinueOnError)

func init() {
	metaFlags.Usage = func() {}
}

func metaPayload(args []string) error {
	if len(args) == 0 {
		return metaUsage()
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "create":
		return metaCreate(subargs)
	case "sign":
		return metaSign(subargs)
	case "verify":
		return metaVerify(subargs)
	case "create-signed":
		return metaCreateSigned(subargs)
	case "export-pubkey":
		return metaExportPubkey(subargs)
	case "help":
		return metaUsage()
	default:
		return fmt.Errorf("unknown meta subcommand %q; run 'fdo meta help'", subcmd)
	}
}

func metaUsage() error {
	fmt.Fprintf(os.Stderr, `Usage: fdo meta <command> [options]

Commands:
  create         Create an unsigned meta-payload CBOR file
  sign           Sign an existing meta-payload with a private key
  verify         Verify a signed meta-payload and optionally print contents
  create-signed  Create and sign a meta-payload in one step
  export-pubkey  Export a private key's public key as COSE_Key CBOR
  help           Show this help

Examples:
  fdo meta create -mime "application/x-raw-disk-image" -url "http://cdn.example.com/image.bin" \
    -hash-file image.bin -name "boot-image" -out meta.cbor

  fdo meta sign -in meta.cbor -key owner-key.pem -out meta-signed.cbor

  fdo meta verify -in meta-signed.cbor -key owner-pub.pem -print

  fdo meta create-signed -mime "application/x-raw-disk-image" -url "http://cdn.example.com/image.bin" \
    -hash-file image.bin -key owner-key.pem -out meta-signed.cbor

  fdo meta export-pubkey -key owner-key.pem -out signer.cbor
`)
	return nil
}

func metaCreate(args []string) error {
	fs := flag.NewFlagSet("meta create", flag.ContinueOnError)
	var (
		mimeType string
		url      string
		hashFile string
		name     string
		bootArgs string
		version  string
		desc     string
		outFile  string
	)
	fs.StringVar(&mimeType, "mime", "", "MIME type of the actual image (required)")
	fs.StringVar(&url, "url", "", "URL where the actual image can be fetched (required)")
	fs.StringVar(&hashFile, "hash-file", "", "Path to the actual image file (computes sha256 hash)")
	fs.StringVar(&name, "name", "", "Optional image name")
	fs.StringVar(&bootArgs, "boot-args", "", "Optional kernel/boot arguments")
	fs.StringVar(&version, "version", "", "Optional version string")
	fs.StringVar(&desc, "description", "", "Optional description")
	fs.StringVar(&outFile, "out", "", "Output file path (required)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if mimeType == "" || url == "" || outFile == "" {
		return fmt.Errorf("meta create requires -mime, -url, and -out flags")
	}

	var expectedHash []byte
	hashAlg := ""
	if hashFile != "" {
		data, err := os.ReadFile(filepath.Clean(hashFile))
		if err != nil {
			return fmt.Errorf("reading hash-file: %w", err)
		}
		expectedHash = fsim.ComputeSHA256(data)
		hashAlg = "sha256"
		fmt.Fprintf(os.Stderr, "Computed SHA-256: %s\n", hex.EncodeToString(expectedHash))
	}

	var opts []fsim.MetaPayloadOption
	if bootArgs != "" {
		opts = append(opts, fsim.WithBootArgs(bootArgs))
	}
	if version != "" {
		opts = append(opts, fsim.WithVersion(version))
	}
	if desc != "" {
		opts = append(opts, fsim.WithDescription(desc))
	}

	data, err := fsim.CreateMetaPayload(mimeType, url, name, hashAlg, expectedHash, opts...)
	if err != nil {
		return fmt.Errorf("creating meta-payload: %w", err)
	}

	if err := os.WriteFile(outFile, data, 0600); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Created meta-payload: %s (%d bytes)\n", outFile, len(data))
	return nil
}

func metaSign(args []string) error {
	fs := flag.NewFlagSet("meta sign", flag.ContinueOnError)
	var (
		inFile  string
		keyFile string
		outFile string
	)
	fs.StringVar(&inFile, "in", "", "Input meta-payload CBOR file (required)")
	fs.StringVar(&keyFile, "key", "", "PEM private key file for signing (required)")
	fs.StringVar(&outFile, "out", "", "Output signed meta-payload file (required)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if inFile == "" || keyFile == "" || outFile == "" {
		return fmt.Errorf("meta sign requires -in, -key, and -out flags")
	}

	payload, err := os.ReadFile(filepath.Clean(inFile))
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	signer, err := loadPrivateKeyPEM(keyFile)
	if err != nil {
		return fmt.Errorf("loading private key: %w", err)
	}

	signed, err := fsim.SignMetaPayload(payload, signer)
	if err != nil {
		return fmt.Errorf("signing meta-payload: %w", err)
	}

	if err := os.WriteFile(outFile, signed, 0600); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Signed meta-payload: %s (%d bytes)\n", outFile, len(signed))
	return nil
}

func metaVerify(args []string) error {
	fs := flag.NewFlagSet("meta verify", flag.ContinueOnError)
	var (
		inFile    string
		keyFile   string
		showPrint bool
	)
	fs.StringVar(&inFile, "in", "", "Signed meta-payload file to verify (required)")
	fs.StringVar(&keyFile, "key", "", "PEM public key file for verification (required)")
	fs.BoolVar(&showPrint, "print", false, "Print meta-payload contents after verification")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if inFile == "" || keyFile == "" {
		return fmt.Errorf("meta verify requires -in and -key flags")
	}

	signedData, err := os.ReadFile(filepath.Clean(inFile))
	if err != nil {
		return fmt.Errorf("reading input: %w", err)
	}

	pubKey, err := loadPublicKeyPEM(keyFile)
	if err != nil {
		return fmt.Errorf("loading public key: %w", err)
	}

	// Marshal public key to COSE_Key for the verifier
	pubKeyCBOR, err := fsim.MarshalSignerPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("marshaling public key: %w", err)
	}

	verifier := &fsim.CoseSign1Verifier{}
	payload, err := verifier.Verify(signedData, pubKeyCBOR)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Signature verified OK\n")

	if showPrint {
		var meta fsim.MetaPayload
		if err := meta.UnmarshalCBOR(payload); err != nil {
			return fmt.Errorf("parsing meta-payload: %w", err)
		}
		fmt.Printf("  MIME Type:  %s\n", meta.MIMEType)
		fmt.Printf("  URL:        %s\n", meta.URL)
		if meta.Name != "" {
			fmt.Printf("  Name:       %s\n", meta.Name)
		}
		if meta.HashAlg != "" {
			fmt.Printf("  Hash Alg:   %s\n", meta.HashAlg)
		}
		if len(meta.ExpectedHash) > 0 {
			fmt.Printf("  Hash:       %s\n", hex.EncodeToString(meta.ExpectedHash))
		}
		if meta.BootArgs != "" {
			fmt.Printf("  Boot Args:  %s\n", meta.BootArgs)
		}
		if meta.Version != "" {
			fmt.Printf("  Version:    %s\n", meta.Version)
		}
		if meta.Description != "" {
			fmt.Printf("  Desc:       %s\n", meta.Description)
		}
	}
	return nil
}

func metaCreateSigned(args []string) error {
	fs := flag.NewFlagSet("meta create-signed", flag.ContinueOnError)
	var (
		mimeType string
		url      string
		hashFile string
		name     string
		bootArgs string
		version  string
		desc     string
		keyFile  string
		outFile  string
	)
	fs.StringVar(&mimeType, "mime", "", "MIME type of the actual image (required)")
	fs.StringVar(&url, "url", "", "URL where the actual image can be fetched (required)")
	fs.StringVar(&hashFile, "hash-file", "", "Path to the actual image file (computes sha256 hash)")
	fs.StringVar(&name, "name", "", "Optional image name")
	fs.StringVar(&bootArgs, "boot-args", "", "Optional kernel/boot arguments")
	fs.StringVar(&version, "version", "", "Optional version string")
	fs.StringVar(&desc, "description", "", "Optional description")
	fs.StringVar(&keyFile, "key", "", "PEM private key file for signing (required)")
	fs.StringVar(&outFile, "out", "", "Output signed meta-payload file (required)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if mimeType == "" || url == "" || keyFile == "" || outFile == "" {
		return fmt.Errorf("meta create-signed requires -mime, -url, -key, and -out flags")
	}

	var expectedHash []byte
	hashAlg := ""
	if hashFile != "" {
		data, err := os.ReadFile(filepath.Clean(hashFile))
		if err != nil {
			return fmt.Errorf("reading hash-file: %w", err)
		}
		expectedHash = fsim.ComputeSHA256(data)
		hashAlg = "sha256"
		fmt.Fprintf(os.Stderr, "Computed SHA-256: %s\n", hex.EncodeToString(expectedHash))
	}

	var opts []fsim.MetaPayloadOption
	if bootArgs != "" {
		opts = append(opts, fsim.WithBootArgs(bootArgs))
	}
	if version != "" {
		opts = append(opts, fsim.WithVersion(version))
	}
	if desc != "" {
		opts = append(opts, fsim.WithDescription(desc))
	}

	metaCBOR, err := fsim.CreateMetaPayload(mimeType, url, name, hashAlg, expectedHash, opts...)
	if err != nil {
		return fmt.Errorf("creating meta-payload: %w", err)
	}

	signer, err := loadPrivateKeyPEM(keyFile)
	if err != nil {
		return fmt.Errorf("loading private key: %w", err)
	}

	signed, err := fsim.SignMetaPayload(metaCBOR, signer)
	if err != nil {
		return fmt.Errorf("signing meta-payload: %w", err)
	}

	if err := os.WriteFile(outFile, signed, 0600); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Created and signed meta-payload: %s (%d bytes)\n", outFile, len(signed))
	return nil
}

func metaExportPubkey(args []string) error {
	fs := flag.NewFlagSet("meta export-pubkey", flag.ContinueOnError)
	var (
		keyFile string
		outFile string
	)
	fs.StringVar(&keyFile, "key", "", "PEM private key file (required)")
	fs.StringVar(&outFile, "out", "", "Output COSE_Key CBOR file (required)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if keyFile == "" || outFile == "" {
		return fmt.Errorf("meta export-pubkey requires -key and -out flags")
	}

	signer, err := loadPrivateKeyPEM(keyFile)
	if err != nil {
		return fmt.Errorf("loading private key: %w", err)
	}

	coseKeyCBOR, err := fsim.MarshalSignerPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("marshaling public key: %w", err)
	}

	if err := os.WriteFile(outFile, coseKeyCBOR, 0600); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	// Also print the SHA-256 fingerprint for reference
	h := sha256.Sum256(coseKeyCBOR)
	fmt.Fprintf(os.Stderr, "Exported COSE_Key: %s (%d bytes, fingerprint: %s)\n",
		outFile, len(coseKeyCBOR), hex.EncodeToString(h[:8]))
	return nil
}

// loadPrivateKeyPEM loads a PEM-encoded private key from a file.
func loadPrivateKeyPEM(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing EC private key: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS8 private key: %w", err)
		}
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is %T, not ECDSA; only ECDSA keys are supported for meta-payload signing", key)
		}
		return ecKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q; expected EC PRIVATE KEY or PRIVATE KEY", block.Type)
	}
}

// loadPublicKeyPEM loads a PEM-encoded public key from a file.
// Supports PUBLIC KEY (PKIX) and also extracts from EC PRIVATE KEY or PRIVATE KEY.
func loadPublicKeyPEM(path string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing public key: %w", err)
		}
		ecKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key is %T, not ECDSA", key)
		}
		return ecKey, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing EC private key: %w", err)
		}
		return &key.PublicKey, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS8 private key: %w", err)
		}
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is %T, not ECDSA", key)
		}
		return &ecKey.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}
