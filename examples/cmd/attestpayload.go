// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

var attestPayloadFlags = flag.NewFlagSet("attestpayload", flag.ContinueOnError)

var (
	apDB          string
	apDBPass      string
	apEncrypt     bool
	apDelegate    string
	apOutput      string
	apPayloadFile string
	apPayloadText string
	apPayloadType string
	apVoucher     string
	// Validity fields
	apExpires string
	apID      string
	apGen     int
)

func init() {
	attestPayloadFlags.StringVar(&apDB, "db", "fdo.db", "SQLite database path")
	attestPayloadFlags.StringVar(&apDBPass, "db-pass", "", "SQLite database encryption passphrase")
	attestPayloadFlags.BoolVar(&apEncrypt, "encrypt", false, "Encrypt the payload (requires RSA device key)")
	attestPayloadFlags.StringVar(&apDelegate, "delegate", "", "Sign with delegate chain (chain name from database)")
	attestPayloadFlags.StringVar(&apOutput, "output", "", "Output file (default: stdout)")
	attestPayloadFlags.StringVar(&apPayloadFile, "file", "", "Payload file to sign")
	attestPayloadFlags.StringVar(&apPayloadText, "payload", "", "Payload text to sign (alternative to -file)")
	attestPayloadFlags.StringVar(&apPayloadType, "type", "", "MIME type of payload (e.g., text/x-shellscript)")
	attestPayloadFlags.StringVar(&apVoucher, "voucher", "", "PEM-encoded voucher file (required for create)")
	// Validity flags
	attestPayloadFlags.StringVar(&apExpires, "expires", "", "Expiration datetime in ISO 8601 format (e.g., 2025-12-31T23:59:59Z)")
	attestPayloadFlags.StringVar(&apID, "id", "", "Identifier for grouping/ordering payloads")
	attestPayloadFlags.IntVar(&apGen, "gen", 0, "Generation number for supersession (higher supersedes lower)")
	attestPayloadFlags.Usage = attestPayloadUsage
}

func attestPayloadUsage() {
	fmt.Fprintf(os.Stderr, `
Usage:
  fdo attestpayload <command> [options]

Commands:
  create    Create a new attested payload
  verify    Verify an attested payload

Create options:
%s
Examples:
  # Create plaintext attested payload
  fdo attestpayload create -db test.db -payload "Hello World" -output payload.fdo

  # Create encrypted attested payload
  fdo attestpayload create -db test.db -payload "Secret data" -encrypt -output encrypted.fdo

  # Create delegate-signed attested payload
  fdo attestpayload create -db test.db -payload "Delegated" -delegate mychain -output delegated.fdo

Verify options:
  -db       SQLite database path (default: fdo.db)

Examples:
  # Verify and decrypt attested payload
  fdo attestpayload verify -db test.db payload.fdo

`, options(attestPayloadFlags))
}

func attestPayload(args []string) error {
	if len(args) < 1 {
		attestPayloadUsage()
		return fmt.Errorf("no command specified")
	}

	cmd := args[0]
	cmdArgs := args[1:]

	switch cmd {
	case "create":
		return attestPayloadCreate(cmdArgs)
	case "verify":
		return attestPayloadVerify(cmdArgs)
	case "help":
		attestPayloadUsage()
		return nil
	default:
		return fmt.Errorf("unknown command: %s", cmd)
	}
}

func attestPayloadCreate(args []string) error {
	if err := attestPayloadFlags.Parse(args); err != nil {
		return err
	}

	// Open database
	state, err := sqlite.Open(apDB, apDBPass)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() { _ = state.Close() }()

	// Get payload
	var payload []byte
	if apPayloadFile != "" {
		payload, err = os.ReadFile(filepath.Clean(apPayloadFile))
		if err != nil {
			return fmt.Errorf("failed to read payload file: %w", err)
		}
	} else if apPayloadText != "" {
		payload = []byte(apPayloadText)
	} else {
		return fmt.Errorf("either -file or -payload must be specified")
	}

	// Get voucher from file
	if apVoucher == "" {
		return fmt.Errorf("-voucher flag is required")
	}
	voucherPEM, err := os.ReadFile(filepath.Clean(apVoucher))
	if err != nil {
		return fmt.Errorf("failed to read voucher file: %w", err)
	}
	block, _ := pem.Decode(voucherPEM)
	if block == nil {
		return fmt.Errorf("invalid PEM-encoded voucher file")
	}
	if block.Type != "OWNERSHIP VOUCHER" {
		return fmt.Errorf("expected OWNERSHIP VOUCHER PEM block, got %s", block.Type)
	}
	var ov fdo.Voucher
	if err := cbor.Unmarshal(block.Bytes, &ov); err != nil {
		return fmt.Errorf("failed to parse voucher: %w", err)
	}

	// Get signing key (owner or delegate)
	var signingKey crypto.Signer
	var delegateChain []*x509.Certificate

	if apDelegate != "" {
		// Use delegate key
		key, chain, err := state.DelegateKey(apDelegate)
		if err != nil {
			return fmt.Errorf("failed to get delegate key %q: %w", apDelegate, err)
		}
		signingKey = key
		delegateChain = chain
		fmt.Printf("Signing with delegate: %s\n", apDelegate)
	} else {
		// Use owner key
		ownerKey, _, err := state.OwnerKey(nil, ov.Header.Val.ManufacturerKey.Type, ov.Header.Val.ManufacturerKey.RsaBits())
		if err != nil {
			return fmt.Errorf("failed to get owner key: %w", err)
		}
		signingKey = ownerKey
		fmt.Println("Signing with owner key")
	}

	// Prepare data to sign and optional encryption
	var payloadData []byte
	var iv, ciphertext, wrappedKey []byte

	if apEncrypt {
		// Get device public key for encryption (from voucher cert chain)
		devicePubKey, err := getDeviceRSAPublicKey(&ov)
		if err != nil {
			return fmt.Errorf("encryption requires RSA device key: %w", err)
		}

		// Encrypt payload
		wrappedKey, iv, ciphertext, err = fdo.EncryptPayload(devicePubKey, payload)
		if err != nil {
			return fmt.Errorf("failed to encrypt payload: %w", err)
		}
		payloadData = ciphertext
		fmt.Println("Payload encrypted")
	} else {
		payloadData = payload
	}

	// Build validity if any fields are set
	var validity *fdo.PayloadValidity
	if apExpires != "" || apID != "" || apGen != 0 {
		validity = &fdo.PayloadValidity{
			Expires: apExpires,
			ID:      apID,
			Gen:     apGen,
		}
	}

	// Build data to sign with length prefixes: len(PayloadType) || PayloadType || len(Validity) || Validity || PayloadData
	if apPayloadType != "" {
		fmt.Printf("Payload type: %s\n", apPayloadType)
	}
	if validity != nil {
		fmt.Printf("Validity: %s\n", validity.ToJSON())
	}
	dataToSign := fdo.BuildSignedData(apPayloadType, validity, payloadData)

	// Sign the data
	signature, err := signData(signingKey, dataToSign)
	if err != nil {
		return fmt.Errorf("failed to sign payload: %w", err)
	}

	// Build output
	output, err := buildAttestedPayloadPEM(&ov, payload, signature, delegateChain, iv, ciphertext, wrappedKey, apEncrypt, apPayloadType, validity)
	if err != nil {
		return fmt.Errorf("failed to build output: %w", err)
	}

	// Write output
	if apOutput != "" {
		if err := os.WriteFile(apOutput, output, 0600); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Printf("Attested payload written to: %s\n", apOutput)
	} else {
		fmt.Println(string(output))
	}

	return nil
}

func attestPayloadVerify(args []string) error {
	if err := attestPayloadFlags.Parse(args); err != nil {
		return err
	}

	if attestPayloadFlags.NArg() < 1 {
		return fmt.Errorf("no input file specified")
	}
	inputFile := attestPayloadFlags.Arg(0)

	// Open database
	state, err := sqlite.Open(apDB, apDBPass)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() { _ = state.Close() }()

	// Read input file
	pemData, err := os.ReadFile(filepath.Clean(inputFile))
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Parse and verify
	ap, ownerKey, devicePrivateKey, err := parseAttestedPayloadPEMForVerify(state, pemData)
	if err != nil {
		return err
	}

	// Verify and decrypt
	verifiedPayload, err := fdo.VerifyAttestedPayload(ap, *ownerKey, devicePrivateKey)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	// Output
	if ap.IsEncrypted() {
		fmt.Printf("Decrypted payload (%d bytes):\n", len(verifiedPayload))
	} else {
		fmt.Printf("Verified payload (%d bytes):\n", len(verifiedPayload))
	}
	fmt.Println(string(verifiedPayload))

	return nil
}

// getDeviceRSAPublicKey extracts the RSA public key from the voucher's device cert chain
func getDeviceRSAPublicKey(ov *fdo.Voucher) (*rsa.PublicKey, error) {
	if ov.CertChain == nil || len(*ov.CertChain) == 0 {
		return nil, fmt.Errorf("voucher has no certificate chain")
	}
	// Device cert is first in chain
	deviceCert := (*ov.CertChain)[0]
	rsaPubKey, ok := deviceCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("device key is not RSA (got %T)", deviceCert.PublicKey)
	}
	return rsaPubKey, nil
}

// signData signs data with SHA-384 hash
func signData(key crypto.Signer, data []byte) ([]byte, error) {
	hashed := sha512.Sum384(data)
	return key.Sign(rand.Reader, hashed[:], crypto.SHA384)
}

// buildAttestedPayloadPEM builds the PEM-encoded attested payload
func buildAttestedPayloadPEM(ov *fdo.Voucher, payload, signature []byte, delegateChain []*x509.Certificate, iv, ciphertext, wrappedKey []byte, encrypted bool, payloadType string, validity *fdo.PayloadValidity) ([]byte, error) {
	var output []byte

	// Voucher
	voucherBytes, err := cbor.Marshal(ov)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal voucher: %w", err)
	}
	output = append(output, pem.EncodeToMemory(&pem.Block{
		Type:  "OWNERSHIP VOUCHER",
		Bytes: voucherBytes,
	})...)

	// Delegate certificates (if any)
	for _, cert := range delegateChain {
		output = append(output, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}

	// Payload type (if specified)
	if payloadType != "" {
		output = append(output, pem.EncodeToMemory(&pem.Block{
			Type:  "PAYLOAD TYPE",
			Bytes: []byte(payloadType),
		})...)
	}

	// Validity (if specified)
	if validity != nil && !validity.IsEmpty() {
		output = append(output, pem.EncodeToMemory(&pem.Block{
			Type:  "VALIDITY",
			Bytes: []byte(validity.ToJSON()),
		})...)
	}

	if encrypted {
		// IV
		output = append(output, pem.EncodeToMemory(&pem.Block{
			Type:  "IV",
			Bytes: []byte(fmt.Sprintf("%x", iv)),
		})...)

		// Wrapped key
		output = append(output, pem.EncodeToMemory(&pem.Block{
			Type:  "WRAPPED ENCRYPTION KEY",
			Bytes: wrappedKey,
		})...)

		// Ciphertext
		output = append(output, pem.EncodeToMemory(&pem.Block{
			Type:  "CIPHERTEXT",
			Bytes: ciphertext,
		})...)
	} else {
		// Plaintext payload
		output = append(output, pem.EncodeToMemory(&pem.Block{
			Type:  "PAYLOAD",
			Bytes: payload,
		})...)
	}

	// Signature
	output = append(output, pem.EncodeToMemory(&pem.Block{
		Type:  "SIGNATURE",
		Bytes: signature,
	})...)

	return output, nil
}

// parseAttestedPayloadPEM parses PEM-encoded attested payload (reused from delegate.go)
func parseAttestedPayloadPEMForVerify(state *sqlite.DB, pemData []byte) (*fdo.AttestedPayload, *crypto.PublicKey, crypto.Signer, error) {
	var ownerKey *crypto.PublicKey
	var devicePrivateKey crypto.Signer
	ap := &fdo.AttestedPayload{}

	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}
		fmt.Printf("Block \"%s\"  -  %d bytes\n", block.Type, len(block.Bytes))

		switch block.Type {
		case "OWNERSHIP VOUCHER":
			result, err := InspectVoucherFull(state, block.Bytes)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("InspectVoucher failed: %w", err)
			}
			ownerKey = result.OwnerKey
			devicePrivateKey = result.PrivateKey

		case "IV":
			// IV might be hex-encoded or raw bytes
			if len(block.Bytes) == 32 {
				// Hex string
				_, err := fmt.Sscanf(string(block.Bytes), "%x", &ap.IV)
				if err != nil {
					ap.IV = block.Bytes
				}
			} else {
				ap.IV = block.Bytes
			}
			fmt.Printf("IV Data %x\n", ap.IV)

		case "CIPHERTEXT":
			ap.Ciphertext = block.Bytes
			fmt.Printf("Ciphertext Data %x\n", block.Bytes)

		case "WRAPPED ENCRYPTION KEY":
			ap.WrappedKey = block.Bytes
			fmt.Printf("Wrapped Encryption Key %x\n", block.Bytes)

		case "PAYLOAD":
			ap.Payload = block.Bytes

		case "PAYLOAD TYPE":
			ap.PayloadType = string(block.Bytes)
			fmt.Printf("Payload Type: %s\n", ap.PayloadType)

		case "VALIDITY":
			validity, err := fdo.ParseValidity(string(block.Bytes))
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to parse validity: %w", err)
			}
			ap.Validity = validity
			fmt.Printf("Validity: %s\n", string(block.Bytes))

		case "SIGNATURE":
			ap.Signature = block.Bytes

		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			fmt.Printf("DELEGATE CERT \"%s\"  -  %d bytes\n", block.Type, len(block.Bytes))
			ap.DelegateChain = append(ap.DelegateChain, cert)

		default:
			fmt.Printf("Unknown Block %s\n", block.Type)
		}
		pemData = rest
	}

	if ownerKey == nil {
		return nil, nil, nil, fmt.Errorf("no ownership voucher found")
	}

	return ap, ownerKey, devicePrivateKey, nil
}

// Helper to encode bytes as base64 for text output
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Helper to get owner key type for signing
func getOwnerKeyForSigning(state *sqlite.DB, ov *fdo.Voucher) (crypto.Signer, error) {
	keyType := ov.Header.Val.ManufacturerKey.Type
	rsaBits := ov.Header.Val.ManufacturerKey.RsaBits()
	key, _, err := state.OwnerKey(nil, keyType, rsaBits)
	if err != nil {
		return nil, err
	}
	return key, nil
}
