// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// ParseVoucherFile loads a voucher from the given path by delegating to
// ParseVoucherString. Files containing the PEM wrapper are decoded as PEM;
// otherwise their raw contents are treated as CBOR bytes.
func ParseVoucherFile(path string) (*Voucher, error) {
	// #nosec G304 -- callers control voucher paths; reading arbitrary voucher files is an explicit capability
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read voucher file: %w", err)
	}

	return ParseVoucherString(string(data))
}

// ParseVoucherString parses a voucher from an in-memory string. If the string
// contains the PEM wrapper the PEM decoder is used; otherwise the raw bytes are
// treated as CBOR.
func ParseVoucherString(contents string) (*Voucher, error) {
	if strings.Contains(contents, "-----BEGIN OWNERSHIP VOUCHER-----") {
		return ParseVoucherPEM([]byte(contents))
	}
	return ParseVoucherCBOR([]byte(contents))
}

// ParseVoucherPEM decodes a PEM-formatted ownership voucher into a Voucher.
func ParseVoucherPEM(data []byte) (*Voucher, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("ownership voucher PEM block not found")
	}
	if block.Type != "OWNERSHIP VOUCHER" {
		return nil, fmt.Errorf("unexpected PEM block type: %s", block.Type)
	}

	return ParseVoucherCBOR(block.Bytes)
}

// ParseVoucherCBOR unmarshals CBOR bytes into a Voucher.
func ParseVoucherCBOR(data []byte) (*Voucher, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("voucher data is empty")
	}

	var voucher Voucher
	if err := cbor.Unmarshal(data, &voucher); err != nil {
		return nil, fmt.Errorf("cbor unmarshal voucher: %w", err)
	}
	return &voucher, nil
}

// FormatVoucherPEM encodes a Voucher as a PEM-wrapped OWNERSHIP VOUCHER block.
// The CBOR-encoded voucher bytes are base64-encoded with proper line wrapping
// per RFC 7468.
func FormatVoucherPEM(v *Voucher) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("voucher is nil")
	}
	data, err := cbor.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("cbor marshal voucher: %w", err)
	}
	return FormatVoucherCBORToPEM(data), nil
}

// FormatVoucherCBORToPEM wraps raw CBOR voucher bytes in a PEM OWNERSHIP
// VOUCHER block with proper line wrapping per RFC 7468.
func FormatVoucherCBORToPEM(data []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "OWNERSHIP VOUCHER",
		Bytes: data,
	})
}
