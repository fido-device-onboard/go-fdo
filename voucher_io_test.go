// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseVoucherFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join("testdata", "ov.pem")
	voucher, err := ParseVoucherFile(path)
	if err != nil {
		t.Fatalf("ParseVoucherFile(%s) = %v", path, err)
	}
	if voucher.Header.Val.DeviceInfo == "" {
		t.Fatal("voucher header missing device info")
	}
}

func TestParseVoucherStringPEM(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("testdata", "ov.pem"))
	if err != nil {
		t.Fatalf("read ov.pem: %v", err)
	}

	v, err := ParseVoucherString(string(data))
	if err != nil {
		t.Fatalf("ParseVoucherString PEM failed: %v", err)
	}
	if v.Header.Val.DeviceInfo == "" {
		t.Fatal("voucher header missing device info")
	}
}

func TestParseVoucherStringCBOR(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("testdata", "ov.pem"))
	if err != nil {
		t.Fatalf("read ov.pem: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("pem decode failed")
	}

	v, err := ParseVoucherString(string(block.Bytes))
	if err != nil {
		t.Fatalf("ParseVoucherString CBOR failed: %v", err)
	}
	if v.Header.Val.DeviceInfo == "" {
		t.Fatal("voucher header missing device info")
	}
}

func TestParseVoucherPEMErrors(t *testing.T) {
	t.Parallel()

	t.Run("missing block", func(t *testing.T) {
		t.Parallel()

		if _, err := ParseVoucherPEM([]byte("not pem")); err == nil {
			t.Fatal("expected error for missing PEM")
		}
	})

	t.Run("wrong type", func(t *testing.T) {
		t.Parallel()

		block := &pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x01}}
		buf := strings.Builder{}
		if err := pem.Encode(&buf, block); err != nil {
			t.Fatalf("pem encode: %v", err)
		}
		if _, err := ParseVoucherPEM([]byte(buf.String())); err == nil {
			t.Fatal("expected error for wrong type")
		}
	})
}

func TestParseVoucherCBORErrors(t *testing.T) {
	t.Parallel()

	if _, err := ParseVoucherCBOR(nil); err == nil {
		t.Fatal("expected error for empty data")
	}

	if _, err := ParseVoucherCBOR([]byte("not cbor")); err == nil {
		t.Fatal("expected error for invalid CBOR")
	}
}
