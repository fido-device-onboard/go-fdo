// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

type fallibleHash interface {
	Err() error
}

// Compute an hmac.
func hmacHash(h hash.Hash, v any) (protocol.Hmac, error) {
	var hmac protocol.Hmac
	switch size := h.Size(); size {
	case sha256.Size:
		hmac.Algorithm = protocol.HmacSha256Hash
		if h == nil {
			panic("HMAC-SHA256 support is required")
		}
	case sha512.Size384:
		hmac.Algorithm = protocol.HmacSha384Hash
		if h == nil {
			return protocol.Hmac{}, fmt.Errorf("unsupported hash algorithm: HMAC-SHA384")
		}
	default:
		return protocol.Hmac{}, fmt.Errorf("unsupported hash size: %d", size)
	}

	h.Reset()
	if err := cbor.NewEncoder(h).Encode(v); err != nil {
		return protocol.Hmac{}, fmt.Errorf("error computing hmac: marshaling payload: %w", err)
	}
	hmac.Value = h.Sum(nil)
	if fallible, ok := h.(fallibleHash); ok {
		if err := fallible.Err(); err != nil {
			return protocol.Hmac{}, fmt.Errorf("error computing hmac: %w", err)
		}
	}
	return hmac, nil
}

// hmacVerify encodes the given value to CBOR and verifies that the given HMAC
// matches it. If the cryptographic portion of verification fails, then
// ErrCryptoVerifyFailed is wrapped.
func hmacVerify(h256, h384 hash.Hash, h1 protocol.Hmac, v any) error {
	if h256 == nil {
		panic("HMAC-SHA256 support is required")
	}

	var h hash.Hash
	switch h1.Algorithm {
	case protocol.HmacSha256Hash:
		h = h256
	case protocol.HmacSha384Hash:
		h = h384
	}
	if h == nil {
		return fmt.Errorf("unsupported hash algorithm: %s", h1.Algorithm)
	}

	h.Reset()
	if err := cbor.NewEncoder(h).Encode(v); err != nil {
		return fmt.Errorf("error computing hmac: marshaling payload: %w", err)
	}
	mac2 := h.Sum(nil)
	if fallible, ok := h.(fallibleHash); ok {
		if err := fallible.Err(); err != nil {
			return fmt.Errorf("error computing hmac: %w", err)
		}
	}
	if !hmac.Equal(h1.Value, mac2) {
		return fmt.Errorf("%w: hmac did not match", ErrCryptoVerifyFailed)
	}
	return nil
}
