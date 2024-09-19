// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// Hash is a crypto hash, with length in bytes preceding. Hashes are computed
// in accordance with FIPS-180-4. See COSE assigned numbers for hash types.
//
//	Hash = [
//	    hashtype: int, ;; negative values possible
//	    hash: bstr
//	]
type Hash struct {
	Algorithm HashAlg
	Value     []byte
}

// Hmac - RFC2104 - is encoded as a hash.
//
//	HMac = Hash
type Hmac = Hash

// HashAlg is an FDO hashtype enum.
//
//	hashtype = (
//	    SHA256: -16,
//	    SHA384: -43,
//	    HMAC-SHA256: 5,
//	    HMAC-SHA384: 6
//	)
type HashAlg int64

// Hash algorithms
const (
	Sha256Hash     HashAlg = -16
	Sha384Hash     HashAlg = -43
	HmacSha256Hash HashAlg = 5
	HmacSha384Hash HashAlg = 6
)

func (alg HashAlg) String() string {
	switch alg {
	case Sha256Hash:
		return "Sha256Hash"
	case Sha384Hash:
		return "Sha384Hash"
	case HmacSha256Hash:
		return "HmacSha256Hash"
	case HmacSha384Hash:
		return "HmacSha384Hash"
	}
	panic("HashAlg missing switch case(s)")
}

// HashFunc implements crypto.SignerOpts, but is mainly intended as a simple
// helper function.
func (alg HashAlg) HashFunc() crypto.Hash {
	switch alg {
	case Sha256Hash, HmacSha256Hash:
		return crypto.SHA256
	case Sha384Hash, HmacSha384Hash:
		return crypto.SHA384
	}
	panic("HashAlg missing switch case(s)")
}

type fallibleHash interface {
	Err() error
}

// Compute an hmac.
func hmacHash(h hash.Hash, v any) (Hmac, error) {
	var hmac Hmac
	switch size := h.Size(); size {
	case sha256.Size:
		hmac.Algorithm = HmacSha256Hash
		if h == nil {
			panic("HMAC-SHA256 support is required")
		}
	case sha512.Size384:
		hmac.Algorithm = HmacSha384Hash
		if h == nil {
			return Hmac{}, fmt.Errorf("unsupported hash algorithm: HMAC-SHA384")
		}
	default:
		return Hmac{}, fmt.Errorf("unsupported hash size: %d", size)
	}

	h.Reset()
	if err := cbor.NewEncoder(h).Encode(v); err != nil {
		return Hmac{}, fmt.Errorf("error computing hmac: marshaling payload: %w", err)
	}
	hmac.Value = h.Sum(nil)
	if fallible, ok := h.(fallibleHash); ok {
		return Hmac{}, fmt.Errorf("error computing hmac: %w", fallible.Err())
	}
	return hmac, nil
}

// hmacVerify encodes the given value to CBOR and verifies that the given HMAC
// matches it. If the cryptographic portion of verification fails, then
// ErrCryptoVerifyFailed is wrapped.
func hmacVerify(h256, h384 hash.Hash, h1 Hmac, v any) error {
	if h256 == nil {
		panic("HMAC-SHA256 support is required")
	}

	var h hash.Hash
	switch h1.Algorithm {
	case HmacSha256Hash:
		h = h256
	case HmacSha384Hash:
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
		return fmt.Errorf("error computing hmac: %w", fallible.Err())
	}
	if !hmac.Equal(h1.Value, mac2) {
		return fmt.Errorf("%w: hmac did not match", ErrCryptoVerifyFailed)
	}
	return nil
}
