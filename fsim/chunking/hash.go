// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package chunking

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

// ComputeHash computes the hash of data using the specified algorithm.
// Supported algorithms: "sha256", "sha384", "sha512"
func ComputeHash(alg string, data []byte) ([]byte, error) {
	h, err := newHash(alg)
	if err != nil {
		return nil, err
	}

	h.Write(data)
	return h.Sum(nil), nil
}

func newHash(alg string) (hash.Hash, error) {
	switch alg {
	case "sha256":
		return sha256.New(), nil
	case "sha384":
		return sha512.New384(), nil
	case "sha512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", alg)
	}
}

// VerifyHash verifies that the hash of data matches the expected hash value.
func VerifyHash(alg string, data []byte, expected []byte) error {
	computed, err := ComputeHash(alg, data)
	if err != nil {
		return err
	}

	if len(computed) != len(expected) {
		return fmt.Errorf("hash length mismatch: computed %d bytes, expected %d bytes",
			len(computed), len(expected))
	}

	for i := range computed {
		if computed[i] != expected[i] {
			return fmt.Errorf("hash mismatch")
		}
	}

	return nil
}
