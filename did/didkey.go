// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package did

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"strings"
)

// ParseDIDKey decodes a did:key URI into a crypto.PublicKey.
// Supports P-256 and P-384 keys encoded per the did:key spec v0.9:
//
//	did:key:z<base58btc(multicodec-varint + compressed-ec-point)>
//
// Multicodec varint prefixes:
//   - P-256: 0x80 0x24  (code 0x1200)
//   - P-384: 0x81 0x24  (code 0x1201)
func ParseDIDKey(didURI string) (crypto.PublicKey, error) {
	if !strings.HasPrefix(didURI, "did:key:z") {
		return nil, fmt.Errorf("did:key URI must start with 'did:key:z': %q", didURI)
	}

	// Strip "did:key:z" — the "z" is the multibase prefix for base58-btc
	encoded := strings.TrimPrefix(didURI, "did:key:z")

	decoded, err := decodeBase58BTC(encoded)
	if err != nil {
		return nil, fmt.Errorf("did:key: base58 decode failed: %w", err)
	}

	if len(decoded) < 3 {
		return nil, fmt.Errorf("did:key: decoded data too short (%d bytes)", len(decoded))
	}

	// Parse multicodec varint prefix (2 bytes for P-256/P-384)
	var curve elliptic.Curve
	var keyBytes []byte
	switch {
	case decoded[0] == 0x80 && decoded[1] == 0x24:
		// P-256 (multicodec 0x1200)
		curve = elliptic.P256()
		keyBytes = decoded[2:]
	case decoded[0] == 0x81 && decoded[1] == 0x24:
		// P-384 (multicodec 0x1201)
		curve = elliptic.P384()
		keyBytes = decoded[2:]
	default:
		return nil, fmt.Errorf("did:key: unsupported multicodec prefix 0x%02x 0x%02x", decoded[0], decoded[1])
	}

	// Decompress the EC point
	x, y := decompressECPoint(curve, keyBytes)
	if x == nil {
		return nil, fmt.Errorf("did:key: failed to decompress EC point for %s", curve.Params().Name)
	}

	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	if err := validateECPoint(curve, x, y); err != nil {
		return nil, fmt.Errorf("did:key: decoded point is not on curve %s", curve.Params().Name)
	}

	return pub, nil
}

// decompressECPoint decompresses a SEC1-compressed EC point (33 or 49 bytes)
// into (x, y) coordinates. The first byte is 0x02 (even y) or 0x03 (odd y).
func decompressECPoint(curve elliptic.Curve, data []byte) (*big.Int, *big.Int) {
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(data) != 1+byteLen {
		return nil, nil
	}
	if data[0] != 0x02 && data[0] != 0x03 {
		return nil, nil
	}

	// x coordinate
	x := new(big.Int).SetBytes(data[1:])
	p := curve.Params().P

	// y² = x³ + ax + b  (for NIST curves, a = -3)
	// y² = x³ - 3x + b (mod p)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Mod(x3, p)

	threeX := new(big.Int).Mul(big.NewInt(3), x)
	threeX.Mod(threeX, p)

	y2 := new(big.Int).Sub(x3, threeX)
	y2.Add(y2, curve.Params().B)
	y2.Mod(y2, p)

	// y = sqrt(y²) mod p
	y := new(big.Int).ModSqrt(y2, p)
	if y == nil {
		return nil, nil
	}

	// Choose the correct y based on the sign bit
	isOdd := y.Bit(0) == 1
	wantOdd := data[0] == 0x03
	if isOdd != wantOdd {
		y.Sub(p, y)
	}

	return x, y
}

// base58BTCAlphabet is the Bitcoin base58 alphabet.
const base58BTCAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// decodeBase58BTC decodes a base58-btc (Bitcoin alphabet) encoded string.
// This is a zero-dependency implementation used for did:key resolution.
func decodeBase58BTC(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	// Build reverse lookup table
	var alphabet [256]int
	for i := range alphabet {
		alphabet[i] = -1
	}
	for i, c := range base58BTCAlphabet {
		alphabet[c] = i
	}

	// Convert base58 string to big.Int
	result := new(big.Int)
	base := big.NewInt(58)
	for _, c := range s {
		if c > 255 {
			return nil, fmt.Errorf("invalid base58 character: %c", c)
		}
		idx := alphabet[c]
		if idx == -1 {
			return nil, fmt.Errorf("invalid base58 character: %c", c)
		}
		result.Mul(result, base)
		result.Add(result, big.NewInt(int64(idx)))
	}

	// Convert to bytes
	decoded := result.Bytes()

	// Count leading '1's in input (each represents a leading zero byte)
	var leadingZeros int
	for _, c := range s {
		if c != '1' {
			break
		}
		leadingZeros++
	}

	if leadingZeros > 0 {
		decoded = append(make([]byte, leadingZeros), decoded...)
	}

	return decoded, nil
}

// validateECPoint validates that (x, y) lies on the given curve using crypto/ecdh.
// This replaces the deprecated elliptic.Curve.IsOnCurve.
func validateECPoint(c elliptic.Curve, x, y *big.Int) error {
	byteLen := (c.Params().BitSize + 7) / 8
	uncompressed := make([]byte, 1+2*byteLen)
	uncompressed[0] = 0x04
	x.FillBytes(uncompressed[1 : 1+byteLen])
	y.FillBytes(uncompressed[1+byteLen:])

	var ecdhCurve ecdh.Curve
	switch c {
	case elliptic.P256():
		ecdhCurve = ecdh.P256()
	case elliptic.P384():
		ecdhCurve = ecdh.P384()
	default:
		return fmt.Errorf("unsupported curve: %s", c.Params().Name)
	}
	_, err := ecdhCurve.NewPublicKey(uncompressed)
	return err
}
