// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package nistkdf implements a NIST 800-108 KDF using the parameters defined in FDO.
package nistkdf

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"math"
)

// KDF implements NIST 800-108 using the parameters defined in FDO.
func KDF(hash crypto.Hash, shSe, contextRand []byte, bits uint16) []byte {
	// NIST SP 800-108 KDF in Counter Mode
	//
	// Parameters:
	//     • h – The length of the output of a single invocation of the PRF in bits
	// 	   • r – The length of the binary representation of the counter i
	//
	// Input: K_IN, Label, Context, and L
	//
	// Process:
	//     1. n := [L/h].
	//     2. If n > 2^r −1, then output an error indicator and stop (i.e., skip steps 3, 4, and 5).
	//     3. result := ∅.
	//     4. For i = 1 to n, do
	//         a. K(i) := PRF (K_IN, [i]_2 || Label || 0x00 || Context || [L]_2),
	//         b. result := result || K(i).
	//     5. K_OUT := the leftmost L bits of result.
	//
	// Output: K_OUT (or an error indicator)
	//
	// FDO specifics:
	//     • r = 8
	//     • L = len(SEVK) or len(SVK)+len(SEK), 16 bits, big endian
	//     • K_IN = ShSe
	//     • Label = "FIDO-KDF"
	//     • Context = "AutomaticOnboardTunnel" ++ ContextRand
	//     • PRF = HMAC-SHA256 or HMAC-SHA384, depending on CipherSuite

	// Parameters
	var h uint16
	switch hash.Size() {
	case sha512.Size256:
		h = sha512.Size256
	case sha512.Size384:
		h = sha512.Size384
	default:
		panic("unsupported hash size")
	}

	// Input
	kIn := shSe
	label := []byte("FIDO-KDF")
	context := append([]byte("AutomaticOnboardTunnel"), contextRand...)
	L := bits

	// Process
	// 1.
	n := L / h
	if L%h != 0 {
		n++
	}

	// 2.
	if n > math.MaxUint8 {
		panic("n too large")
	}
	// Equivalent to
	//
	// r := uint16(8)
	// if float64(n) > math.Pow(2, float64(r))-1 {
	// 	return nil, fmt.Errorf("n too large")
	// }

	// 3.
	var result []byte

	// 4.
	input := []byte{0x00} // iteration-dependent
	input = append(input, label...)
	input = append(input, 0x00)
	input = append(input, context...)
	input = binary.BigEndian.AppendUint16(input, L)
	digest := hmac.New(hash.New, kIn)
	for i := uint8(0); i < uint8(n); i++ {
		// a.
		digest.Reset()
		input[0] = i + 1
		_, _ = digest.Write(input)

		// b.
		result = append(result, digest.Sum(nil)...)
	}

	// 5.
	kOut := result[:L/8]

	// Output
	return kOut
}
