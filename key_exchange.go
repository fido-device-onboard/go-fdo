// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

type cipherSuite int64

// Cipher suite values
const (
	A128GCMCipher             cipherSuite = 1
	A256GCMCipher             cipherSuite = 2
	AES_CCM_16_128_128_Cipher cipherSuite = 30
	AES_CCM_16_128_256_Cipher cipherSuite = 31
	AES_CCM_64_128_128_Cipher cipherSuite = 32
	AES_CCM_64_128_256_Cipher cipherSuite = 33
	COSE_AES128_CBC_Cipher    cipherSuite = -17760703
	COSE_AES128_CTR_Cipher    cipherSuite = -17760704
	COSE_AES256_CBC_Cipher    cipherSuite = -17760705
	COSE_AES256_CTR_Cipher    cipherSuite = -17760706
)

// Key exchange suites
//
// When the Owner Key is RSA:
//
//   - “DHKEXid14”:
//     Diffie-Hellman key exchange method using a standard Diffie-Hellman
//     mechanism with a standard NIST exponent and 2048-bit modulus ([RFC3526],
//     id 14). This is the preferred method for RSA2048RESTR Owner keys.
//   - “DHKEXid15”:
//     Diffie-Hellman key exchange method using a standard Diffie-Hellman
//     mechanism with a standard National Institute of Standards and Technology
//     (NIST) exponent and 3072-bit modulus. ([RFC3526], id 15), This is the
//     preferred method for RSA 3072-bit Owner keys.
//   - “ASYMKEX2048”:
//     Asymmetric key exchange method uses the encryption by an Owner key based
//     on RSA2048RESTR; this method is useful in FIDO Device Onboard Client
//     environments where Diffie-Hellman computation is slow or difficult to
//     code.
//   - “ASYMKEX3072”:
//     The Asymmetric key exchange method uses the encryption by an Owner key
//     based on RSA with 3072-bit key.
//
// DHKEXid14 and DHKEXid15 differ in the size of the Diffie-Hellman modulus, which is chosen to match the RSA key size in use.
//
// When the Owner key is ECDSA:
//
//   - “ECDH256”:
//     The ECDH method uses a standard Diffie-Hellman mechanism for ECDSA keys.
//     The ECC keys follow NIST P-256 (SECP256R1)
//   - “ECDH384”:
//     Standard Diffie-Hellman mechanism ECC NIST P-384 (SECP384R1)
type kexSuiteName string

// Key exchange suites
//
// CDDL
//
//	KexSuitNames /= (
//	    "DHKEXid14",
//	    "DHKEXid15",
//	    "ASYMKEX2048",
//	    "ASYMKEX3072",
//	    "ECDH256",
//	    "ECDH384"
//	)
//
//nolint:unused
const (
	kexDHKEXid14   kexSuiteName = "DHKEXid14"
	kexDHKEXid15   kexSuiteName = "DHKEXid15"
	kexASYMKEX2048 kexSuiteName = "ASYMKEX2048"
	kexASYMKEX3072 kexSuiteName = "ASYMKEX3072"
	kexECDH256     kexSuiteName = "ECDH256"
	kexECDH38      kexSuiteName = "ECDH384"
)
