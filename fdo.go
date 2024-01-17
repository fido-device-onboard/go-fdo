// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

// Guid is implemented as a 128-bit cryptographically strong random number.
//
// The Guid type identifies a Device during onboarding, and is replaced each
// time onboarding is successful in the Transfer Ownership 2 (TO2) protocol.
type Guid [16]byte

// Nonce is a byte array with length (16 bytes) 128-bit Random number.
//
// Nonces are used within FIDO Device Onboard to ensure that signatures are
// create on demand and not replayed (i.e., to ensure the "freshness" of
// signatures). When asymmetric digital signatures are used to prove ownership
// of a private key, as in FIDO Device Onboard, an attacker may try to replay
// previously signed messages, to impersonate the true key owner. A secure
// protocol can detect and thwart a replay attack by attaching a unique value
// to the signed data. In this case, we use a nonce, which is a
// cryptographically secure random number chosen by the other party in the
// connection. Since FIDO Device Onboard contains several signatures, more than
// one nonce is used. The reader may use the number of the nonce type to track
// when a nonce is offered and then subsequently returned.
type Nonce [16]byte

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

// An HMAC - RFC2104 - is encoded as a hash.
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
