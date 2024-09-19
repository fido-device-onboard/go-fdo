// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package protocol

import "crypto"

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
