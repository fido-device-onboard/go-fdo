// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fsim

import "github.com/fido-device-onboard/go-fdo/fsim/chunking"

// CoseSign1Verifier verifies a meta-payload signed by a named publisher key
// (the meta_signer, begin key 9). It is a convenience for tools such as
// fdo-meta-tool; devices use chunking.Resolve, which also covers Owner- and
// PERM.7 delegate-signed meta-payloads. Both go through
// chunking.VerifyMetaPayload, so the rules are identical.
//
// signerKey is a CBOR-encoded COSE_Key; signedPayload is a tagged
// COSE_Sign1. On success the inner MetaPayload CBOR is returned. An unsigned
// input is rejected: naming a signer never downgrades to unsigned.
type CoseSign1Verifier struct{}

// Verify checks the COSE Sign1 signature on a meta-payload against signerKey.
func (v *CoseSign1Verifier) Verify(signedPayload []byte, signerKey []byte) ([]byte, error) {
	inner, _, err := chunking.VerifyMetaPayload(signedPayload, signerKey, nil)
	return inner, err
}

// NewCoseSign1Verifier creates a new CoseSign1Verifier instance.
func NewCoseSign1Verifier() *CoseSign1Verifier {
	return &CoseSign1Verifier{}
}
