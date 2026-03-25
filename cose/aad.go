// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import (
	"github.com/fido-device-onboard/go-fdo/cbor"
)

// Domain separation tags for COSE_Sign1 external_aad.
//
// Each value is the CBOR encoding of:
//
//	FDOExternalAAD = [FDODomainTag]
//	FDODomainTag = tstr
//
// These are included in the COSE Sig_structure hash but NOT transmitted
// in the COSE_Sign1 output. Both signer and verifier independently
// construct the same value based on the protocol context.
//
// See RFC 9052 Section 4.3 ("Externally Supplied Data").
var (
	// Base FDO 2.0 specification operations.
	// Tags are intent-based: the same tag is used for both v1.01 and v2.0
	// message variants of the same operation.

	AADOwnerSign   = mustEncodeDomainAAD("FDO-TO0-OwnerSign-v1")   // TO0.OwnerSign (to1d)
	AADProveToRV   = mustEncodeDomainAAD("FDO-TO1-ProveToRV-v1")   // TO1.ProveToRV
	AADProveDevice = mustEncodeDomainAAD("FDO-TO2-ProveDevice-v1") // TO2.ProveDevice / TO2.ProveDevice20
	AADProveOVHdr  = mustEncodeDomainAAD("FDO-TO2-ProveOVHdr-v1")  // TO2.ProveOVHdr / TO2.ProveOVHdr20
	AADSetupDevice = mustEncodeDomainAAD("FDO-TO2-SetupDevice-v1") // TO2.SetupDevice / TO2.SetupDevice20
	AADOVEntry     = mustEncodeDomainAAD("FDO-OVEntry-v1")         // Ownership Voucher entry

	// Voucher Transfer Protocol (FDOKeyAuth) operations.

	AADKeyAuthChallenge = mustEncodeDomainAAD("FDO-KeyAuth-Challenge-v1") // FDOKeyAuth.Challenge
	AADKeyAuthProve     = mustEncodeDomainAAD("FDO-KeyAuth-Prove-v1")     // FDOKeyAuth.Prove

	// BMO FSIM operations.

	AADMetaPayload = mustEncodeDomainAAD("FDO-FSIM-MetaPayload-v1") // Signed BMO meta-payload
)

// mustEncodeDomainAAD returns the CBOR encoding of FDOExternalAAD = [tag].
// This is the value placed in the external_aad field of the COSE Sig_structure.
func mustEncodeDomainAAD(tag string) []byte {
	data, err := cbor.Marshal([]string{tag})
	if err != nil {
		panic("cose: failed to encode domain AAD tag: " + err.Error())
	}
	return data
}
