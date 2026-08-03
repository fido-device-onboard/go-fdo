// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import "github.com/fido-device-onboard/go-fdo/v2/cbor"

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

	AADOwnerSign   = mustEncodeDomainAAD("FDO-TO0-OwnerSign-v1")
	AADProveToRV   = mustEncodeDomainAAD("FDO-TO1-ProveToRV-v1")
	AADProveDevice = mustEncodeDomainAAD("FDO-TO2-ProveDevice-v1")
	AADProveOVHdr  = mustEncodeDomainAAD("FDO-TO2-ProveOVHdr-v1")
	AADSetupDevice = mustEncodeDomainAAD("FDO-TO2-SetupDevice-v1")
	AADOVEntry     = mustEncodeDomainAAD("FDO-OVEntry-v1")

	// Voucher Transfer Protocol (FDOKeyAuth) operations.

	AADKeyAuthChallenge = mustEncodeDomainAAD("FDO-KeyAuth-Challenge-v1")
	AADKeyAuthProve     = mustEncodeDomainAAD("FDO-KeyAuth-Prove-v1")

	// BMO FSIM operations.

	AADMetaPayload  = mustEncodeDomainAAD("FDO-FSIM-MetaPayload-v1")
	AADBmoProvision = mustEncodeDomainAAD("FDO-FSIM-BmoProvision-v1")

	// Legacy aliases for backward compatibility.

	AADTO0OwnerSign   = AADOwnerSign
	AADTO1ProveToRV   = AADProveToRV
	AADTO2ProveDevice = AADProveDevice
	AADTO2ProveOVHdr  = AADProveOVHdr
	AADTO2SetupDevice = AADSetupDevice
)

// mustEncodeDomainAAD returns the CBOR encoding of FDOExternalAAD = [tag].
func mustEncodeDomainAAD(tag string) []byte {
	data, err := cbor.Marshal([]string{tag})
	if err != nil {
		panic("cose: failed to encode domain AAD tag: " + err.Error())
	}
	return data
}
