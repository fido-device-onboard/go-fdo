// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

// DeviceCredential is non-normative, but the [TPM Draft Spec] proposes a CBOR
// encoding, so that will be used, excluding the key type/handle.
//
//	DCTPM = [
//	    DCProtVer: protver,
//	    DCDeviceInfo: tstr,
//	    DCGuid: bstr
//	    DCRVInfo: RendezvousInfo,
//	    DCPubKeyHash: Hash
//	    DeviceKeyType: uint
//	    DeviceKeyHandle: uint
//	]
//
// [TPM Draft Spec]: https://fidoalliance.org/specs/FDO/securing-fdo-in-tpm-v1.0-rd-20231010/securing-fdo-in-tpm-v1.0-rd-20231010.html
type DeviceCredential struct {
	Version       uint16
	DeviceInfo    string
	GUID          GUID
	RvInfo        [][]RvInstruction
	PublicKeyHash Hash // expected to be a hash of the entire CBOR structure (not just pkBody) for Voucher.VerifyEntries to succeed
}
