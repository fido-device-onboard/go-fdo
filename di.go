// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

// DeviceCredentials is non-normative, but the [TPM Draft Spec] proposes a CBOR
// encoding, so that will be used.
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
type DeviceCredentials struct {
	Version         uint16
	DeviceInfo      string
	Guid            []byte
	RvInfo          []RvInstruction
	PublicKeyHash   Hash
	DeviceKeyType   uint64
	DeviceKeyHandle uint64
}

// DeviceVariable contains all device state, including both public and private
// parts of keys and secrets.
type DeviceVariable struct {
	Active     bool
	DC         DeviceCredentials
	HmacType   int64
	HmacSecret []byte
	PrivateKey []byte // PKCS#8
}
