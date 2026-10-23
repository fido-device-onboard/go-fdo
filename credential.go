// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// DeviceCredential holds the FDO protocol credential fields (FDO spec
// Section 3.4.1). This is the protocol-level view used by DI, TO1, and TO2.
//
// Storage is handled separately: the blob backend (blob package) serializes
// this plus key material to a file; the TPM backend (cred/tpm_store.go)
// stores these fields inside the DCTPM NV index alongside TPM-specific
// metadata (magic, active flag, key handles).
type DeviceCredential struct {
	Version       uint16
	DeviceInfo    string
	GUID          protocol.GUID
	RvInfo        [][]protocol.RvInstruction
	PublicKeyHash protocol.Hash // expected to be a hash of the entire CBOR structure (not just pkBody) for Voucher.VerifyEntries to succeed
}
