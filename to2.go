// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"github.com/fido-device-onboard/go-fdo/cose"
)

// COSE claims for TO2ProveOVHdrUnprotectedHeaders
var (
	NonceClaim       = cose.Label{Int64: 256}
	OwnerPubKeyClaim = cose.Label{Int64: 257}
)

// HelloDevice is message type 60
type HelloDevice struct {
	MaxDeviceMessageSize uint64
	GUID                 GUID
	NonceTO2ProveOV      Nonce
	KexSuiteName         string
	CipherSuiteName      int64
	ASigInfo             *SigInfo
}

// TO2ProveOVHdrUnprotectedHeaders is used in TO2.ProveDevice and TO2.Done as
// COSE signature unprotected headers.
type TO2ProveOVHdrUnprotectedHeaders struct {
	Nonce          Nonce
	OwnerPublicKey PublicKey
}
