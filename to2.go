// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"github.com/fido-device-onboard/go-fdo/cose"
)

// NonceSize for NonceTO2ProveOV
const NonceSize uint64 = 16

// COSE claims for TO2ProveOVHdrUnprotectedHeaders
var (
	NonceClaim       = cose.Label{Int64: 256}
	OwnerPubKeyClaim = cose.Label{Int64: 257}
)

// MessageType 60
type HelloDevice struct {
	MaxDeviceMessageSize uint64
	Guid                 []byte
	NonceTO2ProveOV      []byte
	KexSuiteName         string
	CipherSuiteName      int64
	ASigInfo             *SigInfo
}

type To2ProveOwnerUprotectedHeader struct {
	Nonce          []byte
	OwnerPublicKey PublicKey
}

// TODO
type ServiceInfoModule = any
