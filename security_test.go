// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"testing"

	"github.com/fido-device-onboard/go-fdo/fdotest"
)

// TestSecurityMaliciousTransport_BadDelegateChain tests that the client rejects
// a ProveOVHdr response containing a delegate chain not signed by the owner.
func TestSecurityMaliciousTransport_BadDelegateChain(t *testing.T) {
	fdotest.RunSecurityTest(t, fdotest.AttackBadDelegateChain)
}

// TestSecurityMaliciousTransport_BadNonce tests that the client rejects
// a ProveOVHdr response with a nonce that doesn't match HelloDevice.
func TestSecurityMaliciousTransport_BadNonce(t *testing.T) {
	fdotest.RunSecurityTest(t, fdotest.AttackBadNonce)
}

// TestSecurityMaliciousTransport_WrongOwnerKey tests that the client rejects
// a ProveOVHdr response with an owner key that doesn't match the voucher.
func TestSecurityMaliciousTransport_WrongOwnerKey(t *testing.T) {
	fdotest.RunSecurityTest(t, fdotest.AttackWrongOwnerKey)
}

// TestSecurityMaliciousTransport_BadSignature tests that the client rejects
// a ProveOVHdr response with a corrupted COSE signature.
func TestSecurityMaliciousTransport_BadSignature(t *testing.T) {
	fdotest.RunSecurityTest(t, fdotest.AttackBadSignature)
}

// TestSecurityMaliciousTransport_BadHMAC tests that the client rejects
// a ProveOVHdr response with a corrupted voucher HMAC.
func TestSecurityMaliciousTransport_BadHMAC(t *testing.T) {
	fdotest.RunSecurityTest(t, fdotest.AttackBadHMAC)
}
