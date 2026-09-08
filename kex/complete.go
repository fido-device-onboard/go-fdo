// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package kex

import (
	"bytes"
	"fmt"
)

// CompleteDeviceExchange completes the key exchange from the device side in
// FDO 2.0's "device proves first" flow. After the device has called
// Parameter() to generate its exchange parameter (xB), this function takes
// the owner's exchange parameter (xA) and computes the session keys.
//
// The session is modified in place and is ready for encryption/decryption
// after this call returns.
func CompleteDeviceExchange(sess Session, deviceXB, ownerXA []byte) error {
	switch s := sess.(type) {
	case *DHSession:
		return completeDH(s, ownerXA)
	case *ECDHSession:
		return completeECDH(s, deviceXB, ownerXA)
	default:
		return fmt.Errorf("unsupported session type for device exchange: %T", sess)
	}
}

func completeDH(s *DHSession, ownerXA []byte) error {
	return s.SetParameter(ownerXA, nil)
}

func completeECDH(s *ECDHSession, deviceXB, ownerXA []byte) error {
	// After the device's Parameter() call:
	//   s.priv = devicePrivKey
	//   s.xA = deviceParam (the first Parameter call stores as xA)
	//
	// The server has:
	//   xA = ownerParam, xB = deviceParam
	// and computes ecdhSymmetricKey(ownerPriv, ownerParam, deviceParam)
	//   → shx || deviceParam.Rand || ownerParam.Rand
	//
	// For the client to match, we need the same (xA, xB) ordering:
	//   xA = ownerParam, xB = deviceParam
	// So: swap xA to ownerXA, set xB to deviceXB, then compute keys.

	savedPriv := s.priv
	s.xA = bytes.Clone(ownerXA)
	s.xB = bytes.Clone(deviceXB)

	sek, svk, err := ecdhSymmetricKey(savedPriv, s.xA, s.xB, s.Cipher)
	if err != nil {
		return fmt.Errorf("error computing symmetric keys: %w", err)
	}
	s.SEK, s.SVK = sek, svk
	s.priv = nil
	return nil
}
