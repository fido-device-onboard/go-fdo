// SPDX-FileCopyrightText: (C) 2024 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"
	"crypto/rand"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// FDO 2.0 TO2 Server Handlers
//
// Key difference from 1.01: Device proves itself FIRST (anti-DoS measure)
// Flow: HelloDeviceProbe(80) -> HelloDeviceAck20(81) -> ProveDevice20(82) ->
//       ProveOVHdr20(83) -> GetOVNextEntry20(84) -> OVNextEntry20(85) ->
//       DeviceSvcInfoRdy20(86) -> SetupDevice20(87) -> DeviceSvcInfo20(88) ->
//       OwnerSvcInfo20(89) -> Done20(90) -> DoneAck20(91)

// helloDeviceAck20 handles TO2.HelloDeviceProbe (80) -> TO2.HelloDeviceAck20 (81)
// This is the first message in 2.0 - server acknowledges and prepares challenge
func (s *TO2Server) helloDeviceAck20(ctx context.Context, msg io.Reader) (*HelloDeviceAck20Msg, error) {
	// Parse request
	var probe HelloDeviceProbeMsg
	if err := cbor.NewDecoder(msg).Decode(&probe); err != nil {
		return nil, fmt.Errorf("error decoding TO2.HelloDeviceProbe request: %w", err)
	}

	// Store GUID for session
	if err := s.Session.SetGUID(ctx, probe.GUID); err != nil {
		return nil, fmt.Errorf("error associating device GUID to proof session: %w", err)
	}

	// Retrieve voucher to verify device exists
	ov, err := s.Vouchers.Voucher(ctx, probe.GUID)
	if err != nil || len(ov.Entries) == 0 {
		captureErr(ctx, protocol.ResourceNotFound, "")
		return nil, fmt.Errorf("error retrieving voucher for device %x: %w", probe.GUID, err)
	}

	// Generate nonce for ProveDevice20
	var proveDeviceNonce protocol.Nonce
	if _, err := rand.Read(proveDeviceNonce[:]); err != nil {
		return nil, fmt.Errorf("error generating nonce for TO2.HelloDeviceAck20: %w", err)
	}
	if err := s.Session.SetProveDeviceNonce(ctx, proveDeviceNonce); err != nil {
		return nil, fmt.Errorf("error storing nonce: %w", err)
	}

	// Hash the probe message for verification in ProveDevice20
	hashAlg := probe.HashTypes[0] // Use first supported hash type
	probeHash := protocol.Hash{Algorithm: hashAlg}
	hasher := hashAlg.HashFunc().New()
	// Re-encode probe to get exact bytes for hash
	probeBytes, err := cbor.Marshal(probe)
	if err != nil {
		return nil, fmt.Errorf("error encoding probe for hash: %w", err)
	}
	hasher.Write(probeBytes)
	// Also hash the owner public key hash (from device credential)
	ownerPubKey, err := ov.OwnerPublicKey()
	if err != nil {
		return nil, fmt.Errorf("error getting owner public key: %w", err)
	}
	ownerPubKeyBytes, err := cbor.Marshal(ownerPubKey)
	if err != nil {
		return nil, fmt.Errorf("error encoding owner public key for hash: %w", err)
	}
	hasher.Write(ownerPubKeyBytes)
	probeHash.Value = hasher.Sum(nil)

	// Build response with supported crypto options
	// For now, offer common suites - this could be made configurable
	return &HelloDeviceAck20Msg{
		CapabilityFlags:     GlobalCapabilityFlags,
		GUID:                probe.GUID,
		MaxOwnerMessageSize: 65535,
		KexSuites:           []kex.Suite{kex.ECDH384Suite, kex.ECDH256Suite},
		CipherSuites:        []kex.CipherSuiteID{kex.A256GcmCipher, kex.A128GcmCipher},
		NonceTO2ProveDVPrep: proveDeviceNonce,
		HashPrev:            probeHash,
	}, nil
}

// proveOVHdr20 handles TO2.ProveDevice20 (82) -> TO2.ProveOVHdr20 (83)
// In 2.0, device proves itself FIRST, then owner proves ownership
//
//nolint:gocyclo // Protocol implementation with device verification and key exchange
func (s *TO2Server) proveOVHdr20(ctx context.Context, msg io.Reader) (*cose.Sign1Tag[ProveOVHdr20Payload, []byte], error) {
	// Parse the EAT token from device
	var proveDevice cose.Sign1Tag[ProveDevice20Payload, []byte]
	if err := cbor.NewDecoder(msg).Decode(&proveDevice); err != nil {
		return nil, fmt.Errorf("error decoding TO2.ProveDevice20: %w", err)
	}

	// Get stored session data
	guid, err := s.Session.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting GUID from session: %w", err)
	}

	// Retrieve voucher
	ov, err := s.Vouchers.Voucher(ctx, guid)
	if err != nil {
		captureErr(ctx, protocol.ResourceNotFound, "")
		return nil, fmt.Errorf("error retrieving voucher: %w", err)
	}

	// Get device certificate from voucher to verify signature
	if ov.CertChain == nil || len(*ov.CertChain) == 0 {
		return nil, fmt.Errorf("voucher has no device certificate chain")
	}
	deviceCert := *ov.CertChain

	// Verify device signature on ProveDevice20
	devicePubKey := (*deviceCert[0]).PublicKey
	if ok, err := proveDevice.Verify(devicePubKey, nil, nil); err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("error verifying device signature: %w", err)
	} else if !ok {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("device signature verification failed")
	}

	// Verify nonce matches what we sent (anti-replay protection)
	storedNonce, err := s.Session.ProveDeviceNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting stored nonce: %w", err)
	}
	if proveDevice.Payload.Val.NonceTO2ProveOVPrep != storedNonce {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("nonce mismatch in ProveDevice20: expected %x, got %x", storedNonce, proveDevice.Payload.Val.NonceTO2ProveOVPrep)
	}

	// Now that device is verified, proceed with owner proof (similar to 1.01 proveOVHdr)
	// Begin key exchange with device's selected suite
	payload := proveDevice.Payload.Val
	if !kex.Available(payload.KexSuiteName, payload.CipherSuiteName) {
		return nil, fmt.Errorf("unsupported key exchange/cipher suite")
	}

	expectedOwnerPubKey, err := ov.OwnerPublicKey()
	if err != nil {
		return nil, fmt.Errorf("error getting owner public key: %w", err)
	}

	// Get owner key for signing
	keyType := ov.Header.Val.ManufacturerKey.Type
	ownerKey, ownerPublicKeyProto, err := s.ownerKey(ctx, keyType, ov.Header.Val.ManufacturerKey.Encoding, ov.Header.Val.ManufacturerKey.RsaBits())
	if err != nil {
		return nil, fmt.Errorf("error getting owner key: %w", err)
	}

	// Handle delegate support
	var delegateChainProto *protocol.PublicKey
	if s.OnboardDelegate != "" {
		// Replace "=" with key type string for delegate name lookup
		delegateName := strings.ReplaceAll(s.OnboardDelegate, "=", (*ownerPublicKeyProto).Type.KeyString())
		dk, chain, err := s.DelegateKeys.DelegateKey(delegateName)
		if err != nil {
			return nil, fmt.Errorf("delegate chain %q not found: %w", delegateName, err)
		}

		// Verify delegate chain is valid for this owner
		if err := VerifyDelegateChain(chain, &expectedOwnerPubKey, nil); err != nil {
			return nil, fmt.Errorf("delegate chain verification failed: %w", err)
		}
		// Check for any fdo-ekt-permit-onboard-* permission
		if !DelegateCanOnboard(chain) {
			return nil, fmt.Errorf("delegate certificate does not have any fdo-ekt-permit-onboard-* permission")
		}

		// Convert delegate chain to protocol.PublicKey for COSE header
		delegateChainProto, err = protocol.NewPublicKey(keyType, chain, false)
		if err != nil {
			return nil, fmt.Errorf("error marshaling delegate chain: %w", err)
		}

		// Use delegate key for signing instead of owner key
		ownerKey = dk
	} else {
		// Verify owner key matches voucher
		if !ownerKey.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(expectedOwnerPubKey) {
			return nil, fmt.Errorf("owner key does not match voucher")
		}
	}

	// Initialize key exchange session
	sess := payload.KexSuiteName.New(payload.XAKeyExchange, payload.CipherSuiteName)
	xB, err := sess.Parameter(rand.Reader, nil)
	if err != nil {
		return nil, fmt.Errorf("error generating key exchange parameter: %w", err)
	}
	if err := s.Session.SetXSession(ctx, payload.KexSuiteName, sess); err != nil {
		clear(xB)
		return nil, fmt.Errorf("error storing key exchange session: %w", err)
	}

	// Store the nonce from device for later use
	if err := s.Session.SetProveDeviceNonce(ctx, payload.NonceTO2ProveOVPrep); err != nil {
		return nil, fmt.Errorf("error storing ProveOV nonce: %w", err)
	}

	// Build ProveOVHdr20 response
	if len(ov.Entries) > math.MaxUint8 {
		return nil, fmt.Errorf("voucher has %d entries, exceeds uint8 max of 255", len(ov.Entries))
	}
	numEntries := uint8(len(ov.Entries)) //#nosec G115 -- bounds checked above

	proveOVHdrPayload := ProveOVHdr20Payload{
		OVHeader:            ov.Header,
		NumOVEntries:        numEntries,
		HMac:                ov.Hmac,
		NonceTO2ProveOV:     payload.NonceTO2ProveOVPrep,
		XBKeyExchange:       xB,
		MaxOwnerMessageSize: 65535,
	}

	// Build COSE header with owner public key and optional delegate chain (like 1.01)
	header := cose.Header{
		Unprotected: map[cose.Label]any{
			to2OwnerPubKeyClaim: ownerPublicKeyProto,
		},
	}
	if delegateChainProto != nil {
		header.Unprotected[to2DelegateClaim] = delegateChainProto
	}

	// Sign with owner key
	s1 := &cose.Sign1Tag[ProveOVHdr20Payload, []byte]{
		Sign1: cose.Sign1[ProveOVHdr20Payload, []byte]{
			Header:  header,
			Payload: cbor.NewByteWrap(proveOVHdrPayload),
		},
	}
	opts, err := signOptsFor(ownerKey, false)
	if err != nil {
		return nil, fmt.Errorf("error determining signing options for ProveOVHdr20: %w", err)
	}
	if err := s1.Sign(ownerKey, nil, nil, opts); err != nil {
		return nil, fmt.Errorf("error signing ProveOVHdr20: %w", err)
	}

	return s1, nil
}

// ovNextEntry20 handles TO2.GetOVNextEntry20 (84) -> TO2.OVNextEntry20 (85)
// This is essentially the same as 1.01 - reuse the logic
func (s *TO2Server) ovNextEntry20(ctx context.Context, msg io.Reader) (*OVNextEntry20Msg, error) {
	var req GetOVNextEntry20Msg
	if err := cbor.NewDecoder(msg).Decode(&req); err != nil {
		return nil, fmt.Errorf("error decoding TO2.GetOVNextEntry20: %w", err)
	}

	guid, err := s.Session.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting GUID from session: %w", err)
	}

	ov, err := s.Vouchers.Voucher(ctx, guid)
	if err != nil {
		return nil, fmt.Errorf("error retrieving voucher: %w", err)
	}

	if int(req.OVEntryNum) >= len(ov.Entries) {
		return nil, fmt.Errorf("requested entry %d out of range", req.OVEntryNum)
	}

	entryBytes, err := cbor.Marshal(ov.Entries[req.OVEntryNum])
	if err != nil {
		return nil, fmt.Errorf("error encoding voucher entry: %w", err)
	}

	return &OVNextEntry20Msg{
		OVEntryNum: req.OVEntryNum,
		OVEntry:    entryBytes,
	}, nil
}

// setupDevice20 handles TO2.DeviceSvcInfoRdy20 (86) -> TO2.SetupDevice20 (87)
// Similar to 1.01 but message structures differ slightly
//
//nolint:gocyclo // Protocol implementation with credential handling
func (s *TO2Server) setupDevice20(ctx context.Context, msg io.Reader) (*SetupDevice20Msg, error) {
	var req DeviceSvcInfoRdy20Msg
	if err := cbor.NewDecoder(msg).Decode(&req); err != nil {
		return nil, fmt.Errorf("error decoding TO2.DeviceSvcInfoRdy20: %w", err)
	}

	guid, err := s.Session.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting GUID from session: %w", err)
	}

	ov, err := s.Vouchers.Voucher(ctx, guid)
	if err != nil {
		return nil, fmt.Errorf("error retrieving voucher: %w", err)
	}

	// Generate nonce for Done20
	var setupDeviceNonce protocol.Nonce
	if _, err := rand.Read(setupDeviceNonce[:]); err != nil {
		return nil, fmt.Errorf("error generating nonce: %w", err)
	}
	if err := s.Session.SetSetupDeviceNonce(ctx, setupDeviceNonce); err != nil {
		return nil, fmt.Errorf("error storing setup device nonce: %w", err)
	}

	// Determine if credential reuse based on server policy
	// Note: HMAC is now sent in Done20 (not here) so client can compute it
	// after receiving GUID/RvInfo from this message
	var replacementGUID *protocol.GUID
	var replacementRvInfo *[][]protocol.RvInstruction

	reuseCredential := true // Default to reuse
	if s.ReuseCredential != nil {
		reuseCredential, err = s.ReuseCredential(ctx, *ov)
		if err != nil {
			return nil, fmt.Errorf("error checking credential reuse: %w", err)
		}
	}

	if !reuseCredential {
		// Generate new GUID
		var newGUID protocol.GUID
		if _, err := rand.Read(newGUID[:]); err != nil {
			return nil, fmt.Errorf("error generating new GUID: %w", err)
		}
		replacementGUID = &newGUID

		// Store replacement GUID in session for doneAck20
		if err := s.Session.SetReplacementGUID(ctx, newGUID); err != nil {
			return nil, fmt.Errorf("error storing replacement GUID: %w", err)
		}

		// Get replacement RV info
		if s.RvInfo != nil {
			rvInfo, err := s.RvInfo(ctx, *ov)
			if err != nil {
				return nil, fmt.Errorf("error getting replacement RV info: %w", err)
			}
			replacementRvInfo = &rvInfo

			// Store RV info in session for doneAck20
			if err := s.Session.SetRvInfo(ctx, rvInfo); err != nil {
				return nil, fmt.Errorf("error storing replacement RV info: %w", err)
			}
		}
	}

	// Determine max service info size
	maxSvcInfoSz := uint16(1300) // Default MTU
	if s.MaxDeviceServiceInfoSize != nil {
		maxSvcInfoSz, err = s.MaxDeviceServiceInfoSize(ctx, *ov)
		if err != nil {
			return nil, fmt.Errorf("error getting max service info size: %w", err)
		}
	}

	return &SetupDevice20Msg{
		NonceTO2SetupDV:        setupDeviceNonce,
		ReplacementGUID:        replacementGUID,
		ReplacementRvInfo:      replacementRvInfo,
		MaxDeviceServiceInfoSz: maxSvcInfoSz,
	}, nil
}

// ownerSvcInfo20 handles TO2.DeviceSvcInfo20 (88) -> TO2.OwnerSvcInfo20 (89)
// Reuses the service info exchange logic from 1.01
func (s *TO2Server) ownerSvcInfo20(ctx context.Context, msg io.Reader) (*OwnerSvcInfo20Msg, error) {
	var req DeviceSvcInfo20Msg
	if err := cbor.NewDecoder(msg).Decode(&req); err != nil {
		return nil, fmt.Errorf("error decoding TO2.DeviceSvcInfo20: %w", err)
	}

	// Process device service info through modules (reuse 1.01 logic)
	// This is a simplified version - full implementation would call s.Modules
	guid, err := s.Session.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting GUID from session: %w", err)
	}

	ov, err := s.Vouchers.Voucher(ctx, guid)
	if err != nil {
		return nil, fmt.Errorf("error retrieving voucher: %w", err)
	}

	// TODO: Process device service info through modules
	// For now, return empty response indicating done
	// Full implementation would integrate with s.Modules similar to 1.01
	_ = ov
	_ = req

	return &OwnerSvcInfo20Msg{
		IsMoreServiceInfo: false,
		IsDone:            true,
		ServiceInfo:       nil,
	}, nil
}

// doneAck20 handles TO2.Done20 (90) -> TO2.DoneAck20 (91)
func (s *TO2Server) doneAck20(ctx context.Context, msg io.Reader) (*DoneAck20Msg, error) {
	var req Done20Msg
	if err := cbor.NewDecoder(msg).Decode(&req); err != nil {
		return nil, fmt.Errorf("error decoding TO2.Done20: %w", err)
	}

	// Verify nonce matches what we sent in SetupDevice20
	storedNonce, err := s.Session.SetupDeviceNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting stored setup device nonce: %w", err)
	}
	if req.NonceTO2SetupDV != storedNonce {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("nonce mismatch in TO2.Done20")
	}

	// Get the ProveOV nonce to echo back
	proveOVNonce, err := s.Session.ProveDeviceNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting ProveOV nonce: %w", err)
	}

	// If the Credential Reuse Protocol is being used (no replacement HMAC in Done20),
	// then immediately complete TO2 without replacing the voucher.
	if req.ReplacementHMAC == nil {
		return &DoneAck20Msg{NonceTO2ProveOV: proveOVNonce}, nil
	}
	replacementHmac := *req.ReplacementHMAC

	// Get current and replacement voucher values
	currentGUID, err := s.Session.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving associated device GUID of proof session: %w", err)
	}
	currentOV, err := s.Vouchers.Voucher(ctx, currentGUID)
	if err != nil || len(currentOV.Entries) == 0 {
		return nil, fmt.Errorf("error retrieving voucher for device %x: %w", currentGUID, err)
	}
	rvInfo, err := s.Session.RvInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving rendezvous info for device: %w", err)
	}
	replacementGUID, err := s.Session.ReplacementGUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving replacement GUID for device: %w", err)
	}

	// Create and store a new voucher
	mfgKey := currentOV.Header.Val.ManufacturerKey
	keyType := mfgKey.Type
	keyEncoding := mfgKey.Encoding
	rsaBits := mfgKey.RsaBits()
	_, ownerPublicKey, err := s.ownerKey(ctx, keyType, keyEncoding, rsaBits)
	if err != nil {
		return nil, err
	}
	ov := &Voucher{
		Version: currentOV.Version,
		Header: *cbor.NewBstr(VoucherHeader{
			Version:         currentOV.Header.Val.Version,
			GUID:            replacementGUID,
			RvInfo:          rvInfo,
			DeviceInfo:      currentOV.Header.Val.DeviceInfo,
			ManufacturerKey: *ownerPublicKey,
			CertChainHash:   currentOV.Header.Val.CertChainHash,
		}),
		Hmac:      replacementHmac,
		CertChain: currentOV.CertChain,
		Entries:   nil,
	}
	if err := s.Vouchers.ReplaceVoucher(ctx, currentGUID, ov); err != nil {
		return nil, fmt.Errorf("error replacing persisted voucher: %w", err)
	}

	return &DoneAck20Msg{
		NonceTO2ProveOV: proveOVNonce,
	}, nil
}
