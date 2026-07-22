// SPDX-FileCopyrightText: (C) 2024 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"log/slog"
	"math"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// FDO 2.0 TO2 server handlers.
//
// In FDO 2.0, the device proves itself FIRST (anti-DoS measure), then the
// owner proves ownership. The message flow is:
//
//	HelloDeviceProbe(80) -> HelloDeviceAck20(81)
//	ProveDevice20(82) -> ProveOVHdr20(83)
//	GetOVNextEntry20(84) -> OVNextEntry20(85)
//	DeviceSvcInfoRdy20(86) -> SetupDevice20(87)
//	DeviceSvcInfo20(88) -> OwnerSvcInfo20(89) [loop]
//	Done20(90) -> DoneAck20(91)

// helloDeviceAck20 handles HelloDeviceProbe(80) -> HelloDeviceAck20(81).
//
// The server receives the device's capability flags and GUID, generates a
// nonce for the subsequent ProveDevice20 message, and responds with the
// server's capability flags and supported crypto suites.
func (s *TO2Server) helloDeviceAck20(ctx context.Context, msg io.Reader) (*HelloDeviceAck20Msg, error) {
	// Parse probe
	var probe HelloDeviceProbeMsg
	if err := cbor.NewDecoder(msg).Decode(&probe); err != nil {
		return nil, fmt.Errorf("error decoding TO2.HelloDeviceProbe request: %w", err)
	}

	// Store the device GUID for subsequent messages
	if err := s.Session.SetGUID(ctx, probe.GUID); err != nil {
		return nil, fmt.Errorf("error associating device GUID to proof session: %w", err)
	}

	// Verify the voucher exists
	ov, err := s.Vouchers.Voucher(ctx, probe.GUID)
	if err != nil {
		captureErr(ctx, protocol.ResourceNotFound, "")
		return nil, fmt.Errorf("error retrieving voucher for device %x: %w", probe.GUID, err)
	}
	if ov == nil || len(ov.Entries) == 0 {
		captureErr(ctx, protocol.ResourceNotFound, "")
		return nil, fmt.Errorf("error retrieving voucher for device %x: voucher not found or has no entries", probe.GUID)
	}

	// Generate nonce for ProveDevice20
	var proveDVPrepNonce protocol.Nonce
	if _, err := rand.Read(proveDVPrepNonce[:]); err != nil {
		return nil, fmt.Errorf("error generating ProveDevice nonce: %w", err)
	}
	if err := s.Session.SetProveDeviceNonce(ctx, proveDVPrepNonce); err != nil {
		return nil, fmt.Errorf("error storing ProveDevice nonce: %w", err)
	}

	// Hash the probe for binding in subsequent messages
	hashAlg := ov.Header.Val.CertChainHash.Algorithm
	probeHasher := hashAlg.HashFunc().New()
	probeData, err := cbor.Marshal(probe)
	if err != nil {
		return nil, fmt.Errorf("error marshaling probe for hashing: %w", err)
	}
	_, _ = probeHasher.Write(probeData)
	hashPrev := protocol.Hash{
		Algorithm: hashAlg,
		Value:     probeHasher.Sum(nil),
	}

	// Build response with server capabilities and supported crypto suites
	ack := &HelloDeviceAck20Msg{
		CapabilityFlags:     GlobalCapabilityFlags,
		GUID:                probe.GUID,
		MaxOwnerMsgSz:       65535,
		KexSuites:           []kex.Suite{kex.ECDH256Suite, kex.ECDH384Suite},
		CipherSuites:        []kex.CipherSuiteID{kex.A128GcmCipher, kex.A256GcmCipher},
		NonceTO2ProveDVPrep: proveDVPrepNonce,
		HashPrev:            hashPrev,
	}

	slog.Info("TO2.HelloDeviceAck20",
		"guid", fmt.Sprintf("%x", probe.GUID),
		"version", "2.0",
	)

	return ack, nil
}

// proveOVHdr20 handles ProveDevice20(82) -> ProveOVHdr20(83).
//
// In FDO 2.0, the device proves itself first. The server verifies the
// device EAT, then responds with the ownership voucher header proof
// (ProveOVHdr20). This is the reverse of FDO 1.1 where the owner
// proved first.
//
//nolint:gocyclo
func (s *TO2Server) proveOVHdr20(ctx context.Context, msg io.Reader) (*cose.Sign1Tag[ProveOVHdr20Payload, []byte], error) {
	// Decode the device's EAT (Entity Attestation Token)
	var proof cose.Sign1Tag[cbor.RawBytes, []byte]
	if err := cbor.NewDecoder(msg).Decode(&proof); err != nil {
		return nil, fmt.Errorf("error decoding TO2.ProveDevice20 request: %w", err)
	}
	var payload ProveDevice20Payload
	if err := cbor.Unmarshal([]byte(proof.Payload.Val), &payload); err != nil {
		return nil, fmt.Errorf("error decoding TO2.ProveDevice20 payload: %w", err)
	}

	// Retrieve voucher
	guid, err := s.Session.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving device GUID: %w", err)
	}
	ov, err := s.Vouchers.Voucher(ctx, guid)
	if err != nil {
		captureErr(ctx, protocol.ResourceNotFound, "")
		return nil, fmt.Errorf("error retrieving voucher for device %x: %w", guid, err)
	}
	if ov == nil || len(ov.Entries) == 0 {
		captureErr(ctx, protocol.ResourceNotFound, "")
		return nil, fmt.Errorf("error retrieving voucher for device %x: voucher not found or has no entries", guid)
	}
	numEntries := len(ov.Entries)
	if numEntries > math.MaxUint8 {
		return nil, fmt.Errorf("voucher for device %x has too many entries", guid)
	}

	// Verify device EAT signature
	devicePublicKey, err := ov.DevicePublicKey()
	if err != nil {
		return nil, fmt.Errorf("error parsing device public key: %w", err)
	}
	if ok, err := proof.Verify(devicePublicKey, nil, cose.AADProveDevice); err != nil {
		return nil, fmt.Errorf("error verifying device EAT signature: %w", err)
	} else if !ok {
		return nil, fmt.Errorf("device EAT signature verification failed")
	}

	// Verify the ProveDevice nonce
	proveDeviceNonce, err := s.Session.ProveDeviceNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving ProveDevice nonce: %w", err)
	}
	if payload.NonceTO2ProveOVPrep != proveDeviceNonce {
		return nil, fmt.Errorf("nonce mismatch in TO2.ProveDevice20")
	}

	// Verify voucher using custom configuration option
	if s.VerifyVoucher != nil {
		if err := s.VerifyVoucher(ctx, *ov); err != nil {
			captureErr(ctx, protocol.ResourceNotFound, "")
			return nil, fmt.Errorf("VerifyVoucher: %w", err)
		}
	} else if numEntries == 0 {
		captureErr(ctx, protocol.ResourceNotFound, "")
		return nil, fmt.Errorf("error retrieving voucher for device %x: %w", guid, ErrNotFound)
	}

	// Get owner key
	keyType := ov.Header.Val.ManufacturerKey.Type
	rsaBits := ov.Header.Val.ManufacturerKey.RsaBits()
	ownerKey, ownerPublicKey, err := s.ownerKey(ctx, keyType, ov.Header.Val.ManufacturerKey.Encoding, rsaBits)
	if err != nil {
		return nil, err
	}
	expectedOwnerKey, err := ov.OwnerPublicKey()
	if err != nil {
		return nil, fmt.Errorf("error parsing owner public key from voucher: %w", err)
	}
	eq, ok := ownerKey.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return nil, fmt.Errorf("owner key type %T does not support equality check", ownerKey.Public())
	}
	if !eq.Equal(expectedOwnerKey) {
		return nil, fmt.Errorf("owner key does not match voucher")
	}

	// Generate nonce for ProveOVHdr
	var proveOVNonce protocol.Nonce
	if _, err := rand.Read(proveOVNonce[:]); err != nil {
		return nil, fmt.Errorf("error generating ProveOVHdr nonce: %w", err)
	}

	// Begin key exchange using the device's selected suite
	if !payload.KexSuiteName.Valid(devicePublicKey, expectedOwnerKey) {
		return nil, fmt.Errorf("key exchange %s is invalid for the owner attestation type", payload.KexSuiteName)
	}
	if !kex.Available(payload.KexSuiteName, payload.CipherSuiteName) {
		return nil, fmt.Errorf("unsupported key exchange/cipher suite")
	}
	sess := payload.KexSuiteName.New(payload.XAKeyExchange, payload.CipherSuiteName)
	rsaOwnerPublicKey, _ := expectedOwnerKey.(*rsa.PublicKey)
	xB, err := sess.Parameter(rand.Reader, rsaOwnerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("error generating key exchange parameter: %w", err)
	}
	if err := s.Session.SetXSession(ctx, payload.KexSuiteName, sess); err != nil {
		clear(xB)
		return nil, fmt.Errorf("error storing key exchange session: %w", err)
	}

	// Determine signing key and build unprotected headers
	signingKey := ownerKey
	unprotectedHeaders := map[cose.Label]any{
		to2NonceClaim:       proveOVNonce,
		to2OwnerPubKeyClaim: ownerPublicKey,
	}

	// Handle delegation
	if s.OnboardDelegate != "" && s.DelegateKeys != nil {
		delegateKey, delegateChain, err := s.DelegateKeys.DelegateKey(s.OnboardDelegate)
		if err != nil {
			clear(xB)
			return nil, fmt.Errorf("error retrieving delegate key %q: %w", s.OnboardDelegate, err)
		}
		if len(delegateChain) == 0 {
			clear(xB)
			return nil, fmt.Errorf("delegate %q has no certificate chain", s.OnboardDelegate)
		}
		if err := VerifyDelegateChain(delegateChain, &expectedOwnerKey, nil); err != nil {
			clear(xB)
			return nil, fmt.Errorf("delegate chain for %q does not verify against owner key: %w", s.OnboardDelegate, err)
		}
		if !DelegateCanOnboard(delegateChain) {
			clear(xB)
			return nil, fmt.Errorf("delegate %q does not have onboarding permission", s.OnboardDelegate)
		}

		signingKey = delegateKey
		delegateChainRaw := make([][]byte, len(delegateChain))
		for i, cert := range delegateChain {
			delegateChainRaw[i] = cert.Raw
		}
		unprotectedHeaders[to2DelegateChainClaim] = delegateChainRaw
	}

	// Build ProveOVHdr20 response
	s1 := cose.Sign1[ProveOVHdr20Payload, []byte]{
		Header: cose.Header{
			Unprotected: unprotectedHeaders,
		},
		Payload: cbor.NewByteWrap(ProveOVHdr20Payload{
			OVH:             ov.Header,
			NumOVEntries:    uint8(numEntries),
			OVHHmac:         ov.Hmac,
			NonceTO2ProveOV: proveOVNonce,
			XBKeyExchange:   xB,
			MaxOwnerMsgSz:   65535,
		}),
	}

	opts, err := signOptsFor(signingKey, keyType == protocol.RsaPssKeyType)
	if err != nil {
		clear(xB)
		return nil, fmt.Errorf("error determining signing options: %w", err)
	}
	if err := s1.Sign(signingKey, nil, cose.AADProveOVHdr, opts); err != nil {
		clear(xB)
		return nil, fmt.Errorf("error signing ProveOVHdr20: %w", err)
	}

	// Store the ProveOV nonce for DoneAck20 response. We repurpose the
	// ProveDeviceNonce slot since it is no longer needed after the nonce
	// echo was verified above.
	if err := s.Session.SetProveDeviceNonce(ctx, proveOVNonce); err != nil {
		return nil, fmt.Errorf("error storing ProveOV nonce: %w", err)
	}

	return s1.Tag(), nil
}

// ovNextEntry20 handles GetOVNextEntry20(84) -> OVNextEntry20(85).
func (s *TO2Server) ovNextEntry20(ctx context.Context, msg io.Reader) (*OVNextEntry20Msg, error) {
	var req GetOVNextEntry20Msg
	if err := cbor.NewDecoder(msg).Decode(&req); err != nil {
		return nil, fmt.Errorf("error decoding TO2.GetOVNextEntry20 request: %w", err)
	}

	guid, err := s.Session.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving device GUID: %w", err)
	}
	ov, err := s.Vouchers.Voucher(ctx, guid)
	if err != nil {
		return nil, fmt.Errorf("error retrieving voucher for device %x: %w", guid, err)
	}
	if ov == nil || len(ov.Entries) == 0 {
		return nil, fmt.Errorf("error retrieving voucher for device %x: voucher not found or has no entries", guid)
	}
	if req.OVEntryNum >= len(ov.Entries) {
		return nil, fmt.Errorf("invalid voucher entry index %d", req.OVEntryNum)
	}

	return &OVNextEntry20Msg{
		OVEntryNum: req.OVEntryNum,
		OVEntry:    ov.Entries[req.OVEntryNum],
	}, nil
}

// setupDevice20 handles DeviceSvcInfoRdy20(86) -> SetupDevice20(87).
//
// In FDO 2.0, SetupDevice is the response to DeviceSvcInfoRdy (not to
// ProveDevice as in v1.1). The replacement HMAC is deferred to Done20.
func (s *TO2Server) setupDevice20(ctx context.Context, msg io.Reader) (*SetupDevice20Msg, error) {
	var ready DeviceSvcInfoRdy20Msg
	if err := cbor.NewDecoder(msg).Decode(&ready); err != nil {
		return nil, fmt.Errorf("error decoding TO2.DeviceSvcInfoRdy20 request: %w", err)
	}

	// Set send MTU
	mtu := uint16(serviceinfo.DefaultMTU)
	if ready.MaxOwnerSvcInfoSz != nil {
		mtu = *ready.MaxOwnerSvcInfoSz
	}
	if err := s.Session.SetMTU(ctx, mtu); err != nil {
		return nil, fmt.Errorf("error storing MTU: %w", err)
	}

	// Retrieve and validate voucher
	ov, err := s.sessionVoucher(ctx)
	if err != nil {
		return nil, err
	}

	// Generate setup nonce
	var setupNonce protocol.Nonce
	if _, err := rand.Read(setupNonce[:]); err != nil {
		return nil, fmt.Errorf("error generating SetupDevice nonce: %w", err)
	}
	if err := s.Session.SetSetupDeviceNonce(ctx, setupNonce); err != nil {
		return nil, fmt.Errorf("error storing SetupDevice nonce: %w", err)
	}

	return s.buildSetupDevice20Response(ctx, ov, setupNonce)
}

// buildSetupDevice20Response constructs the SetupDevice20 response, checking
// for credential reuse and generating replacement credentials as needed.
func (s *TO2Server) buildSetupDevice20Response(ctx context.Context, ov *Voucher, setupNonce protocol.Nonce) (*SetupDevice20Msg, error) {
	resp := &SetupDevice20Msg{
		NonceTO2SetupDV:    setupNonce,
		MaxDeviceSvcInfoSz: serviceinfo.DefaultMTU,
	}

	if s.MaxDeviceServiceInfoSize != nil {
		size, err := s.MaxDeviceServiceInfoSize(ctx, *ov)
		if err != nil {
			return nil, fmt.Errorf("error getting max device service info size: %w", err)
		}
		resp.MaxDeviceSvcInfoSz = size
	}

	// Check credential reuse
	if s.ReuseCredential != nil {
		reuse, err := s.ReuseCredential(ctx, *ov)
		if err != nil {
			return nil, fmt.Errorf("error checking credential reuse: %w", err)
		}
		if reuse {
			return resp, nil
		}
	}

	// Generate replacement credentials
	replacementGUID, replacementRvInfo, err := s.replacementCredential(ctx, ov)
	if err != nil {
		return nil, err
	}
	resp.ReplacementGUID = &replacementGUID
	resp.ReplacementRvInfo = &replacementRvInfo

	return resp, nil
}

// ownerServiceInfo20 handles DeviceSvcInfo20(88) -> OwnerSvcInfo20(89).
//
// This reuses much of the v1.1 service info exchange logic but with the
// v2.0 message types.
func (s *TO2Server) ownerServiceInfo20(ctx context.Context, deviceInfo *DeviceSvcInfo20Msg) (*OwnerSvcInfo20Msg, error) {
	// Convert v2.0 service info to the internal format and delegate to
	// the existing service info infrastructure.
	internalDeviceInfo := deviceServiceInfo{
		IsMoreServiceInfo: deviceInfo.IsMoreServiceInfo,
		ServiceInfo:       deviceInfo.ServiceInfo,
	}

	// Use the existing v1.1 owner service info handler, which returns the
	// internal ownerServiceInfo type. This shares the FSIM module
	// infrastructure.
	internalResp, err := s.ownerServiceInfo(ctx, readerFromStruct(internalDeviceInfo))
	if err != nil {
		return nil, err
	}

	return &OwnerSvcInfo20Msg{
		IsMoreServiceInfo: internalResp.IsMoreServiceInfo,
		IsDone:            internalResp.IsDone,
		ServiceInfo:       internalResp.ServiceInfo,
	}, nil
}

// doneAck20 handles Done20(90) -> DoneAck20(91).
func (s *TO2Server) doneAck20(ctx context.Context, msg io.Reader) (*DoneAck20Msg, error) {
	var done Done20Msg
	if err := cbor.NewDecoder(msg).Decode(&done); err != nil {
		return nil, fmt.Errorf("error decoding TO2.Done20 request: %w", err)
	}

	// Get and validate the setup nonce
	setupDeviceNonce, err := s.Session.SetupDeviceNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving SetupDevice nonce: %w", err)
	}
	if !bytes.Equal(setupDeviceNonce[:], done.NonceTO2SetupDV[:]) {
		return nil, fmt.Errorf("nonce from TO2.SetupDevice did not match TO2.Done20")
	}

	// If the replacement HMAC is non-nil, create a replacement voucher
	if done.ReplacementHmac != nil {
		if err := s.replaceVoucher20(ctx, done.ReplacementHmac); err != nil {
			return nil, err
		}
	}

	// Retrieve the ProveOV nonce for the response
	proveDeviceNonce, err := s.Session.ProveDeviceNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving ProveOV nonce: %w", err)
	}
	return &DoneAck20Msg{
		NonceTO2ProveOV: proveDeviceNonce,
	}, nil
}

// replaceVoucher20 stores the replacement HMAC and creates a new voucher
// for credential renewal during Done20.
func (s *TO2Server) replaceVoucher20(ctx context.Context, replacementHmac *protocol.Hmac) error {
	if err := s.Session.SetReplacementHmac(ctx, *replacementHmac); err != nil {
		return fmt.Errorf("error storing replacement HMAC: %w", err)
	}

	currentOV, err := s.sessionVoucher(ctx)
	if err != nil {
		return err
	}
	currentGUID, err := s.Session.GUID(ctx)
	if err != nil {
		return fmt.Errorf("error retrieving device GUID: %w", err)
	}
	rvInfo, err := s.Session.RvInfo(ctx)
	if err != nil {
		return fmt.Errorf("error retrieving rendezvous info: %w", err)
	}
	replacementGUID, err := s.Session.ReplacementGUID(ctx)
	if err != nil {
		return fmt.Errorf("error retrieving replacement GUID: %w", err)
	}

	mfgKey := currentOV.Header.Val.ManufacturerKey
	_, ownerPublicKey, err := s.ownerKey(ctx, mfgKey.Type, mfgKey.Encoding, mfgKey.RsaBits())
	if err != nil {
		return err
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
		Hmac:      *replacementHmac,
		CertChain: currentOV.CertChain,
		Entries:   nil,
	}
	if err := s.Vouchers.ReplaceVoucher(ctx, currentGUID, ov); err != nil {
		return fmt.Errorf("error replacing voucher: %w", err)
	}
	return nil
}

// sessionVoucher retrieves and validates the voucher for the current session.
func (s *TO2Server) sessionVoucher(ctx context.Context) (*Voucher, error) {
	guid, err := s.Session.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving device GUID: %w", err)
	}
	ov, err := s.Vouchers.Voucher(ctx, guid)
	if err != nil {
		return nil, fmt.Errorf("error retrieving voucher for device %x: %w", guid, err)
	}
	if ov == nil || len(ov.Entries) == 0 {
		return nil, fmt.Errorf("error retrieving voucher for device %x: voucher not found or has no entries", guid)
	}
	return ov, nil
}

// readerFromStruct marshals a struct to CBOR and returns it as an io.Reader.
func readerFromStruct(v any) io.Reader {
	data, err := cbor.Marshal(v)
	if err != nil {
		// This should never happen for well-formed structs
		return bytes.NewReader(nil)
	}
	return bytes.NewReader(data)
}
