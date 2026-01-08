// SPDX-FileCopyrightText: (C) 2024 Intel Corporation & Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"fmt"
	"hash"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// FDO 2.0 TO2 Client Flow
//
// Key difference from 1.01: Device proves itself FIRST (anti-DoS measure)
// Flow: HelloDeviceProbe(80) -> HelloDeviceAck20(81) -> ProveDevice20(82) ->
//       ProveOVHdr20(83) -> GetOVNextEntry20(84) -> OVNextEntry20(85) ->
//       DeviceSvcInfoRdy20(86) -> SetupDevice20(87) -> DeviceSvcInfo20(88) ->
//       OwnerSvcInfo20(89) -> Done20(90) -> DoneAck20(91)

// TO2v200 runs the FDO 2.0 TO2 protocol. It has the same interface as TO2 but
// uses the 2.0 message flow where the device proves itself first.
func TO2v200(ctx context.Context, transport Transport, to1d *cose.Sign1[protocol.To1d, []byte], c TO2Config) (*DeviceCredential, error) {
	ctx = contextWithErrMsg(ctx)

	// Configure defaults (same as 1.01)
	if c.KeyExchange == "" {
		c.KeyExchange = kex.ECDH384Suite
	}
	if c.CipherSuite == 0 {
		c.CipherSuite = kex.A256GcmCipher
	}
	if c.MaxServiceInfoSizeReceive == 0 {
		c.MaxServiceInfoSizeReceive = serviceinfo.DefaultMTU
	}
	if c.DeviceModules == nil {
		c.DeviceModules = make(map[string]serviceinfo.DeviceModule)
	}

	// Step 1: Send HelloDeviceProbe, receive HelloDeviceAck20
	ack, err := sendHelloDeviceProbe(ctx, transport, &c)
	if err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}

	// Step 2: Device proves itself FIRST (key 2.0 difference)
	// Send ProveDevice20, receive ProveOVHdr20
	proveOVNonce, ownerInfo, sess, err := sendProveDevice20(ctx, transport, ack, &c)
	if err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}
	defer sess.Destroy()

	// Step 3: Verify owner's proof and get voucher entries
	if err := verifyOwner20(ctx, transport, to1d, ownerInfo, &c); err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}

	// Step 4: Service info exchange
	// Send DeviceSvcInfoRdy20 and receive SetupDevice20 with GUID/RvInfo
	setupDeviceNonce, partialOVH, err := sendDeviceSvcInfoRdy20(ctx, transport, sess, ownerInfo.DelegateChain, &c)
	if err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}

	// Build replacement voucher header using server-provided GUID/RvInfo
	// HMAC will be computed after we have all the info
	alg := c.Cred.PublicKeyHash.Algorithm
	var replacementOVH *VoucherHeader
	if partialOVH != nil {
		// The new owner's public key becomes the ManufacturerKey in the replacement header
		// Use the full protocol.PublicKey from the server (includes cert chain for X5Chain encoding)
		alg, err = hashAlgFor(c.Key.Public(), ownerInfo.OwnerPublicKey)
		if err != nil {
			return nil, fmt.Errorf("error selecting hash algorithm: %w", err)
		}
		replacementOVH = &VoucherHeader{
			Version:         ownerInfo.OVH.Version,
			GUID:            partialOVH.GUID,
			RvInfo:          partialOVH.RvInfo,
			DeviceInfo:      ownerInfo.OVH.DeviceInfo,
			ManufacturerKey: ownerInfo.OwnerPublicKeyPKI,
			CertChainHash:   ownerInfo.OVH.CertChainHash,
		}
	}

	// Step 5: Compute replacement HMAC now that we have GUID/RvInfo from server
	var replacementHMAC *protocol.Hmac
	if replacementOVH != nil {
		var h hash.Hash
		switch alg {
		case protocol.Sha256Hash, protocol.HmacSha256Hash:
			h = c.HmacSha256
		case protocol.Sha384Hash, protocol.HmacSha384Hash:
			h = c.HmacSha384
		default:
			return nil, fmt.Errorf("unsupported hash algorithm: %s", alg)
		}
		hmacVal, err := hmacHash(h, replacementOVH)
		if err != nil {
			return nil, fmt.Errorf("error computing replacement HMAC: %w", err)
		}
		replacementHMAC = &hmacVal
	}

	// Step 6: Exchange service info
	sendMTU := uint16(1300) // Default MTU
	serviceInfoReader, serviceInfoWriter := serviceinfo.NewChunkOutPipe(0)
	defer func() { _ = serviceInfoWriter.Close() }()

	go c.Devmod.Write(ctx, c.DeviceModules, sendMTU, serviceInfoWriter)

	if err := exchangeServiceInfo20(ctx, transport, proveOVNonce, setupDeviceNonce, sendMTU, serviceInfoReader, replacementHMAC, sess, &c); err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}

	// If using Credential Reuse, return the original credential
	if replacementOVH == nil {
		return &c.Cred, nil
	}

	// Hash new owner public key and return replacement credential
	replacementKeyDigest := alg.HashFunc().New()
	if err := cbor.NewEncoder(replacementKeyDigest).Encode(replacementOVH.ManufacturerKey); err != nil {
		err = fmt.Errorf("error computing hash of replacement owner key: %w", err)
		errorMsg(ctx, transport, err)
		return nil, err
	}
	replacementPublicKeyHash := protocol.Hash{Algorithm: alg, Value: replacementKeyDigest.Sum(nil)[:]}

	return &DeviceCredential{
		Version:       replacementOVH.Version,
		DeviceInfo:    replacementOVH.DeviceInfo,
		GUID:          replacementOVH.GUID,
		RvInfo:        replacementOVH.RvInfo,
		PublicKeyHash: replacementPublicKeyHash,
	}, nil
}

// sendHelloDeviceProbe sends TO2.HelloDeviceProbe (80) and receives TO2.HelloDeviceAck20 (81)
func sendHelloDeviceProbe(ctx context.Context, transport Transport, c *TO2Config) (*HelloDeviceAck20Msg, error) {
	// Generate random sugar for hash binding
	var sugar [16]byte
	if _, err := rand.Read(sugar[:]); err != nil {
		return nil, fmt.Errorf("error generating sugar: %w", err)
	}

	probe := HelloDeviceProbeMsg{
		CapabilityFlags:      GlobalCapabilityFlags,
		GUID:                 c.Cred.GUID,
		MaxDeviceMessageSize: 65535,
		HashTypes:            []protocol.HashAlg{protocol.Sha384Hash, protocol.Sha256Hash},
		Sugar:                sugar,
	}

	typ, resp, err := transport.Send(ctx, protocol.TO2HelloDeviceProbeMsgType, probe, nil)
	if err != nil {
		return nil, fmt.Errorf("error sending TO2.HelloDeviceProbe: %w", err)
	}
	defer func() { _ = resp.Close() }()

	switch typ {
	case protocol.TO2HelloDeviceAck20MsgType:
		captureMsgType(ctx, typ)
		var ack HelloDeviceAck20Msg
		if err := cbor.NewDecoder(resp).Decode(&ack); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return nil, fmt.Errorf("error parsing TO2.HelloDeviceAck20: %w", err)
		}
		return &ack, nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return nil, fmt.Errorf("error parsing error message: %w", err)
		}
		return nil, fmt.Errorf("error from TO2.HelloDeviceProbe: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		return nil, fmt.Errorf("unexpected response type %d to TO2.HelloDeviceProbe", typ)
	}
}

// OwnerInfo20 contains the owner's proof information from ProveOVHdr20
type OwnerInfo20 struct {
	OVH               VoucherHeader
	OVHHmac           protocol.Hmac
	NumVoucherEntries int
	OwnerPublicKey    crypto.PublicKey   // Raw public key for signature verification
	OwnerPublicKeyPKI protocol.PublicKey // Full PKI structure for replacement header
	OriginalOwnerKey  crypto.PublicKey
	DelegateChain     *protocol.PublicKey // Delegate chain if using delegation (nil if direct owner)
}

// sendProveDevice20 sends TO2.ProveDevice20 (82) and receives TO2.ProveOVHdr20 (83)
// This is where the device proves itself FIRST in 2.0
func sendProveDevice20(ctx context.Context, transport Transport, ack *HelloDeviceAck20Msg, c *TO2Config) (protocol.Nonce, *OwnerInfo20, kex.Session, error) {
	// Generate nonce for ProveOVHdr20
	var proveOVNonce protocol.Nonce
	if _, err := rand.Read(proveOVNonce[:]); err != nil {
		return protocol.Nonce{}, nil, nil, fmt.Errorf("error generating nonce: %w", err)
	}

	// Select key exchange suite from server's offered options
	var selectedKex kex.Suite
	var selectedCipher kex.CipherSuiteID
	for _, s := range ack.KexSuites {
		if s == c.KeyExchange {
			selectedKex = s
			break
		}
	}
	if selectedKex == "" {
		selectedKex = ack.KexSuites[0] // Use first offered if preferred not available
	}
	for _, cs := range ack.CipherSuites {
		if cs == c.CipherSuite {
			selectedCipher = cs
			break
		}
	}
	if selectedCipher == 0 {
		selectedCipher = ack.CipherSuites[0]
	}

	// Initialize key exchange session
	sess := selectedKex.New(nil, selectedCipher)
	xA, err := sess.Parameter(rand.Reader, nil)
	if err != nil {
		return protocol.Nonce{}, nil, nil, fmt.Errorf("error generating key exchange parameter: %w", err)
	}

	// Hash the HelloDeviceAck20 for binding
	hashAlg := protocol.Sha384Hash // Default to SHA384
	ackHash := protocol.Hash{Algorithm: hashAlg}
	hasher := hashAlg.HashFunc().New()
	ackBytes, err := cbor.Marshal(ack)
	if err != nil {
		clear(xA)
		return protocol.Nonce{}, nil, nil, fmt.Errorf("error encoding ack for hash: %w", err)
	}
	hasher.Write(ackBytes)
	ackHash.Value = hasher.Sum(nil)

	// Build ProveDevice20 payload
	payload := ProveDevice20Payload{
		KexSuiteName:         selectedKex,
		CipherSuiteName:      selectedCipher,
		XAKeyExchange:        xA,
		NonceTO2ProveOV_Prep: proveOVNonce,
		HashPrev2:            ackHash,
	}

	// Sign with device key (EAT token)
	s1 := cose.Sign1[ProveDevice20Payload, []byte]{
		Payload: cbor.NewByteWrap(payload),
	}
	opts, err := signOptsFor(c.Key, c.PSS)
	if err != nil {
		clear(xA)
		return protocol.Nonce{}, nil, nil, fmt.Errorf("error determining signing options for ProveDevice20: %w", err)
	}
	if err := s1.Sign(c.Key, nil, nil, opts); err != nil {
		clear(xA)
		return protocol.Nonce{}, nil, nil, fmt.Errorf("error signing ProveDevice20: %w", err)
	}

	// Send ProveDevice20
	typ, resp, err := transport.Send(ctx, protocol.TO2ProveDevice20MsgType, cose.Sign1Tag[ProveDevice20Payload, []byte]{Sign1: s1}, nil)
	if err != nil {
		clear(xA)
		return protocol.Nonce{}, nil, nil, fmt.Errorf("error sending TO2.ProveDevice20: %w", err)
	}
	defer func() { _ = resp.Close() }()

	switch typ {
	case protocol.TO2ProveOVHdr20MsgType:
		captureMsgType(ctx, typ)
		var proveOVHdr cose.Sign1Tag[ProveOVHdr20Payload, []byte]
		if err := cbor.NewDecoder(resp).Decode(&proveOVHdr); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			sess.Destroy()
			return protocol.Nonce{}, nil, nil, fmt.Errorf("error parsing TO2.ProveOVHdr20: %w", err)
		}

		// Get owner public key from COSE header (like 1.01)
		var ownerPubKeyProto protocol.PublicKey
		if found, err := proveOVHdr.Unprotected.Parse(to2OwnerPubKeyClaim, &ownerPubKeyProto); !found {
			sess.Destroy()
			return protocol.Nonce{}, nil, nil, fmt.Errorf("owner public key not found in COSE header")
		} else if err != nil {
			sess.Destroy()
			return protocol.Nonce{}, nil, nil, fmt.Errorf("error parsing owner public key from header: %w", err)
		}
		ownerPubKey, err := ownerPubKeyProto.Public()
		if err != nil {
			sess.Destroy()
			return protocol.Nonce{}, nil, nil, fmt.Errorf("error parsing owner public key: %w", err)
		}

		// Parse delegate chain if present (optional)
		var delegateChain *protocol.PublicKey
		var delegatePubKeyProto protocol.PublicKey
		if found, err := proveOVHdr.Unprotected.Parse(to2DelegateClaim, &delegatePubKeyProto); found && err == nil {
			delegateChain = &delegatePubKeyProto
			// If delegate is present, verify signature with delegate key instead
			delegatePubKey, err := delegatePubKeyProto.Public()
			if err != nil {
				sess.Destroy()
				return protocol.Nonce{}, nil, nil, fmt.Errorf("error parsing delegate public key: %w", err)
			}
			ownerPubKey = delegatePubKey
		}

		// Verify owner's (or delegate's) signature
		if ok, err := proveOVHdr.Verify(ownerPubKey, nil, nil); err != nil {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			sess.Destroy()
			return protocol.Nonce{}, nil, nil, fmt.Errorf("error verifying owner signature: %w", err)
		} else if !ok {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			sess.Destroy()
			return protocol.Nonce{}, nil, nil, fmt.Errorf("owner signature verification failed")
		}

		// Verify nonce matches
		if proveOVHdr.Payload.Val.NonceTO2ProveOV != proveOVNonce {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			sess.Destroy()
			return protocol.Nonce{}, nil, nil, fmt.Errorf("nonce mismatch in TO2.ProveOVHdr20")
		}

		// Get voucher header directly from Bstr wrapper
		ovh := proveOVHdr.Payload.Val.OVHeader.Val

		// Complete key exchange with server's parameter
		if err := sess.SetParameter(proveOVHdr.Payload.Val.XBKeyExchange, nil); err != nil {
			sess.Destroy()
			return protocol.Nonce{}, nil, nil, fmt.Errorf("error setting peer key exchange parameter: %w", err)
		}

		// Get original owner key from voucher header
		originalOwnerKey, err := ovh.ManufacturerKey.Public()
		if err != nil {
			sess.Destroy()
			return protocol.Nonce{}, nil, nil, fmt.Errorf("error parsing manufacturer key: %w", err)
		}

		return proveOVNonce, &OwnerInfo20{
			OVH:               ovh,
			OVHHmac:           proveOVHdr.Payload.Val.HMac,
			NumVoucherEntries: int(proveOVHdr.Payload.Val.NumOVEntries),
			OwnerPublicKey:    ownerPubKey,
			OwnerPublicKeyPKI: ownerPubKeyProto,
			OriginalOwnerKey:  originalOwnerKey,
			DelegateChain:     delegateChain,
		}, sess, nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return protocol.Nonce{}, nil, nil, fmt.Errorf("error parsing error message: %w", err)
		}
		sess.Destroy()
		return protocol.Nonce{}, nil, nil, fmt.Errorf("error from TO2.ProveDevice20: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		sess.Destroy()
		return protocol.Nonce{}, nil, nil, fmt.Errorf("unexpected response type %d to TO2.ProveDevice20", typ)
	}
}

// verifyOwner20 verifies the owner's proof by fetching and validating voucher entries
func verifyOwner20(ctx context.Context, transport Transport, to1d *cose.Sign1[protocol.To1d, []byte], info *OwnerInfo20, c *TO2Config) error {
	// Fetch all voucher entries
	var entries []cose.Sign1Tag[VoucherEntryPayload, []byte]
	for i := range info.NumVoucherEntries {
		entry, err := sendGetOVNextEntry20(ctx, transport, i)
		if err != nil {
			return err
		}
		entries = append(entries, *entry)
	}

	// Construct voucher and verify
	ov := Voucher{
		Header:  *cbor.NewBstr(info.OVH),
		Hmac:    info.OVHHmac,
		Entries: entries,
	}

	// Determine the expected owner key for validation:
	// - If there are voucher entries, it's the last entry's public key
	// - If no entries, it's the manufacturer key from the header
	// When a delegate is used, OwnerPublicKey is the delegate key (used for signature
	// verification), but voucher validation needs the actual owner from the chain.
	var ownerKeyForValidation crypto.PublicKey
	if len(entries) > 0 {
		lastEntryKey, err := entries[len(entries)-1].Payload.Val.PublicKey.Public()
		if err != nil {
			return fmt.Errorf("error parsing last voucher entry public key: %w", err)
		}
		ownerKeyForValidation = lastEntryKey
	} else {
		ownerKeyForValidation = info.OriginalOwnerKey
	}

	if err := ov.VerifyCrypto(VerifyOptions{
		HmacSha256:         c.HmacSha256,
		HmacSha384:         c.HmacSha384,
		MfgPubKeyHash:      c.Cred.PublicKeyHash,
		OwnerPubToValidate: ownerKeyForValidation,
		To1d:               to1d,
	}); err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return err
	}

	return nil
}

// sendGetOVNextEntry20 sends TO2.GetOVNextEntry20 (84) and receives TO2.OVNextEntry20 (85)
func sendGetOVNextEntry20(ctx context.Context, transport Transport, entryNum int) (*cose.Sign1Tag[VoucherEntryPayload, []byte], error) {
	req := GetOVNextEntry20Msg{OVEntryNum: uint8(entryNum)}

	typ, resp, err := transport.Send(ctx, protocol.TO2GetOVNextEntry20MsgType, req, nil)
	if err != nil {
		return nil, fmt.Errorf("error sending TO2.GetOVNextEntry20: %w", err)
	}
	defer func() { _ = resp.Close() }()

	switch typ {
	case protocol.TO2OVNextEntry20MsgType:
		captureMsgType(ctx, typ)
		var entry OVNextEntry20Msg
		if err := cbor.NewDecoder(resp).Decode(&entry); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return nil, fmt.Errorf("error parsing TO2.OVNextEntry20: %w", err)
		}
		var voucherEntry cose.Sign1Tag[VoucherEntryPayload, []byte]
		if err := cbor.Unmarshal(entry.OVEntry, &voucherEntry); err != nil {
			return nil, fmt.Errorf("error parsing voucher entry: %w", err)
		}
		return &voucherEntry, nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return nil, fmt.Errorf("error parsing error message: %w", err)
		}
		return nil, fmt.Errorf("error from TO2.GetOVNextEntry20: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		return nil, fmt.Errorf("unexpected response type %d to TO2.GetOVNextEntry20", typ)
	}
}

// partialOVH20 holds partial replacement voucher header info
type partialOVH20 struct {
	GUID            protocol.GUID
	RvInfo          [][]protocol.RvInstruction
	ManufacturerKey protocol.PublicKey
}

// sendDeviceSvcInfoRdy20 sends TO2.DeviceSvcInfoRdy20 (86) and receives TO2.SetupDevice20 (87)
// Note: HMAC is computed and sent in Done20 (not here) so client can compute it
// after receiving GUID/RvInfo from SetupDevice20
func sendDeviceSvcInfoRdy20(ctx context.Context, transport Transport, sess kex.Session, delegateChain *protocol.PublicKey, c *TO2Config) (protocol.Nonce, *partialOVH20, error) {
	req := DeviceSvcInfoRdy20Msg{
		MaxOwnerServiceInfoSz: &c.MaxServiceInfoSizeReceive,
	}

	typ, resp, err := transport.Send(ctx, protocol.TO2DeviceSvcInfoRdy20MsgType, req, sess)
	if err != nil {
		return protocol.Nonce{}, nil, fmt.Errorf("error sending TO2.DeviceSvcInfoRdy20: %w", err)
	}
	defer func() { _ = resp.Close() }()

	switch typ {
	case protocol.TO2SetupDevice20MsgType:
		captureMsgType(ctx, typ)
		var setup SetupDevice20Msg
		if err := cbor.NewDecoder(resp).Decode(&setup); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return protocol.Nonce{}, nil, fmt.Errorf("error parsing TO2.SetupDevice20: %w", err)
		}

		// Check for credential reuse
		if setup.ReplacementGUID == nil {
			if !c.AllowCredentialReuse {
				captureErr(ctx, protocol.CredReuseErrCode, "")
				return protocol.Nonce{}, nil, fmt.Errorf("credential reuse not allowed")
			}
			// If using delegate, verify it has fdo-ekt-permit-onboard-reuse-cred permission
			if delegateChain != nil {
				chain, err := delegateChain.Chain()
				if err != nil {
					captureErr(ctx, protocol.InvalidMessageErrCode, "")
					return protocol.Nonce{}, nil, fmt.Errorf("error parsing delegate chain: %w", err)
				}
				if !DelegateCanReuseCred(chain) {
					captureErr(ctx, protocol.CredReuseErrCode, "")
					return protocol.Nonce{}, nil, fmt.Errorf("delegate certificate does not have fdo-ekt-permit-onboard-reuse-cred permission")
				}
			}
			return setup.NonceTO2SetupDV, nil, nil
		}

		// Build partial replacement header
		// Note: ManufacturerKey will be the new owner's key
		return setup.NonceTO2SetupDV, &partialOVH20{
			GUID:   *setup.ReplacementGUID,
			RvInfo: *setup.ReplacementRvInfo,
			// ManufacturerKey will be filled from owner info
		}, nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return protocol.Nonce{}, nil, fmt.Errorf("error parsing error message: %w", err)
		}
		return protocol.Nonce{}, nil, fmt.Errorf("error from TO2.DeviceSvcInfoRdy20: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		return protocol.Nonce{}, nil, fmt.Errorf("unexpected response type %d to TO2.DeviceSvcInfoRdy20", typ)
	}
}

// exchangeServiceInfo20 handles the service info exchange loop for 2.0
func exchangeServiceInfo20(ctx context.Context, transport Transport, proveOVNonce, setupDeviceNonce protocol.Nonce, sendMTU uint16, serviceInfoReader *serviceinfo.ChunkReader, replacementHMAC *protocol.Hmac, sess kex.Session, c *TO2Config) error {
	// Simple service info exchange - send device info, receive owner info
	var deviceDone bool
	for {
		// Read next chunk of device service info
		var kvs []*serviceinfo.KV
		if !deviceDone {
			kv, err := serviceInfoReader.ReadChunk(sendMTU)
			if err != nil {
				deviceDone = true
			} else if kv != nil {
				kvs = append(kvs, kv)
			}
		}

		req := DeviceSvcInfo20Msg{
			IsMoreServiceInfo: !deviceDone,
			ServiceInfo:       kvs,
		}

		typ, resp, err := transport.Send(ctx, protocol.TO2DeviceSvcInfo20MsgType, req, sess)
		if err != nil {
			return fmt.Errorf("error sending TO2.DeviceSvcInfo20: %w", err)
		}

		switch typ {
		case protocol.TO2OwnerSvcInfo20MsgType:
			captureMsgType(ctx, typ)
			var ownerInfo OwnerSvcInfo20Msg
			if err := cbor.NewDecoder(resp).Decode(&ownerInfo); err != nil {
				_ = resp.Close()
				captureErr(ctx, protocol.MessageBodyErrCode, "")
				return fmt.Errorf("error parsing TO2.OwnerSvcInfo20: %w", err)
			}
			_ = resp.Close()

			// TODO: Process owner service info through device modules
			// Full implementation would parse KV.Key to get module name and message
			// and call the appropriate device module
			_ = ownerInfo.ServiceInfo

			// Check if done
			if ownerInfo.IsDone && deviceDone {
				// Send Done20 with replacement HMAC
				return sendDone20(ctx, transport, proveOVNonce, setupDeviceNonce, replacementHMAC, sess)
			}

		case protocol.ErrorMsgType:
			var errMsg protocol.ErrorMessage
			_ = cbor.NewDecoder(resp).Decode(&errMsg)
			_ = resp.Close()
			return fmt.Errorf("error from TO2.DeviceSvcInfo20: %w", errMsg)

		default:
			_ = resp.Close()
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return fmt.Errorf("unexpected response type %d to TO2.DeviceSvcInfo20", typ)
		}
	}
}

// sendDone20 sends TO2.Done20 (90) and receives TO2.DoneAck20 (91)
func sendDone20(ctx context.Context, transport Transport, proveOVNonce, setupDeviceNonce protocol.Nonce, replacementHMAC *protocol.Hmac, sess kex.Session) error {
	req := Done20Msg{
		NonceTO2SetupDV: setupDeviceNonce,
		ReplacementHMAC: replacementHMAC,
	}

	typ, resp, err := transport.Send(ctx, protocol.TO2Done20MsgType, req, sess)
	if err != nil {
		return fmt.Errorf("error sending TO2.Done20: %w", err)
	}
	defer func() { _ = resp.Close() }()

	switch typ {
	case protocol.TO2DoneAck20MsgType:
		captureMsgType(ctx, typ)
		var ack DoneAck20Msg
		if err := cbor.NewDecoder(resp).Decode(&ack); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return fmt.Errorf("error parsing TO2.DoneAck20: %w", err)
		}

		// Verify nonce
		if !bytes.Equal(ack.NonceTO2ProveOV[:], proveOVNonce[:]) {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			return fmt.Errorf("nonce mismatch in TO2.DoneAck20")
		}

		return nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return fmt.Errorf("error parsing error message: %w", err)
		}
		return fmt.Errorf("error from TO2.Done20: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		return fmt.Errorf("unexpected response type %d to TO2.Done20", typ)
	}
}
