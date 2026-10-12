// SPDX-FileCopyrightText: (C) 2024 Intel Corporation & Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"slices"

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

// TO2v200 implements the FDO 2.0 TO2 protocol
func TO2v200(ctx context.Context, transport Transport, to1d *cose.Sign1[protocol.To1d, []byte], c *TO2Config) (*DeviceCredential, error) { //nolint:gocyclo
	ctx = withTO2v200(contextWithErrMsg(ctx))

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
	ack, ackBytes, err := sendHelloDeviceProbe(ctx, transport, c)
	if err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}
	// NonceTO2ProveDv: signed in the ProveDevice20 EAT, echoed in Done20
	proveDvNonce := ack.NonceTO2ProveDVPrep

	// Step 2: Device proves itself FIRST (key 2.0 difference)
	// Send ProveDevice20, receive ProveOVHdr20
	ownerInfo, sess, err := sendProveDevice20(ctx, transport, ack, ackBytes, c)
	if err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}
	defer sess.Destroy()

	// Step 3: Verify owner's proof and get voucher entries
	if err := verifyOwner20(ctx, transport, to1d, ownerInfo, c); err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}

	// Step 4: Service info exchange
	// Send DeviceSvcInfoRdy20 and receive SetupDevice20 with GUID/RvInfo
	setupDeviceNonce, partialOVH, sendMTU, err := sendDeviceSvcInfoRdy20(ctx, transport, sess, ownerInfo, c)
	if err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}

	// Build replacement voucher header using server-provided GUID/RvInfo
	// HMAC will be computed after we have all the info
	alg := c.Cred.PublicKeyHash.Algorithm
	var replacementOVH *VoucherHeader
	if partialOVH != nil {
		// The Owner2 key becomes the ManufacturerKey in the replacement header
		owner2Pub, err := partialOVH.ManufacturerKey.Public()
		if err != nil {
			return nil, fmt.Errorf("error parsing Owner2 key: %w", err)
		}
		alg, err = hashAlgFor(c.Key.Public(), owner2Pub)
		if err != nil {
			return nil, fmt.Errorf("error selecting hash algorithm: %w", err)
		}
		replacementOVH = &VoucherHeader{
			Version:         ownerInfo.OVH.Version,
			GUID:            partialOVH.GUID,
			RvInfo:          partialOVH.RvInfo,
			DeviceInfo:      ownerInfo.OVH.DeviceInfo,
			ManufacturerKey: partialOVH.ManufacturerKey,
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

	// Step 6: Exchange service info, sending at most the
	// MaxDeviceServiceInfoSz from TO2.SetupDevice20 (exchangeServiceInfo
	// accounts for the message overhead, as for FDO 1.01)
	serviceInfoReader, serviceInfoWriter := serviceinfo.NewChunkOutPipe(0)
	defer func() { _ = serviceInfoWriter.Close() }()

	go c.Devmod.Write(ctx, c.DeviceModules, sendMTU, serviceInfoWriter)

	sendDone := func(ctx context.Context) error {
		return sendDone20(ctx, transport, proveDvNonce, setupDeviceNonce, replacementHMAC, sess)
	}
	if err := exchangeServiceInfo(ctx, transport, sendMTU, serviceInfoReader, sess, c, sendDone); err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}

	// If using Credential Reuse, return nil to match FDO 1.01 behavior
	if replacementOVH == nil {
		return nil, nil
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

// sendHelloDeviceProbe sends TO2.HelloDeviceProbe (80) and receives TO2.HelloDeviceAck20 (81).
// It returns the ack and its bytes as received (hashed into ProveDevice20.hashPrev2).
func sendHelloDeviceProbe(ctx context.Context, transport Transport, c *TO2Config) (*HelloDeviceAck20Msg, []byte, error) { //nolint:gocyclo
	// Generate random sugar for hash binding
	var sugar [16]byte
	if _, err := rand.Read(sugar[:]); err != nil {
		return nil, nil, fmt.Errorf("error generating sugar: %w", err)
	}

	probe := HelloDeviceProbeMsg{
		CapabilityFlags:      GlobalCapabilityFlags,
		GUID:                 c.Cred.GUID,
		MaxDeviceMessageSize: 65535,
		HashTypes:            []protocol.HashAlg{protocol.Sha384Hash, protocol.Sha256Hash},
		Sugar:                sugar,
	}
	// Encoding is deterministic, so these are the bytes the transport sends.
	probeBytes, err := cbor.Marshal(probe)
	if err != nil {
		return nil, nil, fmt.Errorf("error encoding TO2.HelloDeviceProbe: %w", err)
	}

	typ, resp, err := transport.Send(ctx, protocol.TO2HelloDeviceProbeMsgType, probe, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("error sending TO2.HelloDeviceProbe: %w", err)
	}
	defer func() { _ = resp.Close() }()

	switch typ {
	case protocol.TO2HelloDeviceAck20MsgType:
		captureMsgType(ctx, typ)
		ackBytes, err := io.ReadAll(resp)
		if err != nil {
			return nil, nil, fmt.Errorf("error reading TO2.HelloDeviceAck20: %w", err)
		}
		var ack HelloDeviceAck20Msg
		if err := cbor.Unmarshal(ackBytes, &ack); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return nil, nil, fmt.Errorf("error parsing TO2.HelloDeviceAck20: %w", err)
		}
		if ack.GUID != c.Cred.GUID {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			return nil, nil, fmt.Errorf("TO2.HelloDeviceAck20 GUID does not match device credential")
		}

		// hashPrev must be the hash of the probe we sent, with a hash type we offered
		if !slices.Contains(probe.HashTypes, ack.HashPrev.Algorithm) {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			return nil, nil, fmt.Errorf("TO2.HelloDeviceAck20 hashPrev uses a hash type the device did not offer")
		}
		want, err := hashMessage(ack.HashPrev.Algorithm, probeBytes)
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(want.Value, ack.HashPrev.Value) {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			return nil, nil, fmt.Errorf("TO2.HelloDeviceAck20 hashPrev does not match TO2.HelloDeviceProbe")
		}

		return &ack, ackBytes, nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return nil, nil, fmt.Errorf("error parsing error message: %w", err)
		}
		return nil, nil, fmt.Errorf("error from TO2.HelloDeviceProbe: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		return nil, nil, fmt.Errorf("unexpected response type %d to TO2.HelloDeviceProbe", typ)
	}
}

// OwnerInfo20 contains the owner's proof information from ProveOVHdr20
type OwnerInfo20 struct {
	OVH               VoucherHeader
	OVHHmac           protocol.Hmac
	NumVoucherEntries int
	OwnerPublicKey    crypto.PublicKey   // Key that signed ProveOVHdr20 (Owner, or Delegate leaf)
	OwnerPublicKeyPKI protocol.PublicKey // OwnerPubKey from the ProveOVHdr20 payload
	OriginalOwnerKey  crypto.PublicKey
	DelegateChain     *protocol.PublicKey // Delegate chain if using delegation (nil if direct owner)
	KexSuite          kex.Suite           // Key exchange suite selected in ProveDevice20
}

// selectSuites20 picks the key exchange and cipher suites for
// TO2.ProveDevice20 from those offered in TO2.HelloDeviceAck20. The
// configured suites are used when offered; otherwise the first offered suite
// usable in FDO 2.0 is used. Whether the key exchange suite is valid for the
// Owner key is checked once the Owner key is known (see verifyOwner20).
func selectSuites20(offeredKex []kex.Suite, offeredCiphers []kex.CipherSuiteID, wantKex kex.Suite, wantCipher kex.CipherSuiteID) (kex.Suite, kex.CipherSuiteID, error) {
	usable := func(suite kex.Suite) bool {
		return slices.Contains(kexSuites20, suite) && kex.Available(suite, kex.A128GcmCipher)
	}
	var suite kex.Suite
	if slices.Contains(offeredKex, wantKex) && usable(wantKex) {
		suite = wantKex
	} else if i := slices.IndexFunc(offeredKex, usable); i >= 0 {
		suite = offeredKex[i]
		slog.Info("configured key exchange not offered by owner; using owner's choice", "configured", wantKex, "selected", suite)
	} else {
		return "", 0, fmt.Errorf("TO2.HelloDeviceAck20 offers no usable key exchange suite: %v", offeredKex)
	}

	if slices.Contains(offeredCiphers, wantCipher) && kex.Available(suite, wantCipher) {
		return suite, wantCipher, nil
	}
	i := slices.IndexFunc(offeredCiphers, func(c kex.CipherSuiteID) bool { return kex.Available(suite, c) })
	if i < 0 {
		return "", 0, fmt.Errorf("TO2.HelloDeviceAck20 offers no usable cipher suite: %v", offeredCiphers)
	}
	slog.Info("configured cipher suite not offered by owner; using owner's choice", "configured", wantCipher, "selected", offeredCiphers[i])
	return suite, offeredCiphers[i], nil
}

// sendProveDevice20 sends TO2.ProveDevice20 (82) and receives TO2.ProveOVHdr20 (83)
// This is where the device proves itself FIRST in 2.0
//
//nolint:gocyclo // Protocol implementation with key exchange and validation
func sendProveDevice20(ctx context.Context, transport Transport, ack *HelloDeviceAck20Msg, ackBytes []byte, c *TO2Config) (*OwnerInfo20, kex.Session, error) {
	// NonceTO2ProveOV is generated by the Device and must come back in the
	// Owner's signed ProveOVHdr20, proving that message is fresh.
	var proveOVNonce protocol.Nonce
	if _, err := rand.Read(proveOVNonce[:]); err != nil {
		return nil, nil, fmt.Errorf("error generating NonceTO2ProveOV: %w", err)
	}

	if len(ack.KexSuites) == 0 || len(ack.CipherSuites) == 0 {
		return nil, nil, fmt.Errorf("TO2.HelloDeviceAck20 offers no key exchange or cipher suites")
	}

	// Select key exchange and cipher suites from the Owner's offer
	selectedKex, selectedCipher, err := selectSuites20(ack.KexSuites, ack.CipherSuites, c.KeyExchange, c.CipherSuite)
	if err != nil {
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		return nil, nil, err
	}

	// Initialize key exchange session
	sess := selectedKex.New(nil, selectedCipher)
	xA, err := sess.Parameter(rand.Reader, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating key exchange parameter: %w", err)
	}

	// hashPrev2 = hash[TO2.HelloDeviceAck20] as received, same hash type as hashPrev
	ackHash, err := hashMessage(ack.HashPrev.Algorithm, ackBytes)
	if err != nil {
		clear(xA)
		return nil, nil, err
	}

	// Build ProveDevice20 EAT: nonce claim is NonceTO2ProveDv, FDO claim is the payload
	payload := ProveDevice20Payload{
		KexSuiteName:        selectedKex,
		CipherSuiteName:     selectedCipher,
		XAKeyExchange:       xA,
		NonceTO2ProveOVPrep: proveOVNonce,
		HashPrev2:           ackHash,
	}
	s1 := cose.Sign1[eatoken, []byte]{
		Payload: cbor.NewByteWrap(newProveDevice20EAT(c.Cred.GUID, ack.NonceTO2ProveDVPrep, payload)),
	}
	opts, err := signOptsFor(c.Key, c.PSS)
	if err != nil {
		clear(xA)
		return nil, nil, fmt.Errorf("error determining signing options for ProveDevice20: %w", err)
	}
	if err := s1.Sign(c.Key, nil, cose.AADProveDevice, opts); err != nil {
		clear(xA)
		return nil, nil, fmt.Errorf("error signing ProveDevice20: %w", err)
	}

	// Send ProveDevice20
	typ, resp, err := transport.Send(ctx, protocol.TO2ProveDevice20MsgType, s1.Tag(), nil)
	if err != nil {
		clear(xA)
		return nil, nil, fmt.Errorf("error sending TO2.ProveDevice20: %w", err)
	}
	defer func() { _ = resp.Close() }()

	switch typ {
	case protocol.TO2ProveOVHdr20MsgType:
		captureMsgType(ctx, typ)
		var proveOVHdr cose.Sign1Tag[ProveOVHdr20Payload, []byte]
		if err := cbor.NewDecoder(resp).Decode(&proveOVHdr); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			sess.Destroy()
			return nil, nil, fmt.Errorf("error parsing TO2.ProveOVHdr20: %w", err)
		}
		hdr := proveOVHdr.Payload.Val

		// Owner public key is carried in the signed payload
		ownerPubKey, err := hdr.OwnerPubKey.Public()
		if err != nil {
			sess.Destroy()
			return nil, nil, fmt.Errorf("error parsing owner public key: %w", err)
		}

		// If a delegate chain is present, ProveOVHdr20 is signed by its leaf.
		// The chain itself is validated against the voucher in verifyOwner20.
		signerKey := ownerPubKey
		var delegateChain *protocol.PublicKey
		if hdr.DelegateChain != nil {
			if len(*hdr.DelegateChain) == 0 {
				sess.Destroy()
				return nil, nil, fmt.Errorf("TO2.ProveOVHdr20 has an empty delegate chain")
			}
			chain := make([]*x509.Certificate, len(*hdr.DelegateChain))
			for i, cert := range *hdr.DelegateChain {
				chain[i] = (*x509.Certificate)(cert)
			}
			leafType, err := protocol.KeyTypeFromPublicKey(chain[0].PublicKey)
			if err != nil {
				sess.Destroy()
				return nil, nil, fmt.Errorf("error determining delegate key type: %w", err)
			}
			delegateChain, err = protocol.NewPublicKey(leafType, chain, false)
			if err != nil {
				sess.Destroy()
				return nil, nil, fmt.Errorf("error encoding delegate chain: %w", err)
			}
			signerKey = chain[0].PublicKey
		}

		// Verify owner's (or delegate's) signature
		if ok, err := proveOVHdr.Verify(signerKey, nil, cose.AADProveOVHdr); err != nil {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			sess.Destroy()
			return nil, nil, fmt.Errorf("error verifying owner signature: %w", err)
		} else if !ok {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			sess.Destroy()
			return nil, nil, fmt.Errorf("owner signature verification failed")
		}

		// Verify the Owner echoed the Device's NonceTO2ProveOV (after the signature check)
		if hdr.NonceTO2ProveOV != proveOVNonce {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			sess.Destroy()
			return nil, nil, fmt.Errorf("nonce mismatch in TO2.ProveOVHdr20")
		}

		// Get voucher header directly from Bstr wrapper
		ovh := hdr.OVHeader.Val

		// Complete key exchange with server's parameter
		if err := sess.SetParameter(hdr.XBKeyExchange, nil); err != nil {
			sess.Destroy()
			return nil, nil, fmt.Errorf("error setting peer key exchange parameter: %w", err)
		}

		// Get original owner key from voucher header
		originalOwnerKey, err := ovh.ManufacturerKey.Public()
		if err != nil {
			sess.Destroy()
			return nil, nil, fmt.Errorf("error parsing manufacturer key: %w", err)
		}

		return &OwnerInfo20{
			OVH:               ovh,
			OVHHmac:           hdr.HMac,
			NumVoucherEntries: int(hdr.NumOVEntries),
			OwnerPublicKey:    signerKey,
			OwnerPublicKeyPKI: hdr.OwnerPubKey,
			OriginalOwnerKey:  originalOwnerKey,
			DelegateChain:     delegateChain,
			KexSuite:          selectedKex,
		}, sess, nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return nil, nil, fmt.Errorf("error parsing error message: %w", err)
		}
		sess.Destroy()
		return nil, nil, fmt.Errorf("error from TO2.ProveDevice20: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		sess.Destroy()
		return nil, nil, fmt.Errorf("unexpected response type %d to TO2.ProveDevice20", typ)
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
		Version:            protocol.VersionFromContext(ctx),
	}); err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return err
	}

	// ProveOVHdr20 carried the owner key; it must be the voucher's owner.
	ownerPub, err := info.OwnerPublicKeyPKI.Public()
	if err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return fmt.Errorf("error parsing ProveOVHdr20 owner key: %w", err)
	}
	if eq, ok := ownerPub.(interface{ Equal(crypto.PublicKey) bool }); !ok || !eq.Equal(ownerKeyForValidation) {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return fmt.Errorf("ProveOVHdr20 owner key does not match the ownership voucher")
	}

	// The key exchange chosen before the Owner key was known must be one the
	// spec allows for the device and owner attestation keys
	if !validKex20(info.KexSuite, c.Key.Public(), ownerKeyForValidation) {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return fmt.Errorf("key exchange %s is invalid for the device and owner attestation types", info.KexSuite)
	}

	// A delegate that signed ProveOVHdr20 must chain to the voucher's owner
	// and hold an onboard permission.
	if info.DelegateChain != nil {
		chain, err := info.DelegateChain.Chain()
		if err != nil {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			return fmt.Errorf("error parsing delegate chain: %w", err)
		}
		if err := VerifyDelegateChain(chain, &ownerKeyForValidation, nil); err != nil {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			return fmt.Errorf("delegate chain verification failed: %w", err)
		}
		if !DelegateCanOnboard(chain) {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			return fmt.Errorf("delegate certificate does not have any fdo-ekt-permit-onboard-* permission")
		}
	}

	return nil
}

// sendGetOVNextEntry20 sends TO2.GetOVNextEntry20 (84) and receives TO2.OVNextEntry20 (85)
func sendGetOVNextEntry20(ctx context.Context, transport Transport, entryNum int) (*cose.Sign1Tag[VoucherEntryPayload, []byte], error) {
	if entryNum < 0 || entryNum > 255 {
		return nil, fmt.Errorf("entry number %d out of uint8 range", entryNum)
	}
	req := GetOVNextEntry20Msg{OVEntryNum: uint8(entryNum)} //#nosec G115 -- bounds checked above

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

// sendDeviceSvcInfoRdy20 sends TO2.DeviceSvcInfoRdy20 (86) and receives TO2.SetupDevice20 (87).
// It returns the Device's NonceTO2SetupDv (echoed in DoneAck20) and, for the
// Resale disposition, the replacement credentials.
// Note: the replacement HMAC is sent in Done20 (FDO 2.0 Errata 1), after the
// Device has the new credentials from SetupDevice20.
func sendDeviceSvcInfoRdy20(ctx context.Context, transport Transport, sess kex.Session, ownerInfo *OwnerInfo20, c *TO2Config) (protocol.Nonce, *partialOVH20, uint16, error) {
	var setupDvNonce protocol.Nonce
	if _, err := rand.Read(setupDvNonce[:]); err != nil {
		return protocol.Nonce{}, nil, 0, fmt.Errorf("error generating NonceTO2SetupDv: %w", err)
	}
	req := DeviceSvcInfoRdy20Msg{
		ReplacementHMac:       nil, // Not used (FDO 2.0 Errata 1)
		MaxOwnerServiceInfoSz: &c.MaxServiceInfoSizeReceive,
		NonceTO2SetupDVPrep:   setupDvNonce,
	}

	typ, resp, err := transport.Send(ctx, protocol.TO2DeviceSvcInfoRdy20MsgType, req, sess)
	if err != nil {
		return protocol.Nonce{}, nil, 0, fmt.Errorf("error sending TO2.DeviceSvcInfoRdy20: %w", err)
	}
	defer func() { _ = resp.Close() }()

	switch typ {
	case protocol.TO2SetupDevice20MsgType:
		captureMsgType(ctx, typ)
		var setup cose.Sign1Tag[SetupDevice20Payload, []byte]
		if err := cbor.NewDecoder(resp).Decode(&setup); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return protocol.Nonce{}, nil, 0, fmt.Errorf("error parsing TO2.SetupDevice20: %w", err)
		}
		partial, err := checkSetupDevice20(setup.Untag(), setupDvNonce, ownerInfo.OwnerPublicKey, ownerInfo.DelegateChain, c.AllowCredentialReuse)
		if err != nil {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			return protocol.Nonce{}, nil, 0, err
		}
		mtu := uint16(serviceinfo.DefaultMTU)
		if sz := setup.Payload.Val.MaxDeviceServiceInfoSz; sz != nil {
			mtu = *sz
		}
		return setupDvNonce, partial, mtu, nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return protocol.Nonce{}, nil, 0, fmt.Errorf("error parsing error message: %w", err)
		}
		return protocol.Nonce{}, nil, 0, fmt.Errorf("error from TO2.DeviceSvcInfoRdy20: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		return protocol.Nonce{}, nil, 0, fmt.Errorf("unexpected response type %d to TO2.DeviceSvcInfoRdy20", typ)
	}
}

// checkSetupDevice20 applies the TO2.SetupDevice20 rules (FDO 2.0 Errata 1)
// and returns the replacement credentials for DispResale, or nil.
//
//   - DispResale: MUST be signed by ReplacementCred.Owner2PubKey (proof of
//     possession), and ReplacementCred.NonceTO2SetupDv MUST equal the nonce the
//     Device sent in DeviceSvcInfoRdy20.
//   - DispCredReuse: signed by the ProveOVHdr20 signer (Owner or Delegate).
//     The Device MAY skip verification; this implementation verifies.
//   - DispDisable: not supported by this implementation.
func checkSetupDevice20(setup *cose.Sign1[SetupDevice20Payload, []byte], setupDvNonce protocol.Nonce, proveOVHdrSigner crypto.PublicKey, delegateChain *protocol.PublicKey, allowReuse bool) (*partialOVH20, error) { //nolint:gocyclo
	payload := setup.Payload.Val
	switch payload.DispositionCode {
	case DispResale:
		cred := payload.ReplacementCred
		if cred == nil {
			return nil, fmt.Errorf("TO2.SetupDevice20 DispResale without ReplacementCred")
		}
		owner2Pub, err := cred.Owner2PubKey.Public()
		if err != nil {
			return nil, fmt.Errorf("error parsing TO2.SetupDevice20 Owner2PubKey: %w", err)
		}
		if ok, err := setup.Verify(owner2Pub, nil, cose.AADSetupDevice); err != nil {
			return nil, fmt.Errorf("error verifying TO2.SetupDevice20 signature: %w", err)
		} else if !ok {
			return nil, fmt.Errorf("%w: TO2.SetupDevice20 signature does not verify against Owner2PubKey", ErrCryptoVerifyFailed)
		}
		if cred.NonceTO2SetupDv != setupDvNonce {
			return nil, fmt.Errorf("nonce mismatch in TO2.SetupDevice20")
		}
		return &partialOVH20{
			GUID:            cred.GUID,
			RvInfo:          cred.RvInfo,
			ManufacturerKey: cred.Owner2PubKey,
		}, nil

	case DispCredReuse:
		if payload.ReplacementCred != nil {
			return nil, fmt.Errorf("TO2.SetupDevice20 DispCredReuse must not carry ReplacementCred")
		}
		if ok, err := setup.Verify(proveOVHdrSigner, nil, cose.AADSetupDevice); err != nil {
			return nil, fmt.Errorf("error verifying TO2.SetupDevice20 signature: %w", err)
		} else if !ok {
			return nil, fmt.Errorf("%w: TO2.SetupDevice20 signature does not verify against the ProveOVHdr20 signer", ErrCryptoVerifyFailed)
		}
		if !allowReuse {
			return nil, fmt.Errorf("credential reuse not allowed")
		}
		// A delegate needs fdo-ekt-permit-onboard-reuse-cred for credential reuse
		if delegateChain != nil {
			chain, err := delegateChain.Chain()
			if err != nil {
				return nil, fmt.Errorf("error parsing delegate chain: %w", err)
			}
			if !DelegateCanReuseCred(chain) {
				return nil, fmt.Errorf("delegate certificate does not have fdo-ekt-permit-onboard-reuse-cred permission")
			}
		}
		return nil, nil

	case DispDisable:
		return nil, fmt.Errorf("TO2.SetupDevice20 DispDisable is not supported")

	default:
		return nil, fmt.Errorf("TO2.SetupDevice20 has unknown DispositionCode %d", payload.DispositionCode)
	}
}

// sendDone20 sends TO2.Done20 (90) and receives TO2.DoneAck20 (91)
func sendDone20(ctx context.Context, transport Transport, proveDvNonce, setupDvNonce protocol.Nonce, replacementHMAC *protocol.Hmac, sess kex.Session) error {
	req := Done20Msg{
		NonceTO2ProveDv: proveDvNonce,
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

		// DoneAck20 must echo the Device's NonceTO2SetupDv
		if !bytes.Equal(ack.NonceTO2SetupDv[:], setupDvNonce[:]) {
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

// to2v200Key marks a context as running the FDO 2.0 TO2 protocol, so that the
// service info exchange shared with FDO 1.01 uses the 2.0 messages.
type to2v200Key struct{}

func withTO2v200(ctx context.Context) context.Context {
	return context.WithValue(ctx, to2v200Key{}, true)
}

func isTO2v200(ctx context.Context) bool {
	v, _ := ctx.Value(to2v200Key{}).(bool)
	return v
}

// sendDeviceSvcInfo20 sends TO2.DeviceSvcInfo20 (88) and receives
// TO2.OwnerSvcInfo20 (89). It is the FDO 2.0 form of sendDeviceServiceInfo,
// used by the service info exchange loop shared with FDO 1.01.
func sendDeviceSvcInfo20(ctx context.Context, transport Transport, msg deviceServiceInfo, sess kex.Session) (*ownerServiceInfo, error) {
	req := DeviceSvcInfo20Msg{
		ReplacementHMacOrNull: nil, // Not used (FDO 2.0 Errata 1)
		IsMoreServiceInfo:     msg.IsMoreServiceInfo,
		ServiceInfo:           msg.ServiceInfo,
	}
	typ, resp, err := transport.Send(ctx, protocol.TO2DeviceSvcInfo20MsgType, req, sess)
	if err != nil {
		return nil, fmt.Errorf("TO2.DeviceSvcInfo20: %w", err)
	}
	defer func() { _ = resp.Close() }()

	switch typ {
	case protocol.TO2OwnerSvcInfo20MsgType:
		captureMsgType(ctx, typ)
		var info OwnerSvcInfo20Msg
		if err := cbor.NewDecoder(resp).Decode(&info); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return nil, fmt.Errorf("error parsing TO2.OwnerSvcInfo20 contents: %w", err)
		}
		return &ownerServiceInfo{
			IsMoreServiceInfo: info.IsMoreServiceInfo,
			IsDone:            info.IsDone,
			ServiceInfo:       info.ServiceInfo,
		}, nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return nil, fmt.Errorf("error parsing error message contents of TO2.OwnerSvcInfo20 response: %w", err)
		}
		return nil, fmt.Errorf("error received from TO2.DeviceSvcInfo20 request: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		return nil, fmt.Errorf("unexpected message type for response to TO2.DeviceSvcInfo20: %d", typ)
	}
}
