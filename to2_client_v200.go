// SPDX-FileCopyrightText: (C) 2024 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// TO2v200 runs the FDO 2.0 TO2 protocol. Unlike FDO 1.1, the device
// proves itself first (anti-DoS), then the owner proves ownership.
//
// The flow is:
//
//	HelloDeviceProbe(80) -> HelloDeviceAck20(81)
//	ProveDevice20(82) -> ProveOVHdr20(83)
//	GetOVNextEntry20(84) -> OVNextEntry20(85) [loop for all entries]
//	DeviceSvcInfoRdy20(86) -> SetupDevice20(87)
//	DeviceSvcInfo20(88) -> OwnerSvcInfo20(89) [loop]
//	Done20(90) -> DoneAck20(91)
//
// If the Credential Reuse protocol is allowed and occurs, then the
// returned device credential will be nil.
func TO2v200(ctx context.Context, transport Transport, to1d *cose.Sign1[protocol.To1d, []byte], c TO2Config) (*DeviceCredential, error) {
	ctx = contextWithErrMsg(ctx)
	ctx = protocol.ContextWithVersion(ctx, protocol.Version200)

	// Configure defaults
	applyTO2Defaults(&c)

	// Step 1: Send HelloDeviceProbe(80), receive HelloDeviceAck20(81)
	ack, err := sendHelloDeviceProbe(ctx, transport, &c)
	if err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}

	// Step 2: Device proves first — ProveDevice20(82) -> ProveOVHdr20(83)
	ownerInfo, sess, err := sendProveDevice20(ctx, transport, ack, &c)
	if err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}
	defer sess.Destroy()

	// Step 3: Verify the ownership voucher by fetching all entries
	if err := verifyOwner20(ctx, transport, to1d, ownerInfo, &c); err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}

	// Step 4: DeviceSvcInfoRdy20(86) -> SetupDevice20(87)
	partialOVH, setupNonce, err := sendDeviceSvcInfoRdy20(ctx, transport, sess, &c)
	if err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}

	// Build replacement credential data (nil if credential reuse)
	replacementOVH, replacementHmac, alg, err := buildReplacementCredential20(partialOVH, ownerInfo, &c)
	if err != nil {
		return nil, err
	}

	// Step 5: Exchange service info
	if err := runServiceInfoExchange20(ctx, transport, ownerInfo, setupNonce, replacementHmac, sess, &c); err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}

	// If using credential reuse, return nil
	if replacementOVH == nil {
		return nil, nil
	}

	return buildReplacementDeviceCredential(replacementOVH, alg)
}

// applyTO2Defaults fills in zero-value fields with protocol defaults.
func applyTO2Defaults(c *TO2Config) {
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
}

// buildReplacementCredential20 constructs the replacement voucher header and
// HMAC from the SetupDevice20 response. Returns nils for credential reuse.
func buildReplacementCredential20(partialOVH *partialOVH20, ownerInfo *ownerInfo20, c *TO2Config) (*VoucherHeader, *protocol.Hmac, protocol.HashAlg, error) {
	alg := c.Cred.PublicKeyHash.Algorithm
	if partialOVH == nil {
		return nil, nil, alg, nil
	}

	// In FDO 2.0, SetupDevice20 does not include the owner key
	// (unlike v1.1's Owner2Key). Use the owner key from the
	// already-verified voucher header (ProveOVHdr20).
	ownerKey := ownerInfo.OVH.ManufacturerKey
	nextOwnerPublicKey, err := ownerKey.Public()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("error parsing replacement owner key: %w", err)
	}
	alg, err = hashAlgFor(c.Key.Public(), nextOwnerPublicKey)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("error selecting hash algorithm: %w", err)
	}
	replacementOVH := &VoucherHeader{
		Version:         ownerInfo.OVH.Version,
		GUID:            partialOVH.GUID,
		RvInfo:          partialOVH.RvInfo,
		DeviceInfo:      ownerInfo.OVH.DeviceInfo,
		ManufacturerKey: ownerKey,
		CertChainHash:   ownerInfo.OVH.CertChainHash,
	}

	// Compute replacement HMAC (in FDO 2.0 this is sent with Done20)
	h := hmacHashForAlg(alg, c)
	hmacVal, err := hmacHash(h, replacementOVH)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("error computing HMAC: %w", err)
	}
	return replacementOVH, &hmacVal, alg, nil
}

// hmacHashForAlg returns the HMAC hash.Hash for the given algorithm.
func hmacHashForAlg(alg protocol.HashAlg, c *TO2Config) hash.Hash {
	switch alg {
	case protocol.Sha256Hash, protocol.HmacSha256Hash:
		return c.HmacSha256
	case protocol.Sha384Hash, protocol.HmacSha384Hash:
		return c.HmacSha384
	default:
		panic("only SHA256 and SHA384 are supported in FDO")
	}
}

// runServiceInfoExchange20 performs the FDO 2.0 service info exchange and Done.
func runServiceInfoExchange20(ctx context.Context, transport Transport, ownerInfo *ownerInfo20, setupNonce protocol.Nonce, replacementHmac *protocol.Hmac, sess kex.Session, c *TO2Config) error {
	sendMTU := c.MaxServiceInfoSizeReceive
	serviceInfoReader, serviceInfoWriter := serviceinfo.NewChunkOutPipe(0)
	defer func() { _ = serviceInfoWriter.Close() }()

	go c.Devmod.Write(ctx, c.DeviceModules, sendMTU, serviceInfoWriter)

	return exchangeServiceInfo20(ctx, transport, ownerInfo.ProveOVNonce, setupNonce, replacementHmac, sendMTU, serviceInfoReader, sess, c)
}

// buildReplacementDeviceCredential computes the replacement credential from
// the new voucher header.
func buildReplacementDeviceCredential(ovh *VoucherHeader, alg protocol.HashAlg) (*DeviceCredential, error) {
	replacementKeyDigest := alg.HashFunc().New()
	if err := cbor.NewEncoder(replacementKeyDigest).Encode(ovh.ManufacturerKey); err != nil {
		return nil, fmt.Errorf("error computing hash of replacement owner key: %w", err)
	}
	replacementPublicKeyHash := protocol.Hash{Algorithm: alg, Value: replacementKeyDigest.Sum(nil)[:]}

	return &DeviceCredential{
		Version:       ovh.Version,
		DeviceInfo:    ovh.DeviceInfo,
		GUID:          ovh.GUID,
		RvInfo:        ovh.RvInfo,
		PublicKeyHash: replacementPublicKeyHash,
	}, nil
}

// sendHelloDeviceProbe sends HelloDeviceProbe(80) and receives
// HelloDeviceAck20(81).
func sendHelloDeviceProbe(ctx context.Context, transport Transport, c *TO2Config) (*HelloDeviceAck20Msg, error) {
	// Generate random sugar for hash binding
	sugar := make([]byte, 16)
	if _, err := rand.Read(sugar); err != nil {
		return nil, fmt.Errorf("error generating sugar: %w", err)
	}

	probe := HelloDeviceProbeMsg{
		CapabilityFlags: GlobalCapabilityFlags,
		GUID:            c.Cred.GUID,
		MaxDeviceMsgSz:  65535,
		HashTypes:       []protocol.HashAlg{protocol.Sha256Hash, protocol.Sha384Hash},
		Sugar:           sugar,
	}

	typ, resp, err := transport.Send(ctx, protocol.TO2HelloDeviceProbeMsgType, probe, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Close() }()

	switch typ {
	case protocol.TO2HelloDeviceAck20MsgType:
		captureMsgType(ctx, typ)
		var ack HelloDeviceAck20Msg
		if err := cbor.NewDecoder(resp).Decode(&ack); err != nil {
			return nil, fmt.Errorf("error parsing TO2.HelloDeviceAck20: %w", err)
		}
		return &ack, nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return nil, fmt.Errorf("error parsing error response: %w", err)
		}
		return nil, fmt.Errorf("error from HelloDeviceProbe: %w", errMsg)

	default:
		return nil, fmt.Errorf("unexpected message type %d for HelloDeviceProbe response", typ)
	}
}

// ownerInfo20 holds the parsed owner proof information from ProveOVHdr20.
type ownerInfo20 struct {
	OVH               VoucherHeader
	OVHHmac           protocol.Hmac
	NumVoucherEntries int
	OwnerPublicKey    crypto.PublicKey
	DelegateChain     []*x509.Certificate
	ProveOVNonce      protocol.Nonce
}

// sendProveDevice20 sends ProveDevice20(82) and receives ProveOVHdr20(83).
// The device proves itself first, then parses the owner's proof.
//
//nolint:gocyclo
func sendProveDevice20(ctx context.Context, transport Transport, ack *HelloDeviceAck20Msg, c *TO2Config) (*ownerInfo20, kex.Session, error) {
	// Select key exchange and cipher suite from server's offerings
	selectedKex := c.KeyExchange
	selectedCipher := c.CipherSuite

	// Initialize key exchange session and get device's parameter.
	// In FDO 2.0, the device proves first and the owner's key is not yet
	// known at this point, so nil is passed for the RSA public key. For
	// ECDH-based key exchange (the common case), nil is correct.
	sess := selectedKex.New(nil, selectedCipher)
	xA, err := sess.Parameter(rand.Reader, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating key exchange parameter: %w", err)
	}

	// Hash the HelloDeviceAck20 for binding
	ackData, err := cbor.Marshal(ack)
	if err != nil {
		clear(xA)
		sess.Destroy()
		return nil, nil, fmt.Errorf("error marshaling ack for hashing: %w", err)
	}
	hashAlg := ack.HashPrev.Algorithm
	ackHasher := hashAlg.HashFunc().New()
	_, _ = ackHasher.Write(ackData)
	hashPrev2 := protocol.Hash{
		Algorithm: hashAlg,
		Value:     ackHasher.Sum(nil),
	}

	// Build the ProveDevice20 EAT payload
	// Echo back the server's NonceTO2ProveDVPrep as NonceTO2ProveOVPrep to
	// prove we received the HelloDeviceAck20 message.
	payload := ProveDevice20Payload{
		KexSuiteName:        selectedKex,
		CipherSuiteName:     selectedCipher,
		XAKeyExchange:       xA,
		NonceTO2ProveOVPrep: ack.NonceTO2ProveDVPrep,
		HashPrev2:           hashPrev2,
	}

	// Sign with the device key
	eatPayload, err := cbor.Marshal(payload)
	if err != nil {
		clear(xA)
		sess.Destroy()
		return nil, nil, fmt.Errorf("error marshaling ProveDevice20 payload: %w", err)
	}
	token := cose.Sign1[cbor.RawBytes, []byte]{
		Payload: cbor.NewByteWrap(cbor.RawBytes(eatPayload)),
	}
	opts, err := signOptsFor(c.Key, c.PSS)
	if err != nil {
		clear(xA)
		sess.Destroy()
		return nil, nil, fmt.Errorf("error determining signing options: %w", err)
	}
	if err := token.Sign(c.Key, nil, cose.AADProveDevice, opts); err != nil {
		clear(xA)
		sess.Destroy()
		return nil, nil, fmt.Errorf("error signing ProveDevice20: %w", err)
	}

	// Send ProveDevice20
	typ, resp, err := transport.Send(ctx, protocol.TO2ProveDevice20MsgType, token.Tag(), nil)
	if err != nil {
		clear(xA)
		sess.Destroy()
		return nil, nil, err
	}
	defer func() { _ = resp.Close() }()

	switch typ {
	case protocol.TO2ProveOVHdr20MsgType:
		captureMsgType(ctx, typ)

	case protocol.ErrorMsgType:
		sess.Destroy()
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return nil, nil, fmt.Errorf("error parsing error response: %w", err)
		}
		return nil, nil, fmt.Errorf("error from ProveDevice20: %w", errMsg)

	default:
		sess.Destroy()
		return nil, nil, fmt.Errorf("unexpected message type %d for ProveDevice20 response", typ)
	}

	// Parse ProveOVHdr20 response
	var proveOVHdr cose.Sign1Tag[ProveOVHdr20Payload, []byte]
	if err := cbor.NewDecoder(resp).Decode(&proveOVHdr); err != nil {
		sess.Destroy()
		return nil, nil, fmt.Errorf("error parsing ProveOVHdr20: %w", err)
	}

	// Parse owner public key from unprotected headers
	var ownerPubKey protocol.PublicKey
	if found, err := proveOVHdr.Unprotected.Parse(to2OwnerPubKeyClaim, &ownerPubKey); !found {
		sess.Destroy()
		return nil, nil, fmt.Errorf("missing owner pubkey in ProveOVHdr20 unprotected headers")
	} else if err != nil {
		sess.Destroy()
		return nil, nil, fmt.Errorf("error parsing owner pubkey: %w", err)
	}
	ownerKey, err := ownerPubKey.Public()
	if err != nil {
		sess.Destroy()
		return nil, nil, fmt.Errorf("error parsing owner public key: %w", err)
	}

	// Parse optional delegate chain
	var delegateChain []*x509.Certificate
	var sigVerifyKey crypto.PublicKey
	var delegateChainRaw [][]byte
	if found, err := proveOVHdr.Unprotected.Parse(to2DelegateChainClaim, &delegateChainRaw); err != nil {
		sess.Destroy()
		return nil, nil, fmt.Errorf("error parsing delegate chain: %w", err)
	} else if found && len(delegateChainRaw) > 0 {
		for i, der := range delegateChainRaw {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				sess.Destroy()
				return nil, nil, fmt.Errorf("error parsing delegate cert %d: %w", i, err)
			}
			delegateChain = append(delegateChain, cert)
		}
		sigVerifyKey = delegateChain[0].PublicKey
	} else {
		sigVerifyKey = ownerKey
	}

	// Verify ProveOVHdr20 signature with AAD domain separation
	if ok, err := proveOVHdr.Verify(sigVerifyKey, nil, cose.AADProveOVHdr); err != nil {
		sess.Destroy()
		return nil, nil, fmt.Errorf("error verifying ProveOVHdr20 signature: %w", err)
	} else if !ok {
		sess.Destroy()
		return nil, nil, fmt.Errorf("%w: ProveOVHdr20 signature verification failed", ErrCryptoVerifyFailed)
	}

	// Parse nonce
	var proveOVNonce protocol.Nonce
	if found, err := proveOVHdr.Unprotected.Parse(to2NonceClaim, &proveOVNonce); !found {
		sess.Destroy()
		return nil, nil, fmt.Errorf("missing nonce in ProveOVHdr20 unprotected headers")
	} else if err != nil {
		sess.Destroy()
		return nil, nil, fmt.Errorf("error parsing ProveOVHdr20 nonce: %w", err)
	}

	// Complete key exchange with the server's parameter.
	// SetParameter requires *rsa.PrivateKey for RSA key exchange, but
	// the client does not have the owner's private key. For ECDH-based
	// key exchange (which is the common case), nil is correct.
	if err := sess.SetParameter(proveOVHdr.Payload.Val.XBKeyExchange, nil); err != nil {
		sess.Destroy()
		return nil, nil, fmt.Errorf("error completing key exchange: %w", err)
	}

	return &ownerInfo20{
		OVH:               proveOVHdr.Payload.Val.OVH.Val,
		OVHHmac:           proveOVHdr.Payload.Val.OVHHmac,
		NumVoucherEntries: int(proveOVHdr.Payload.Val.NumOVEntries),
		OwnerPublicKey:    ownerKey,
		DelegateChain:     delegateChain,
		ProveOVNonce:      proveOVNonce,
	}, sess, nil
}

// verifyOwner20 fetches and verifies the ownership voucher in FDO 2.0.
func verifyOwner20(ctx context.Context, transport Transport, to1d *cose.Sign1[protocol.To1d, []byte], info *ownerInfo20, c *TO2Config) error {
	// Fetch all voucher entries
	var entries []cose.Sign1Tag[VoucherEntryPayload, []byte]
	for i := range info.NumVoucherEntries {
		entry, err := sendGetOVNextEntry20(ctx, transport, i)
		if err != nil {
			return err
		}
		entries = append(entries, *entry)
	}

	ov := Voucher{
		Header:  *cbor.NewBstr(info.OVH),
		Hmac:    info.OVHHmac,
		Entries: entries,
	}

	// Verify voucher integrity (header, manufacturer key, entries)
	if err := verifyVoucherIntegrity20(ctx, &ov, c); err != nil {
		return err
	}

	// Verify owner key matches voucher chain
	expectedOwnerPub, err := verifyOwnerKey20(ctx, &ov, info.OwnerPublicKey)
	if err != nil {
		return err
	}

	// Verify delegate chain if present
	if len(info.DelegateChain) > 0 {
		if err := verifyDelegateChain20(ctx, info.DelegateChain, expectedOwnerPub); err != nil {
			return err
		}
	}

	// Verify to1d blob
	return verifyTo1dBlob20(ctx, to1d, expectedOwnerPub)
}

// verifyVoucherIntegrity20 verifies the voucher header, manufacturer key,
// and entry signatures.
func verifyVoucherIntegrity20(ctx context.Context, ov *Voucher, c *TO2Config) error {
	if err := ov.VerifyHeader(c.HmacSha256, c.HmacSha384); err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return fmt.Errorf("bad ownership voucher header: %w", err)
	}
	if err := ov.VerifyManufacturerKey(c.Cred.PublicKeyHash); err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return fmt.Errorf("bad manufacturer key: %w", err)
	}
	if err := ov.VerifyEntries(); err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return fmt.Errorf("bad voucher entries: %w", err)
	}
	return nil
}

// verifyOwnerKey20 verifies the owner key matches the voucher chain and
// returns the expected owner public key.
func verifyOwnerKey20(ctx context.Context, ov *Voucher, ownerPublicKey crypto.PublicKey) (crypto.PublicKey, error) {
	ownerPub := ov.Header.Val.ManufacturerKey
	if len(ov.Entries) > 0 {
		ownerPub = ov.Entries[len(ov.Entries)-1].Payload.Val.PublicKey
	}
	expectedOwnerPub, err := ownerPub.Public()
	if err != nil {
		return nil, fmt.Errorf("error parsing last public key of voucher: %w", err)
	}
	eq, ok := ownerPublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("owner public key type %T does not support equality check", ownerPublicKey)
	}
	if !eq.Equal(expectedOwnerPub) {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("owner public key did not match voucher")
	}
	return expectedOwnerPub, nil
}

// verifyDelegateChain20 verifies a delegate chain against the expected owner
// public key and checks onboarding permission.
func verifyDelegateChain20(ctx context.Context, chain []*x509.Certificate, expectedOwnerPub crypto.PublicKey) error {
	if err := VerifyDelegateChain(chain, &expectedOwnerPub, nil); err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return fmt.Errorf("delegate chain verification failed: %w", err)
	}
	if !DelegateCanOnboard(chain) {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return fmt.Errorf("delegate does not have onboarding permission")
	}
	slog.Info("delegate chain verified (v2.0)",
		"summary", DelegateChainSummary(chain),
	)
	return nil
}

// verifyTo1dBlob20 verifies the to1d blob signature if present.
func verifyTo1dBlob20(ctx context.Context, to1d *cose.Sign1[protocol.To1d, []byte], expectedOwnerPub crypto.PublicKey) error {
	if to1d == nil {
		return nil
	}
	ok, err := to1d.Verify(expectedOwnerPub, nil, nil)
	if err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return fmt.Errorf("error verifying to1d signature: %w", err)
	}
	if !ok {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return fmt.Errorf("%w: to1d signature verification failed", ErrCryptoVerifyFailed)
	}
	return nil
}

// sendGetOVNextEntry20 sends GetOVNextEntry20(84) and receives
// OVNextEntry20(85).
func sendGetOVNextEntry20(ctx context.Context, transport Transport, i int) (*cose.Sign1Tag[VoucherEntryPayload, []byte], error) {
	msg := GetOVNextEntry20Msg{OVEntryNum: i}

	typ, resp, err := transport.Send(ctx, protocol.TO2GetOVNextEntry20MsgType, msg, nil)
	if err != nil {
		return nil, fmt.Errorf("TO2.GetOVNextEntry20: %w", err)
	}
	defer func() { _ = resp.Close() }()

	switch typ {
	case protocol.TO2OVNextEntry20MsgType:
		captureMsgType(ctx, typ)
		var entry OVNextEntry20Msg
		if err := cbor.NewDecoder(resp).Decode(&entry); err != nil {
			return nil, fmt.Errorf("error parsing OVNextEntry20: %w", err)
		}
		if entry.OVEntryNum != i {
			return nil, fmt.Errorf("OVNextEntry20 contained entry %d, requested %d", entry.OVEntryNum, i)
		}
		return &entry.OVEntry, nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return nil, fmt.Errorf("error parsing error response: %w", err)
		}
		return nil, fmt.Errorf("error from GetOVNextEntry20: %w", errMsg)

	default:
		return nil, fmt.Errorf("unexpected message type %d for GetOVNextEntry20 response", typ)
	}
}

// partialOVH20 holds partial replacement voucher header info from
// SetupDevice20.
type partialOVH20 struct {
	GUID            protocol.GUID
	RvInfo          [][]protocol.RvInstruction
	ManufacturerKey protocol.PublicKey
}

// sendDeviceSvcInfoRdy20 sends DeviceSvcInfoRdy20(86) and receives
// SetupDevice20(87).
func sendDeviceSvcInfoRdy20(ctx context.Context, transport Transport, sess kex.Session, c *TO2Config) (*partialOVH20, protocol.Nonce, error) {
	msg := DeviceSvcInfoRdy20Msg{
		MaxOwnerSvcInfoSz: &c.MaxServiceInfoSizeReceive,
	}

	typ, resp, err := transport.Send(ctx, protocol.TO2DeviceSvcInfoRdy20MsgType, msg, sess)
	if err != nil {
		return nil, protocol.Nonce{}, fmt.Errorf("TO2.DeviceSvcInfoRdy20: %w", err)
	}
	defer func() { _ = resp.Close() }()

	switch typ {
	case protocol.TO2SetupDevice20MsgType:
		captureMsgType(ctx, typ)
		var setup SetupDevice20Msg
		if err := cbor.NewDecoder(resp).Decode(&setup); err != nil {
			return nil, protocol.Nonce{}, fmt.Errorf("error parsing SetupDevice20: %w", err)
		}

		// Credential reuse: no replacement GUID/RvInfo
		if setup.ReplacementGUID == nil {
			if !c.AllowCredentialReuse {
				captureErr(ctx, protocol.CredReuseErrCode, "")
				return nil, protocol.Nonce{}, fmt.Errorf("credential reuse not enabled")
			}
			return nil, setup.NonceTO2SetupDV, nil
		}

		// Get owner public key for the partial voucher header
		// We need to know the new owner key for the replacement credential.
		// In v2.0, the owner key comes from the voucher we already verified.
		// For now, we construct the partial OVH with the current credential's
		// key info since the actual owner key was verified in verifyOwner20.
		partial := &partialOVH20{
			GUID:   *setup.ReplacementGUID,
			RvInfo: *setup.ReplacementRvInfo,
		}

		return partial, setup.NonceTO2SetupDV, nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return nil, protocol.Nonce{}, fmt.Errorf("error parsing error response: %w", err)
		}
		return nil, protocol.Nonce{}, fmt.Errorf("error from DeviceSvcInfoRdy20: %w", errMsg)

	default:
		return nil, protocol.Nonce{}, fmt.Errorf("unexpected message type %d for DeviceSvcInfoRdy20 response", typ)
	}
}

// exchangeServiceInfo20 exchanges service info using FDO 2.0 message
// types (88/89), then sends Done20(90) and receives DoneAck20(91).
//
// This mirrors the v1.1 exchangeServiceInfo flow but uses v2.0 message
// types. Owner service info is processed through device modules
// (FSIMs), and device module responses are sent back to the owner.
func exchangeServiceInfo20(ctx context.Context,
	transport Transport,
	proveOVNonce, setupDvNonce protocol.Nonce,
	replacementHmac *protocol.Hmac,
	mtu uint16,
	initInfo *serviceinfo.ChunkReader,
	sess kex.Session,
	c *TO2Config,
) error {
	// Shadow context to ensure that any goroutines still running after this
	// function exits will shutdown
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Subtract 5 bytes for CBOR array overhead (same as v1.1)
	mtu -= 5

	// 1000 service info buffered in and out means up to ~1MB of data for
	// the default MTU. If both queues fill, the device will deadlock. This
	// should only happen for a poorly behaved owner service.
	ownerInfo, ownerInfoIn := serviceinfo.NewChunkInPipe(1000)

	// Send initial device info (devmod)
	totalRounds, done, err := exchangeServiceInfoRound20(ctx, transport, mtu, initInfo, ownerInfoIn, sess)
	_ = initInfo.Close()
	if err != nil {
		return fmt.Errorf("error sending devmod (v2.0): %w", err)
	}
	if err := ownerInfoIn.Close(); err != nil {
		return fmt.Errorf("error closing owner service info -> device module pipe: %w", err)
	}
	if totalRounds >= 1_000_000 {
		return fmt.Errorf("exceeded 1e6 rounds of service info exchange")
	}
	if done {
		return sendDone20(ctx, transport, setupDvNonce, proveOVNonce, replacementHmac, sess)
	}

	// Track active modules
	modules := deviceModuleMap{modules: c.DeviceModules, active: make(map[string]bool)}
	defer stopDevicePlugins(&modules)

	var prevModuleName string
	for {
		// Handle received owner service info and produce zero or more service
		// info to send. Each service info grouping is automatically chunked
		// and if it exceeds the MTU will have IsMoreServiceInfo=true.
		deviceInfo, deviceInfoIn := serviceinfo.NewChunkOutPipe(1000)
		ctxWithMTU := context.WithValue(ctx, serviceinfo.MTUKey{}, mtu)
		// Track the owner module in use so that if the next round has no data
		// exchanged, we can still yield to the appropriate device module.
		moduleName := make(chan string)
		go func() {
			select {
			case <-ctx.Done():
			case moduleName <- handleOwnerModuleMessages(ctxWithMTU, prevModuleName, modules, ownerInfo, deviceInfoIn):
			}
		}()

		// Send all device service info and receive all owner service info into
		// a buffered pipe. Note that if >1000 service info are received from
		// the owner service without it allowing the device to respond, the
		// device will deadlock.
		nextOwnerInfo, ownerInfoIn := serviceinfo.NewChunkInPipe(1000)
		rounds, done, err := exchangeServiceInfoRound20(ctx, transport, mtu, deviceInfo, ownerInfoIn, sess)
		if err != nil {
			_ = ownerInfoIn.CloseWithError(err)
			return err
		}
		if err := ownerInfoIn.Close(); err != nil {
			return fmt.Errorf("error closing owner service info -> device module pipe: %w", err)
		}

		// Limit to 1e6 (1 million) rounds and fail TO2 if exceeded
		totalRounds += rounds
		if totalRounds >= 1_000_000 {
			return fmt.Errorf("exceeded 1e6 rounds of service info exchange")
		}
		if done {
			// Process final service info from message with IsDone
			deviceInfo, discard := serviceinfo.NewChunkOutPipe(1000)
			go discardDeviceInfo(deviceInfo)
			ctxWithMTU := context.WithValue(ctx, serviceinfo.MTUKey{}, mtu)
			_ = handleOwnerModuleMessages(ctxWithMTU, prevModuleName, modules, nextOwnerInfo, discard)

			// Continue TO2
			return sendDone20(ctx, transport, setupDvNonce, proveOVNonce, replacementHmac, sess)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case prevModuleName = <-moduleName:
			ownerInfo = nextOwnerInfo
		}
	}
}

// Perform one iteration of send all device service info (may be across
// multiple FDO messages) and receive all owner service info (same applies)
// using FDO 2.0 message types.
func exchangeServiceInfoRound20(ctx context.Context, transport Transport, mtu uint16,
	r *serviceinfo.ChunkReader, w *serviceinfo.ChunkWriter, sess kex.Session,
) (int, bool, error) {
	// Create DeviceSvcInfo20 request structure
	var msg DeviceSvcInfo20Msg
	maxRead := mtu
	for {
		chunk, err := r.ReadChunk(maxRead)
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, serviceinfo.ErrSizeTooSmall) {
			msg.IsMoreServiceInfo = true
			if maxRead == mtu {
				msg.IsMoreServiceInfo = false // likely due to a yield
			}
			break
		}
		if err != nil {
			return 0, false, fmt.Errorf("error reading KV to send to owner: %w", err)
		}
		maxRead -= chunk.Size()
		msg.ServiceInfo = append(msg.ServiceInfo, chunk)
	}

	// Send request
	ownerSvcInfo, err := sendDeviceServiceInfo20(ctx, transport, msg, sess)
	if err != nil {
		return 0, false, err
	}

	// Receive all owner service info
	for _, kv := range ownerSvcInfo.ServiceInfo {
		if err := w.WriteChunk(kv); err != nil {
			return 0, false, fmt.Errorf("error piping owner service info to device module: %w", err)
		}
	}

	// Recurse when there's more service info to send from device or receive
	// from owner without allowing the other side to respond
	if msg.IsMoreServiceInfo || ownerSvcInfo.IsMoreServiceInfo {
		rounds, done, err := exchangeServiceInfoRound20(ctx, transport, mtu, r, w, sess)
		return rounds + 1, done, err
	}

	return 1, ownerSvcInfo.IsDone, nil
}

// DeviceSvcInfo20(88) -> OwnerSvcInfo20(89)
func sendDeviceServiceInfo20(ctx context.Context, transport Transport, msg DeviceSvcInfo20Msg, sess kex.Session) (*OwnerSvcInfo20Msg, error) {
	// Make request
	typ, resp, err := transport.Send(ctx, protocol.TO2DeviceSvcInfo20MsgType, msg, sess)
	if err != nil {
		return nil, fmt.Errorf("TO2.DeviceSvcInfo20: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case protocol.TO2OwnerSvcInfo20MsgType:
		captureMsgType(ctx, typ)
		var ownerSvcInfo OwnerSvcInfo20Msg
		if err := cbor.NewDecoder(resp).Decode(&ownerSvcInfo); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return nil, fmt.Errorf("error parsing TO2.OwnerSvcInfo20 contents: %w", err)
		}
		return &ownerSvcInfo, nil

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

// sendDone20 sends Done20(90) and receives DoneAck20(91).
func sendDone20(ctx context.Context, transport Transport, setupDvNonce, proveOVNonce protocol.Nonce, replacementHmac *protocol.Hmac, sess kex.Session) error {
	msg := Done20Msg{
		NonceTO2SetupDV: setupDvNonce,
		ReplacementHmac: replacementHmac,
	}

	typ, resp, err := transport.Send(ctx, protocol.TO2Done20MsgType, msg, sess)
	if err != nil {
		return fmt.Errorf("TO2.Done20: %w", err)
	}
	defer func() { _ = resp.Close() }()

	switch typ {
	case protocol.TO2DoneAck20MsgType:
		captureMsgType(ctx, typ)
		var ack DoneAck20Msg
		if err := cbor.NewDecoder(resp).Decode(&ack); err != nil {
			return fmt.Errorf("error parsing DoneAck20: %w", err)
		}
		if ack.NonceTO2ProveOV != proveOVNonce {
			return fmt.Errorf("nonce mismatch in DoneAck20")
		}
		return nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return fmt.Errorf("error parsing error response: %w", err)
		}
		return fmt.Errorf("error from Done20: %w", errMsg)

	default:
		return fmt.Errorf("unexpected message type %d for Done20 response", typ)
	}
}
