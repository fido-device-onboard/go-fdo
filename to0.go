// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// DefaultRVBlobTTL is the default requested TTL for a rendezvous blob
// mapping.
const DefaultRVBlobTTL = 4_294_967_295 // max uint32

// TO0Client is used by owner services communicating with rendezvous services.
// Unlike [DOClient], it is not used by devices.
type TO0Client struct {
	// Vouchers is used to lookup the ownership voucher for registering a
	// rendezvous blob for a given device.
	Vouchers VoucherPersistentState

	// OwnerKeys are used for signing the rendezvous blob.
	OwnerKeys OwnerKeyPersistentState

	// DelegateKeys may be used for signing the rendezvous blob.
	DelegateKeys DelegateKeyPersistentState

	// TTL is the amount of time to recommend that the Rendezvous Server allows
	// the rendezvous blob mapping to remain active.
	//
	// If TTL is 0, [DefaultRVBlobTTL] will be used.
	TTL uint32

	// Version specifies the FDO protocol version to use.
	// Defaults to Version101 if not set.
	Version protocol.Version
}

// RegisterBlob tells a Rendezvous Server where to direct a given device to its
// owner service for onboarding. The returned uint32 is the number of seconds
// before the rendezvous blob must be refreshed by calling [RegisterBlob] again.
// The rendezvous blob is signed by the Owner key.
func (c *TO0Client) RegisterBlob(ctx context.Context, transport Transport, guid protocol.GUID, addrs []protocol.RvTO2Addr) (uint32, error) {
	return c.RegisterBlobWithDelegate(ctx, transport, guid, addrs, "")
}

// RegisterBlobWithDelegate is like [TO0Client.RegisterBlob], but signs the
// rendezvous blob with the named delegate from DelegateKeys (a "=" in the name
// is replaced by the Owner key type). The delegate chain must carry the
// fdo-ekt-permit-redirect permission. An empty delegateName signs with the
// Owner key.
func (c *TO0Client) RegisterBlobWithDelegate(ctx context.Context, transport Transport, guid protocol.GUID, addrs []protocol.RvTO2Addr, delegateName string) (uint32, error) {
	ctx = contextWithErrMsg(ctx)
	if c.Version != 0 {
		ctx = protocol.ContextWithVersion(ctx, c.Version)
	}

	nonce, err := c.hello(ctx, transport)
	if err != nil {
		return 0, err
	}

	ttl := c.TTL
	if ttl == 0 {
		ttl = DefaultRVBlobTTL
	}

	return c.ownerSign(ctx, transport, guid, ttl, nonce, addrs, delegateName)
}

// Hello(20) -> HelloAck(21)
func (c *TO0Client) hello(ctx context.Context, transport Transport) (protocol.Nonce, error) {
	// Define request structure
	msg := GlobalCapabilityFlags

	// Make request
	typ, resp, err := transport.Send(ctx, protocol.TO0HelloMsgType, msg, nil)
	if err != nil {
		return protocol.Nonce{}, fmt.Errorf("TO0.Hello: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case protocol.TO0HelloAckMsgType:
		captureMsgType(ctx, typ)
		if protocol.VersionFromContext(ctx) == protocol.Version200 {
			var ack to0Ack20
			if err := cbor.NewDecoder(resp).Decode(&ack); err != nil {
				captureErr(ctx, protocol.MessageBodyErrCode, "")
				return protocol.Nonce{}, fmt.Errorf("error parsing TO0.HelloAck contents: %w", err)
			}
			return ack.NonceTO0Sign, nil
		}
		var ack to0Ack
		if err := cbor.NewDecoder(resp).Decode(&ack); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return protocol.Nonce{}, fmt.Errorf("error parsing TO0.HelloAck contents: %w", err)
		}
		return ack.NonceTO0Sign, nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return protocol.Nonce{}, fmt.Errorf("error parsing error message contents of TO0.Hello response: %w", err)
		}
		return protocol.Nonce{}, fmt.Errorf("error received from TO0.Hello request: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		return protocol.Nonce{}, fmt.Errorf("unexpected message type for response to TO0.Hello: %d", typ)
	}
}

type to0Ack struct {
	NonceTO0Sign protocol.Nonce
}

type to0Ack20 struct {
	CapabilityFlags
	NonceTO0Sign protocol.Nonce
}

// Hello(20) -> HelloAck(21)
func (s *TO0Server) helloAck(ctx context.Context, msg io.Reader) (any, error) {
	var hello CapabilityFlags
	if err := cbor.NewDecoder(msg).Decode(&hello); err != nil {
		return nil, fmt.Errorf("error decoding TO0.Hello request: %w", err)
	}

	// Generate and store nonce
	var nonce protocol.Nonce
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("error generating nonce for TO0 sign: %w", err)
	}
	if err := s.Session.SetTO0SignNonce(ctx, nonce); err != nil {
		return nil, fmt.Errorf("error storing nonce for TO0.OwnerSign: %w", err)
	}

	if protocol.VersionFromContext(ctx) == protocol.Version200 {
		return &to0Ack20{
			CapabilityFlags: GlobalCapabilityFlags,
			NonceTO0Sign:    nonce,
		}, nil
	}
	return &to0Ack{
		NonceTO0Sign: nonce,
	}, nil
}

type to0d struct {
	Voucher      Voucher
	WaitSeconds  uint32
	NonceTO0Sign protocol.Nonce
}

type ownerSign struct {
	To0d cbor.Bstr[to0d]
	To1d cose.Sign1Tag[protocol.To1d, []byte]
}

// ownerSign20 is TO0.OwnerSign for FDO 2.0. The delegate chain, if any, is
// inside the signed to1d payload.
type ownerSign20 struct {
	CapabilityFlags
	To0d cbor.Bstr[to0d]
	To1d cose.Sign1Tag[protocol.To1d, []byte]
}

// OwnerSign(22) -> AcceptOwner(23)
//
//nolint:gocyclo // Protocol implementation with multiple key type handling
func (c *TO0Client) ownerSign(ctx context.Context, transport Transport, guid protocol.GUID, ttl uint32, nonce protocol.Nonce, addrs []protocol.RvTO2Addr, delegateName string) (negotiatedTTL uint32, _ error) {
	// Create and hash to0d
	ov, err := c.Vouchers.Voucher(ctx, guid)
	if err != nil {
		return 0, fmt.Errorf("error looking up ownership voucher: %w", err)
	}
	if len(ov.Entries) == 0 {
		return 0, fmt.Errorf("ownership voucher has zero extensions")
	}
	to0d := to0d{
		Voucher:      *ov,
		WaitSeconds:  ttl,
		NonceTO0Sign: nonce,
	}
	alg := ov.Entries[0].Payload.Val.PreviousHash.Algorithm
	to0dHash := alg.HashFunc().New()
	if err := cbor.NewEncoder(to0dHash).Encode(to0d); err != nil {
		return 0, fmt.Errorf("error hashing to0d structure: %w", err)
	}

	// Sign to1d rendezvous blob
	mfgKey := ov.Header.Val.ManufacturerKey
	keyType := mfgKey.Type
	ownerKey, _, err := c.OwnerKeys.OwnerKey(ctx, keyType, mfgKey.RsaBits())
	if errors.Is(err, ErrNotFound) {
		return 0, fmt.Errorf("no available owner key for TO0.OwnerSign [type=%s]", keyType)
	} else if err != nil {
		return 0, fmt.Errorf("error getting owner key [type=%s]: %w", keyType, err)
	}
	opts, err := signOptsFor(ownerKey, keyType == protocol.RsaPssKeyType)
	if err != nil {
		return 0, fmt.Errorf("error determining signing options for TO0.OwnerSign: %w", err)
	}

	var header = cose.Header{
		Unprotected: map[cose.Label]any{},
	}

	v20 := protocol.VersionFromContext(ctx) == protocol.Version200
	payload := protocol.To1d{
		RV: addrs,
		To0dHash: protocol.Hash{
			Algorithm: alg,
			Value:     to0dHash.Sum(nil),
		},
	}
	if v20 {
		// FDO 2.0: DelegateChain is part of the signed payload (null for Owner)
		payload.DelegateChain = cbor.NewBstr[*[]*cbor.X509Certificate](nil)
	}
	to1d := cose.Sign1[protocol.To1d, []byte]{
		Header:  header,
		Payload: cbor.NewByteWrap(payload),
	}

	// Sign blob with OwnerKey - or Delegate, if requested
	if delegateName != "" {
		// Delegate must be X509 or X5CHAIN so it can prove that Owner signed it
		delegateName = strings.ReplaceAll(delegateName, "=", keyType.KeyString())
		delegateKey, ch, err := c.DelegateKeys.DelegateKey(delegateName)
		if err != nil {
			return 0, fmt.Errorf("error getting delegate key [type=%s]: %w", keyType, err)
		}
		// Get key type from the delegate certificate's public key (leaf cert)
		delegateKeyType, err := protocol.KeyTypeFromPublicKey(ch[0].PublicKey)
		if err != nil {
			return 0, fmt.Errorf("error determining delegate key type: %w", err)
		}
		delegateOpts, err := signOptsFor(delegateKey, delegateKeyType == protocol.RsaPssKeyType)
		if err != nil {
			return 0, fmt.Errorf("error determining signing options for TO0 Delegate: %w", err)
		}
		chain, err := protocol.NewPublicKey(delegateKeyType, ch, false)
		if err != nil {
			return 0, fmt.Errorf("error creating delegate public key: %w", err)
		}
		if v20 {
			certs := make([]*cbor.X509Certificate, len(ch))
			for i, cert := range ch {
				certs[i] = (*cbor.X509Certificate)(cert)
			}
			payload.DelegateChain = cbor.NewBstr(&certs)
			to1d.Payload = cbor.NewByteWrap(payload)
		} else {
			to1d.Unprotected[to2DelegateClaim] = chain
		}

		// FDO 2.0 uses domain-specific AAD; FDO 1.01 uses empty AAD
		var aad []byte
		if ov.Version >= uint16(protocol.Version200) {
			aad = cose.AADOwnerSign
		}
		if err := to1d.Sign(delegateKey, nil, aad, delegateOpts); err != nil {
			return 0, fmt.Errorf("error signing To1d payload for w/ Delegate TO0.OwnerSign: %w", err)
		}

		// This will fail if the device has been DI'd with a key of one type,
		// but the Delegate chain was rooted by a different key of a different type
		p, err := chain.Public()
		if err != nil {
			return 0, fmt.Errorf("Error getting public key from delegate chain: %v", err)
		}
		ok, err := to1d.Verify(p, nil, aad)
		if err != nil {
			return 0, fmt.Errorf("To1d verify failed: %w", err)
		}
		if !ok {
			return 0, fmt.Errorf("To1d verify failed")
		}
	} else {
		// FDO 2.0 uses domain-specific AAD; FDO 1.01 uses empty AAD
		var aad []byte
		if ov.Version >= uint16(protocol.Version200) {
			aad = cose.AADOwnerSign
		}
		if err := to1d.Sign(ownerKey, nil, aad, opts); err != nil {
			return 0, fmt.Errorf("error signing To1d payload for TO0.OwnerSign: %w", err)
		}
	}
	// Define request structure
	var msg any = ownerSign{
		To0d: *cbor.NewBstr(to0d),
		To1d: *to1d.Tag(),
	}
	if v20 {
		msg = ownerSign20{
			CapabilityFlags: GlobalCapabilityFlags,
			To0d:            *cbor.NewBstr(to0d),
			To1d:            *to1d.Tag(),
		}
	}

	// Make request
	typ, resp, err := transport.Send(ctx, protocol.TO0OwnerSignMsgType, msg, nil)
	if err != nil {
		return 0, fmt.Errorf("TO0.OwnerSign: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case protocol.TO0AcceptOwnerMsgType:
		captureMsgType(ctx, typ)
		var accept to0AcceptOwner
		if err := cbor.NewDecoder(resp).Decode(&accept); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return 0, fmt.Errorf("error parsing TO0.AcceptOwner contents: %w", err)
		}
		return accept.WaitSeconds, nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return 0, fmt.Errorf("error parsing error message contents of TO0.OwnerSign response: %w", err)
		}
		return 0, fmt.Errorf("error received from TO0.OwnerSign request: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		return 0, fmt.Errorf("unexpected message type for response to TO0.OwnerSign: %d", typ)
	}
}

type to0AcceptOwner struct {
	WaitSeconds uint32
}

// OwnerSign(22) -> AcceptOwner(23)
func (s *TO0Server) acceptOwner(ctx context.Context, msg io.Reader) (*to0AcceptOwner, error) { //nolint:gocyclo
	var sig ownerSign
	if protocol.VersionFromContext(ctx) == protocol.Version200 {
		var sig20 ownerSign20
		if err := cbor.NewDecoder(msg).Decode(&sig20); err != nil {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			return nil, fmt.Errorf("error decoding TO0.OwnerSign request: %w", err)
		}
		sig = ownerSign{To0d: sig20.To0d, To1d: sig20.To1d}
	} else if err := cbor.NewDecoder(msg).Decode(&sig); err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("error decoding TO0.OwnerSign request: %w", err)
	}

	// Verify to0d hash matches to0d
	to0dHash := sig.To1d.Payload.Val.To0dHash.Algorithm.HashFunc().New()
	if err := cbor.NewEncoder(to0dHash).Encode(sig.To0d.Val); err != nil {
		return nil, fmt.Errorf("error hashing to0d structure: %w", err)
	}
	if !bytes.Equal(to0dHash.Sum(nil), sig.To1d.Payload.Val.To0dHash.Value) {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("to0d did not match hash in to1d")
	}

	// Verify ownership voucher is valid
	ov := sig.To0d.Val.Voucher
	if len(ov.Entries) == 0 {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("voucher has not been extended")
	}
	if err := ov.VerifyEntries(); err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("voucher is not valid: %w", err)
	}

	// Check owner sign nonce in to0d
	signNonce, err := s.Session.TO0SignNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting TO0 owner sign nonce: %w", err)
	}
	nonce := sig.To0d.Val.NonceTO0Sign
	if !bytes.Equal(nonce[:], signNonce[:]) {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("TO0 owner sign nonces not match")
	}

	// Delegate chain that signed the to1d, if any (signed payload in FDO 2.0,
	// unprotected header in FDO 1.1)
	delegateChain, err := to1dDelegateChain(sig.To1d.Untag())
	if err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, err
	}

	// Optionally verify the to1d signature, as the Device will in TO2
	if s.VerifyTo1d {
		ownerPub, err := ov.OwnerPublicKey()
		if err != nil {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			return nil, fmt.Errorf("error getting voucher owner public key: %w", err)
		}
		if err := verifyTo1d(sig.To1d.Untag(), ownerPub, ov.Header.Val.Version); err != nil {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			return nil, fmt.Errorf("rendezvous blob rejected: %w", err)
		}
	}

	// Use optional callback to decide whether to accept voucher and how long
	// the rendezvous blob should be valid.
	// AcceptVoucherWithInfo takes precedence over AcceptVoucher.
	ttl := sig.To0d.Val.WaitSeconds
	if s.AcceptVoucherWithInfo != nil {
		info := TO0OwnerSignInfo{
			Voucher:       ov,
			To1d:          *sig.To1d.Untag(),
			DelegateChain: delegateChain,
			RequestedTTL:  ttl,
		}
		if ttl, err = s.AcceptVoucherWithInfo(ctx, info); err != nil {
			return nil, err
		}
		if ttl == 0 {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			return nil, fmt.Errorf("voucher has been rejected")
		}
	} else if s.AcceptVoucher != nil {
		if ttl, err = s.AcceptVoucher(ctx, ov, ttl); err != nil {
			return nil, err
		}
		if ttl == 0 {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			return nil, fmt.Errorf("voucher has been rejected")
		}
	}

	// Store rendezvous blob
	expiration := time.Now().Add(time.Duration(ttl) * time.Second)
	if err := s.RVBlobs.SetRVBlob(ctx, &ov, sig.To1d.Untag(), expiration); err != nil {
		return nil, fmt.Errorf("error storing rendezvous blob: %w", err)
	}

	return &to0AcceptOwner{
		WaitSeconds: ttl,
	}, nil
}
