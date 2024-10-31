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
	Vouchers OwnerVoucherPersistentState

	// OwnerKeys are used for signing the rendezvous blob.
	OwnerKeys OwnerKeyPersistentState

	// TTL is the amount of time to recommend that the Rendezvous Server allows
	// the rendezvous blob mapping to remain active.
	//
	// If TTL is 0, [DefaultRVBlobTTL] will be used.
	TTL uint32
}

// RegisterBlob tells a Rendezvous Server where to direct a given device to its
// owner service for onboarding. The returned uint32 is the number of seconds
// before the rendezvous blob must be refreshed by calling [RegisterBlob] again.
func (c *TO0Client) RegisterBlob(ctx context.Context, transport Transport, guid protocol.GUID, addrs []protocol.RvTO2Addr) (uint32, error) {
	ctx = contextWithErrMsg(ctx)

	nonce, err := c.hello(ctx, transport)
	if err != nil {
		return 0, err
	}

	ttl := c.TTL
	if ttl == 0 {
		ttl = DefaultRVBlobTTL
	}

	return c.ownerSign(ctx, transport, guid, ttl, nonce, addrs)
}


// Hello(20) -> HelloAck(21)
func (c *TO0Client) hello(ctx context.Context, transport Transport) (protocol.Nonce, error) {
	// Define request structure
	msg := GlobalCapabilityFlags

	// Make request
	typ, resp, err := transport.Send(ctx, protocol.TO0HelloMsgType, msg, nil)
	if err != nil {
		return protocol.Nonce{}, fmt.Errorf("error sending TO0.Hello: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case protocol.TO0HelloAckMsgType:
		captureMsgType(ctx, typ)
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

// Hello(20) -> HelloAck(21)
func (s *TO0Server) helloAck(ctx context.Context, msg io.Reader) (*to0Ack, error) {
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

// OwnerSign(22) -> AcceptOwner(23)
func (c *TO0Client) ownerSign(ctx context.Context, transport Transport, guid protocol.GUID, ttl uint32, nonce protocol.Nonce, addrs []protocol.RvTO2Addr) (negotiatedTTL uint32, _ error) {
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
	keyType := ov.Header.Val.ManufacturerKey.Type
	ownerKey, _, err := c.OwnerKeys.OwnerKey(keyType)
	if errors.Is(err, ErrNotFound) {
		return 0, fmt.Errorf("no available owner key for TO0.OwnerSign [type=%s]", keyType)
	} else if err != nil {
		return 0, fmt.Errorf("error getting owner key [type=%s]: %w", keyType, err)
	}
	opts, err := signOptsFor(ownerKey, keyType == protocol.RsaPssKeyType)
	if err != nil {
		return 0, fmt.Errorf("error determining signing options for TO0.OwnerSign: %w", err)
	}
	to1d := cose.Sign1[protocol.To1d, []byte]{Payload: cbor.NewByteWrap(protocol.To1d{
		RV: addrs,
		To0dHash: protocol.Hash{
			Algorithm: alg,
			Value:     to0dHash.Sum(nil),
		},
	})}
	if err := to1d.Sign(ownerKey, nil, nil, opts); err != nil {
		return 0, fmt.Errorf("error signing To1d payload for TO0.OwnerSign: %w", err)
	}

	// Define request structure
	msg := ownerSign{
		To0d: *cbor.NewBstr(to0d),
		To1d: *to1d.Tag(),
	}

	// Make request
	typ, resp, err := transport.Send(ctx, protocol.TO0OwnerSignMsgType, msg, nil)
	if err != nil {
		return 0, fmt.Errorf("error sending TO0.OwnerSign: %w", err)
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
func (s *TO0Server) acceptOwner(ctx context.Context, msg io.Reader) (*to0AcceptOwner, error) {
	var sig ownerSign
	if err := cbor.NewDecoder(msg).Decode(&sig); err != nil {
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

	// Use optional callback to decide whether to accept voucher
	if s.AcceptVoucher != nil {
		if accept, err := s.AcceptVoucher(ctx, ov); err != nil {
			return nil, err
		} else if !accept {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			return nil, fmt.Errorf("voucher has been rejected")
		}
	}

	// Allow adjusting rendezvous blob mapping validity period
	negotiatedTTL := sig.To0d.Val.WaitSeconds
	if s.NegotiateTTL != nil {
		negotiatedTTL = s.NegotiateTTL(negotiatedTTL, ov)
	}

	// Store rendezvous blob
	expiration := time.Now().Add(time.Duration(negotiatedTTL) * time.Second)
	if err := s.RVBlobs.SetRVBlob(ctx, &ov, sig.To1d.Untag(), expiration); err != nil {
		return nil, fmt.Errorf("error storing rendezvous blob: %w", err)
	}

	return &to0AcceptOwner{
		WaitSeconds: negotiatedTTL,
	}, nil
}
