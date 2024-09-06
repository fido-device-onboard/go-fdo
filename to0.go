// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

// TO0 Message Types
const (
	to0HelloMsgType       uint8 = 20
	to0HelloAckMsgType    uint8 = 21
	to0OwnerSignMsgType   uint8 = 22
	to0AcceptOwnerMsgType uint8 = 23
)

// DefaultRVBlobTTL is the default requested TTL for a rendezvous blob
// mapping.
const DefaultRVBlobTTL = 4_294_967_295 // max uint32

// TO0Client is used by owner services communicating with rendezvous services.
// Unlike [Client], it is not used by devices.
type TO0Client struct {
	// Transport performs message passing and may be implemented over TCP,
	// HTTP, CoAP, and others
	Transport Transport

	// Addrs are the network address(es) where the device can find its owner
	// service for onboarding.
	Addrs []RvTO2Addr

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
// owner service. The returned uint32 is the number of seconds before the
// rendezvous blob must be refreshed by calling [RegisterBlob] again.
func (c *TO0Client) RegisterBlob(ctx context.Context, baseURL string, guid GUID) (uint32, error) {
	ctx = contextWithErrMsg(ctx)

	nonce, err := c.hello(ctx, baseURL)
	if err != nil {
		return 0, err
	}

	ttl := c.TTL
	if ttl == 0 {
		ttl = DefaultRVBlobTTL
	}

	return c.ownerSign(ctx, baseURL, nonce, ttl, guid)
}

// Hello(20) -> HelloAck(21)
func (c *TO0Client) hello(ctx context.Context, baseURL string) (Nonce, error) {
	// Define request structure
	msg := struct{}{}

	// Make request
	typ, resp, err := c.Transport.Send(ctx, baseURL, to0HelloMsgType, msg, nil)
	if err != nil {
		return Nonce{}, fmt.Errorf("error sending TO0.Hello: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case to0HelloAckMsgType:
		captureMsgType(ctx, typ)
		var ack to0Ack
		if err := cbor.NewDecoder(resp).Decode(&ack); err != nil {
			captureErr(ctx, messageBodyErrCode, "")
			return Nonce{}, fmt.Errorf("error parsing TO0.HelloAck contents: %w", err)
		}
		return ack.NonceTO0Sign, nil

	case ErrorMsgType:
		var errMsg ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return Nonce{}, fmt.Errorf("error parsing error message contents of TO0.Hello response: %w", err)
		}
		return Nonce{}, fmt.Errorf("error received from TO0.Hello request: %w", errMsg)

	default:
		captureErr(ctx, messageBodyErrCode, "")
		return Nonce{}, fmt.Errorf("unexpected message type for response to TO0.Hello: %d", typ)
	}
}

type to0Ack struct {
	NonceTO0Sign Nonce
}

// Hello(20) -> HelloAck(21)
func (s *TO0Server) helloAck(ctx context.Context, msg io.Reader) (*to0Ack, error) {
	var hello struct{}
	if err := cbor.NewDecoder(msg).Decode(&hello); err != nil {
		return nil, fmt.Errorf("error decoding TO0.Hello request: %w", err)
	}

	// Generate and store nonce
	var nonce Nonce
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
	NonceTO0Sign Nonce
}

type ownerSign struct {
	To0d cbor.Bstr[to0d]
	To1d cose.Sign1Tag[To1d, []byte]
}

// OwnerSign(22) -> AcceptOwner(23)
func (c *TO0Client) ownerSign(ctx context.Context, baseURL string, nonce Nonce, ttl uint32, guid GUID) (negotiatedTTL uint32, _ error) {
	// Create and hash to0d
	ov, err := c.Vouchers.Voucher(ctx, guid)
	if err != nil {
		return 0, fmt.Errorf("error looking up ownership voucher: %w", err)
	}
	to0d := to0d{
		Voucher:      *ov,
		WaitSeconds:  ttl,
		NonceTO0Sign: nonce,
	}
	to0dHash := sha256.New()
	if err := cbor.NewEncoder(to0dHash).Encode(to0d); err != nil {
		return 0, fmt.Errorf("error hashing to0d structure: %w", err)
	}

	// Sign to1d rendezvous blob
	keyType := ov.Header.Val.ManufacturerKey.Type
	key, ok := c.OwnerKeys.Signer(keyType)
	if !ok {
		return 0, fmt.Errorf("no available owner key for TO0.OwnerSign [type=%s]", keyType)
	}
	opts, err := signOptsFor(key, keyType == RsaPssKeyType)
	if err != nil {
		return 0, fmt.Errorf("error determining signing options for TO0.OwnerSign: %w", err)
	}
	to1d := cose.Sign1[To1d, []byte]{Payload: cbor.NewByteWrap(To1d{
		RV: c.Addrs,
		To0dHash: Hash{
			Algorithm: Sha256Hash,
			Value:     to0dHash.Sum(nil),
		},
	})}
	if err := to1d.Sign(key, nil, nil, opts); err != nil {
		return 0, fmt.Errorf("error signing To1d payload for TO0.OwnerSign: %w", err)
	}

	// Define request structure
	msg := ownerSign{
		To0d: *cbor.NewBstr(to0d),
		To1d: *to1d.Tag(),
	}

	// Make request
	typ, resp, err := c.Transport.Send(ctx, baseURL, to0OwnerSignMsgType, msg, nil)
	if err != nil {
		return 0, fmt.Errorf("error sending TO0.OwnerSign: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case to0AcceptOwnerMsgType:
		captureMsgType(ctx, typ)
		var accept to0AcceptOwner
		if err := cbor.NewDecoder(resp).Decode(&accept); err != nil {
			captureErr(ctx, messageBodyErrCode, "")
			return 0, fmt.Errorf("error parsing TO0.AcceptOwner contents: %w", err)
		}
		return accept.WaitSeconds, nil

	case ErrorMsgType:
		var errMsg ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return 0, fmt.Errorf("error parsing error message contents of TO0.OwnerSign response: %w", err)
		}
		return 0, fmt.Errorf("error received from TO0.OwnerSign request: %w", errMsg)

	default:
		captureErr(ctx, messageBodyErrCode, "")
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
		captureErr(ctx, invalidMessageErrCode, "")
		return nil, fmt.Errorf("error decoding TO0.OwnerSign request: %w", err)
	}

	// Verify to0d hash matches to0d
	to0dHash := sig.To1d.Payload.Val.To0dHash.Algorithm.HashFunc().New()
	if err := cbor.NewEncoder(to0dHash).Encode(sig.To0d.Val); err != nil {
		return nil, fmt.Errorf("error hashing to0d structure: %w", err)
	}
	if !bytes.Equal(to0dHash.Sum(nil), sig.To1d.Payload.Val.To0dHash.Value) {
		captureErr(ctx, invalidMessageErrCode, "")
		return nil, fmt.Errorf("to0d did not match hash in to1d")
	}

	// Verify ownership voucher is valid
	ov := sig.To0d.Val.Voucher
	if len(ov.Entries) == 0 {
		captureErr(ctx, invalidMessageErrCode, "")
		return nil, fmt.Errorf("voucher has not been extended")
	}
	if err := ov.VerifyEntries(); err != nil {
		captureErr(ctx, invalidMessageErrCode, "")
		return nil, fmt.Errorf("voucher is not valid: %w", err)
	}

	// TODO: Use optional callback to decide whether to accept voucher

	// TODO: Allow adjusting rendezvous blob mapping validity period
	negotiatedTTL := sig.To0d.Val.WaitSeconds

	// Store rendezvous blob
	expiration := time.Now().Add(time.Duration(negotiatedTTL) * time.Second)
	if err := s.RVBlobs.SetRVBlob(ctx, &ov, sig.To1d.Untag(), expiration); err != nil {
		return nil, fmt.Errorf("error storing rendezvous blob: %w", err)
	}

	return &to0AcceptOwner{
		WaitSeconds: negotiatedTTL,
	}, nil
}
