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

	// DelegateKeys may be used for signing the rendezvous blob.
	DelegateKeys DelegateKeyPersistentState

	// TTL is the amount of time to recommend that the Rendezvous Server allows
	// the rendezvous blob mapping to remain active.
	//
	// If TTL is 0, [DefaultRVBlobTTL] will be used.
	TTL uint32
}

// RegisterBlob tells a Rendezvous Server where to direct a given device to its
// owner service for onboarding. The returned uint32 is the number of seconds
// before the rendezvous blob must be refreshed by calling [RegisterBlob] again.
func (c *TO0Client) RegisterBlob(ctx context.Context, transport Transport, guid protocol.GUID, addrs []protocol.RvTO2Addr, delegateName string) (uint32, error) {
	ctx = contextWithErrMsg(ctx)

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
	DelegateChain *[]*cbor.X509Certificate `cbor:",omitempty"`
}

/*
func (c *TO0Client) delegateKey(keyType protocol.KeyType, keyEncoding protocol.KeyEncoding) (crypto.Signer, *protocol.PublicKey, error) {
	key, chain, err := c.DelegateKeys.DelegateKey("TEST") //keyType)
	if errors.Is(err, ErrNotFound) {
		return nil, nil, fmt.Errorf("delegate key type %s not supported", keyType)
	} else if err != nil {
		return nil, nil, fmt.Errorf("error getting delegate key [type=%s]: %w", keyType, err)
	}

	// Default to X509 key encoding if owner key does not have a certificate
	// chain
	if keyEncoding == protocol.X5ChainKeyEnc && len(chain) == 0 {
		keyEncoding = protocol.X509KeyEnc
	}

	var pubkey *protocol.PublicKey
	switch keyEncoding {
	case protocol.X509KeyEnc, protocol.CoseKeyEnc:
		switch keyType {
		case protocol.Secp256r1KeyType, protocol.Secp384r1KeyType:
			pubkey, err = protocol.NewPublicKey(keyType, key.Public().(*ecdsa.PublicKey), keyEncoding == protocol.CoseKeyEnc)
		case protocol.Rsa2048RestrKeyType, protocol.RsaPkcsKeyType, protocol.RsaPssKeyType:
			pubkey, err = protocol.NewPublicKey(keyType, key.Public().(*rsa.PublicKey), keyEncoding == protocol.CoseKeyEnc)
		default:
			return nil, nil, fmt.Errorf("unsupported key type: %s", keyType)
		}

	case protocol.X5ChainKeyEnc:
		pubkey, err = protocol.NewPublicKey(keyType, chain, false)

	default:
		return nil, nil, fmt.Errorf("unsupported delegate key encoding: %s", keyEncoding)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("error with delegate public key: %w", err)
	}

	return key, pubkey, nil
}
*/

// OwnerSign(22) -> AcceptOwner(23)
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
	keyType := ov.Header.Val.ManufacturerKey.Type
	// Sign with Delegate or Owner Key?
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

	var header = cose.Header{
			Unprotected: map[cose.Label]any{
			},
		}


	to1d := cose.Sign1[protocol.To1d, []byte]{
		Header: header,
		Payload: cbor.NewByteWrap(protocol.To1d{
		RV: addrs,
		To0dHash: protocol.Hash{
			Algorithm: alg,
			Value:     to0dHash.Sum(nil),
		},
	})}

	fmt.Printf("*** OV KEY TYPE IS %T Name is \"%s\"\n",keyType,keyType)
	fmt.Printf("*** OV KEY String is \"%s\"\n",keyType.KeyString())
	// Sign blob with OwnerKey - or Delegate, if requested
	if (delegateName != "") {
		// TODO This imples that Delegate Key type will always be the same as manufacture - which may not be true
		// Delegate must be X509 or X5CHAIN so it can prove that Owner signed it
		if (delegateName == "=") { delegateName = keyType.KeyString() }
		delegateKey, ch, err := c.DelegateKeys.DelegateKey(delegateName)
		if err != nil {
			return 0, fmt.Errorf("error getting delegate key [type=%s]: %w", keyType, err)
		}
		delegateOpts, err := signOptsFor(delegateKey, keyType == protocol.RsaPssKeyType)
		if err != nil {
			return 0, fmt.Errorf("error determining signing options for TO0 Delgate: %w", err)
		}
		chain, err := protocol.NewPublicKey(keyType,ch,false)
		header.Unprotected[to2DelegateClaim] = chain
		
		if err := to1d.Sign(delegateKey, nil, nil, delegateOpts); err != nil {
			return 0, fmt.Errorf("error signing To1d payload for w/ Delegate TO0.OwnerSign: %w", err)
		}
		fmt.Printf("*** BLOB SIGNED WITH DELEGATE %T %v\n",delegateKey,delegateKey)
		fmt.Printf("*** BLOB SIGNED WITH DELEGATE chain %T %v\n",chain,chain)

		// TODO Do a veryify just to check if this is okay
		//ok,err := to1d.Verify(delegateKey.Public(),nil,nil)

		// This will fail if the device has been DI'd with a key of one type,
		// but the Delegate chain was rooted by a different key of a different type
		p, err := chain.Public()
		if (err != nil) {
			return 0, fmt.Errorf("Error getting public key from delegate chain: %v",err)
		}
		ok,err := to1d.Verify(p,nil,nil)
		fmt.Printf("TO1D was : %T %+v\n",to1d,to1d)
		fmt.Printf("TO1D was : %+v\n",to1d.Payload)
		fmt.Printf("To1d Re-Verify returned ok=%v err=%v\n",ok,err)
		fmt.Printf("Public Key was: %T %+v\n",delegateKey.Public(),delegateKey.Public())
		if err != nil {
			return 0, fmt.Errorf("To1d verify failed: %w", err)
		}
	} else {
		if err := to1d.Sign(ownerKey, nil, nil, opts); err != nil {
			return 0, fmt.Errorf("error signing To1d payload for TO0.OwnerSign: %w", err)
		}
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
