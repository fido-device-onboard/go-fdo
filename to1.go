// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// TO1Options contains optional configuration values.
type TO1Options struct {
	// When true and an RSA key is used as a crypto.Signer argument, RSA-SSAPSS
	// will be used for signing.
	PSS bool
}

// TO1 runs the TO1 protocol and returns the owner service (TO2) addresses. It
// requires that a device credential, hmac secret, and key are all configured
// on the client.
func TO1(ctx context.Context, transport Transport, cred DeviceCredential, key crypto.Signer, opts *TO1Options) (*cose.Sign1[protocol.To1d, []byte], error) {
	ctx = contextWithErrMsg(ctx)

	var usePSS bool
	if opts != nil {
		usePSS = opts.PSS
	}
	signOpts, err := signOptsFor(key, usePSS)
	if err != nil {
		return nil, fmt.Errorf("error determining signing options: %w", err)
	}

	nonce, err := helloRv(ctx, transport, cred, key, signOpts)
	if err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}

	blob, err := proveToRv(ctx, transport, cred, nonce, key, signOpts)
	if err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}

	return blob, nil
}

type helloRV struct {
	GUID     protocol.GUID
	ASigInfo sigInfo
	CapabilityFlags
}

// HelloRV(30) -> HelloRVAck(31)
func helloRv(ctx context.Context, transport Transport, cred DeviceCredential, key crypto.Signer, opts crypto.SignerOpts) (protocol.Nonce, error) {
	var usePSS bool
	if _, ok := opts.(*rsa.PSSOptions); ok {
		usePSS = true
	}
	eASigInfo, err := sigInfoFor(key, usePSS)
	if err != nil {
		return protocol.Nonce{}, fmt.Errorf("error determining eASigInfo for TO1.HelloRV: %w", err)
	}

	// Define request structure
	msg := helloRV{
		GUID:     cred.GUID,
		ASigInfo: *eASigInfo,
		CapabilityFlags: GlobalCapabilityFlags,
	}

	// Make request
	typ, resp, err := transport.Send(ctx, protocol.TO1HelloRVMsgType, msg, nil)
	if err != nil {
		return protocol.Nonce{}, fmt.Errorf("TO1.HelloRV: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case protocol.TO1HelloRVAckMsgType:
		captureMsgType(ctx, typ)
		var ack rvAck
		if err := cbor.NewDecoder(resp).Decode(&ack); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return protocol.Nonce{}, fmt.Errorf("error parsing TO1.HelloRVAck contents: %w", err)
		}
		return ack.NonceTO1Proof, nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return protocol.Nonce{}, fmt.Errorf("error parsing error message contents of TO1.HelloRV response: %w", err)
		}
		return protocol.Nonce{}, fmt.Errorf("error received from TO1.HelloRV request: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		return protocol.Nonce{}, fmt.Errorf("unexpected message type for response to TO1.HelloRV: %d", typ)
	}
}

type rvAck struct {
	NonceTO1Proof protocol.Nonce
	BSigInfo      sigInfo
	CapabilityFlags
}

// HelloRV(30) -> HelloRVAck(31)
func (s *TO1Server) helloRVAck(ctx context.Context, msg io.Reader) (*rvAck, error) {
	var hello helloRV
	if err := cbor.NewDecoder(msg).Decode(&hello); err != nil {
		return nil, fmt.Errorf("error decoding TO1.HelloRV request: %w", err)
	}

	// Check if device has been registered
	if _, _, err := s.RVBlobs.RVBlob(ctx, hello.GUID); errors.Is(err, ErrNotFound) {
		captureErr(ctx, protocol.ResourceNotFound, "")
		return nil, ErrNotFound
	} else if err != nil {
		return nil, fmt.Errorf("error looking up device: %w", err)
	}

	// Generate and store nonce
	var nonce protocol.Nonce
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("error generating nonce for TO1 proof: %w", err)
	}
	if err := s.Session.SetTO1ProofNonce(ctx, nonce); err != nil {
		return nil, fmt.Errorf("error storing nonce for TO1.ProveToRV: %w", err)
	}

	return &rvAck{
		NonceTO1Proof: nonce,
		BSigInfo:      hello.ASigInfo,
		CapabilityFlags: GlobalCapabilityFlags,
	}, nil
}

// ProveToRV(32) -> RVRedirect(33)
func proveToRv(ctx context.Context, transport Transport, cred DeviceCredential, nonce protocol.Nonce, key crypto.Signer, opts crypto.SignerOpts) (*cose.Sign1[protocol.To1d, []byte], error) {
	// Define request structure
	token := cose.Sign1[eatoken, []byte]{
		Payload: cbor.NewByteWrap(newEAT(cred.GUID, nonce, nil, nil)),
	}
	if err := token.Sign(key, nil, nil, opts); err != nil {
		return nil, fmt.Errorf("error signing EAT payload for TO1.ProveToRV: %w", err)
	}
	msg := token.Tag()

	// Make request
	typ, resp, err := transport.Send(ctx, protocol.TO1ProveToRVMsgType, msg, nil)
	if err != nil {
		return nil, fmt.Errorf("TO1.ProveToRV: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case protocol.TO1RVRedirectMsgType:
		captureMsgType(ctx, typ)
		var redirect cose.Sign1Tag[protocol.To1d, []byte]
		if err := cbor.NewDecoder(resp).Decode(&redirect); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return nil, fmt.Errorf("error parsing TO1.RVRedirect contents: %w", err)
		}
		return redirect.Untag(), nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return nil, fmt.Errorf("error parsing error message contents of TO1.ProveToRV response: %w", err)
		}
		return nil, fmt.Errorf("error received from TO1.ProveToRV request: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		return nil, fmt.Errorf("unexpected message type for response to TO1.ProveToRV: %d", typ)
	}
}

// ProveToRV(32) -> RVRedirect(33)
func (s *TO1Server) rvRedirect(ctx context.Context, msg io.Reader) (*cose.Sign1Tag[protocol.To1d, []byte], error) {
	// Decode a fully-parsed and raw COSE Sign1. The latter is used for
	// verifying in a more lenient way, as it doesn't require deterministic
	// encoding of CBOR (even though FDO requires this).
	var token cose.Sign1Tag[cbor.RawBytes, []byte]
	if err := cbor.NewDecoder(msg).Decode(&token); err != nil {
		return nil, fmt.Errorf("error decoding TO1.ProveToRV request: %w", err)
	}
	var eat eatoken
	if err := cbor.Unmarshal([]byte(token.Payload.Val), &eat); err != nil {
		return nil, fmt.Errorf("error decoding TO1.ProveToRV request: %w", err)
	}

	// Check EAT nonce
	proofNonce, err := s.Session.TO1ProofNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting TO1 proof nonce: %w", err)
	}
	nonce, ok := eat[eatNonceClaim].([]byte)
	if !ok {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("EAT missing nonce claim")
	}
	if !bytes.Equal(nonce, proofNonce[:]) {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("EAT nonce does not match")
	}

	// Get GUID from EAT
	ueid, ok := eat[eatUeidClaim].([]byte)
	if !ok {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("EAT missing UEID claim")
	}
	if len(ueid) != 1+len(protocol.GUID{}) {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("EAT UEID claim is not a valid length")
	}
	if ueid[0] != eatRandUeid {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("EAT UEID type must be RAND")
	}
	var guid protocol.GUID
	_ = copy(guid[:], ueid[1:])

	// Get device public key from ownership voucher
	blob, ov, err := s.RVBlobs.RVBlob(ctx, guid)
	if err != nil {
		return nil, fmt.Errorf("error looking up rendezvous blob: %w", err)
	}
	pub, err := ov.DevicePublicKey()
	if err != nil {
		return nil, fmt.Errorf("error getting device public key from ownership voucher: %w", err)
	}

	// Verify EAT signature
	if ok, err := token.Verify(pub, nil, nil); err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("error verifying EAT signature: %w", err)
	} else if !ok {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return nil, fmt.Errorf("%w: EAT signature verification failed", ErrCryptoVerifyFailed)
	}

	// Return RV blob
	return blob.Tag(), nil
}
