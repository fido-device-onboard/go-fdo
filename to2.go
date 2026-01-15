// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"math"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cbor/cdn"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/plugin"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// COSE unprotected header labels for TO2.ProveOVHdr
// These are in the "Reserved for Private Use" space of COSE Header Parameters.
//
// TODO: There is an open debate about whether OwnerPubKey and DelegateChain
// should remain in unprotected headers or be moved into the signed payload.
// The spec (TO2ProveOVHdrPayload) shows them in the payload, but this
// implementation keeps them in unprotected headers for consistency with FDO 1.x.
// Security argument for unprotected headers: these provide verification materials,
// so if tampered, signature verification fails anyway - the security properties
// are equivalent whether signed or unsigned.
var (
	CUPHNonce         = cose.Label{Int64: 256} // FDO assigned
	CUPHOwnerPubKey   = cose.Label{Int64: 257} // FDO assigned
	CUPHDelegateChain = cose.Label{Int64: 258} // FDO assigned - delegate certificate chain
)

// Aliases for backward compatibility
var (
	to2NonceClaim       = CUPHNonce
	to2OwnerPubKeyClaim = CUPHOwnerPubKey
	to2DelegateClaim    = CUPHDelegateChain
)

// TO2Config contains the device credential, including secrets and keys,
// optional configuration, and service info modules.
type TO2Config struct {
	// Non-secret device credential data.
	Cred DeviceCredential

	// HMAC-SHA256 with a device secret that does not change when ownership is
	// transferred. HMAC-SHA256 support is always required by spec, so this
	// field must be non-nil.
	//
	// This hash.Hash may optionally implement the following interface to
	// return errors from Reset/Write/Sum, noting that implementations of
	// hash.Hash are not supposed to return non-nil errors from Write.
	//
	// 	type FallibleHash interface {
	// 		Err() error
	// 	}
	HmacSha256 hash.Hash

	// HMAC-SHA384 with a device secret that does not change when ownership is
	// transferred. HMAC-SHA384 support is optional by spec, so this field may
	// be nil iff Key is RSA 2048 or EC P-256.
	//
	// This hash.Hash may optionally implement the following interface to
	// return errors from Reset/Write/Sum, noting that implementations of
	// hash.Hash are not supposed to return non-nil errors from Write.
	//
	// 	type FallibleHash interface {
	// 		Err() error
	// 	}
	HmacSha384 hash.Hash

	// An ECDSA or RSA private key that may or may not be implemented with the
	// stdlib ecdsa and rsa packages.
	Key crypto.Signer

	// When true and an RSA key is used as a crypto.Signer argument, RSA-SSAPSS
	// will be used for signing.
	PSS bool

	// Devmod contains all required and any number of optional messages.
	//
	// Alternatively to setting this field, a devmod module may be provided in
	// the arguments to TransferOwnership2 where the module must provide any
	// devmod messages EXCEPT nummodules and modules via its Yield method.
	//
	// Note: The device plugin will be yielded to exactly once and is expected
	// to provide all required and desired fields and yield. It may then exit.
	Devmod serviceinfo.Devmod

	// Each ServiceInfo module will be reported in devmod and potentially
	// activated and used. If a devmod module is included in this list, it
	// overrides the Devmod field in TO2Config. The custom devmod should not
	// send nummodules or modules messages, as these will always be sent upon
	// module completion.
	DeviceModules map[string]serviceinfo.DeviceModule

	// Selects the key exchange suite to use. If unset, it defaults to ECDH384.
	KeyExchange kex.Suite

	// Selects the cipher suite to use for encryption. If unset, it defaults to
	// A256GCM.
	CipherSuite kex.CipherSuiteID

	// Maximum transmission unit (MTU) to tell owner service to send with. If
	// zero, the default of 1300 will be used. The value chosen can make a
	// difference for performance when using service info to exchange large
	// amounts of data, but choosing the best value depends on network
	// configuration (e.g. jumbo packets) and transport (overhead size).
	MaxServiceInfoSizeReceive uint16

	// Allow for the Credential Reuse Protocol (Section 7) to be used. If not
	// enabled, TO2 will fail with CredReuseErrCode (102) if reuse is
	// attempted by the owner service.
	AllowCredentialReuse bool
}

// TO2 runs the TO2 protocol and returns a DeviceCredential with replaced GUID,
// rendezvous info, and owner public key. It requires that a device credential,
// hmac secret, and key are all provided as configuration.
//
// A to1d signed blob is expected if rendezvous bypass is not used. This blob
// is output from TO1.
//
// It has the side effect of performing service info modules, which may include
// actions such as downloading files.
//
// If the Credential Reuse protocol is allowed and occurs, then the returned
// device credential will be nil.
func TO2(ctx context.Context, transport Transport, to1d *cose.Sign1[protocol.To1d, []byte], c TO2Config) (*DeviceCredential, error) {
	ctx = contextWithErrMsg(ctx)

	// Configure defaults
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

	// Mutually attest the device and owner service
	//
	// Results: Replacement ownership voucher, nonces to be retransmitted in
	// Done/Done2 messages
	proveDeviceNonce, ownerPublicKey, originalOwnerKey, originalOVH, sess, err := verifyOwner(ctx, transport, to1d, &c)
	if err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}
	defer sess.Destroy()
	setupDeviceNonce, partialOVH, err := proveDevice(ctx, transport, proveDeviceNonce, ownerPublicKey, originalOwnerKey, sess, &c)
	if err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}

	// Select the appropriate hash algorithm for HMAC and public key hash
	alg := c.Cred.PublicKeyHash.Algorithm
	var replacementOVH *VoucherHeader
	if partialOVH != nil {
		nextOwnerPublicKey, err := partialOVH.ManufacturerKey.Public()
		if err != nil {
			return nil, fmt.Errorf("error parsing manufacturer public key type from incomplete replacement ownership voucher header: %w", err)
		}
		alg, err = hashAlgFor(c.Key.Public(), nextOwnerPublicKey)
		if err != nil {
			return nil, fmt.Errorf("error selecting the appropriate hash algorithm: %w", err)
		}
		replacementOVH = &VoucherHeader{
			Version:         originalOVH.Version,
			GUID:            partialOVH.GUID,
			RvInfo:          partialOVH.RvInfo,
			DeviceInfo:      originalOVH.DeviceInfo,
			ManufacturerKey: partialOVH.ManufacturerKey,
			CertChainHash:   originalOVH.CertChainHash,
		}
	}

	// Prepare to send and receive service info, determining the transmit MTU
	sendMTU, err := sendReadyServiceInfo(ctx, transport, alg, replacementOVH, sess, &c)
	if err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}

	// Start synchronously writing the initial device service info. This occurs
	// in a goroutine because the pipe is unbuffered and needs to be
	// concurrently read by the send/receive service info loop.
	serviceInfoReader, serviceInfoWriter := serviceinfo.NewChunkOutPipe(0)
	defer func() { _ = serviceInfoWriter.Close() }()

	// Send devmod KVs in initial ServiceInfo
	go c.Devmod.Write(ctx, c.DeviceModules, sendMTU, serviceInfoWriter)

	// Loop, sending and receiving service info until done
	if err := exchangeServiceInfo(ctx, transport, proveDeviceNonce, setupDeviceNonce, sendMTU, serviceInfoReader, sess, &c); err != nil {
		errorMsg(ctx, transport, err)
		return nil, err
	}

	// If using the Credential Reuse protocol the device credential is not updated
	if replacementOVH == nil {
		return nil, nil
	}

	// Hash new initial owner public key and return replacement device
	// credential
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

func stopOwnerPlugin(ctx context.Context, name string, module plugin.Module) {
	// Try a graceful stop for up to five seconds
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := module.GracefulStop(ctx); err != nil && !errors.Is(err, context.Canceled) {
		slog.Warn("plugin graceful stop failed", "module", name, "error", err)
	}

	if err := module.Stop(); err != nil {
		slog.Warn("plugin forceful stop failed", "module", name, "error", err)
	}
}

// Stop any plugin device modules
func stopDevicePlugins(modules *deviceModuleMap) {
	pluginStopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var pluginStopWg sync.WaitGroup
	for name, mod := range modules.modules {
		if !modules.active[name] {
			continue
		}
		if p, ok := mod.(plugin.Module); ok {
			pluginStopWg.Add(1)
			pluginGracefulStopCtx, done := context.WithCancel(pluginStopCtx)

			// Allow Graceful stop up to the original shared timeout
			go func(p plugin.Module) {
				defer done()
				if err := p.GracefulStop(pluginGracefulStopCtx); err != nil && !errors.Is(err, context.Canceled) { //nolint:revive,staticcheck
					slog.Warn("graceful stop failed", "module", name, "error", err)
				}
			}(p)

			// Force stop after the shared timeout expires or graceful stop
			// completes
			go func(p plugin.Module) {
				<-pluginGracefulStopCtx.Done()
				_ = p.Stop()
				pluginStopWg.Done()
			}(p)
		}
	}
	pluginStopWg.Wait()
}

// Verify owner by sending HelloDevice and validating the response, as well as
// all ownership voucher entries, which are retrieved iteratively with
// subsequence requests.
func verifyOwner(ctx context.Context, transport Transport, to1d *cose.Sign1[protocol.To1d, []byte], c *TO2Config) (protocol.Nonce, crypto.PublicKey, crypto.PublicKey, *VoucherHeader, kex.Session, error) {
	proveDeviceNonce, info, sess, err := sendHelloDevice(ctx, transport, c)
	if err != nil {
		return protocol.Nonce{}, nil, nil, nil, nil, err
	}
	if !c.KeyExchange.Valid(c.Key.Public(), info.PublicKeyToValidate) {
		sess.Destroy()
		return protocol.Nonce{}, nil, nil, nil, nil, fmt.Errorf(
			"key exchange %s is invalid for the device and owner attestation types",
			c.KeyExchange,
		)
	}
	if !kex.Available(c.KeyExchange, c.CipherSuite) {
		sess.Destroy()
		return protocol.Nonce{}, nil, nil, nil, nil, fmt.Errorf("unsupported key exchange/cipher suite")
	}
	if err := verifyVoucher(ctx, transport, to1d, info, c); err != nil {
		sess.Destroy()
		return protocol.Nonce{}, nil, nil, nil, nil, err
	}
	return proveDeviceNonce, info.PublicKeyToValidate, info.OriginalOwnerKey, &info.OVH, sess, nil
}

// Verify Voucher - using Transport to get entries
func verifyVoucher(ctx context.Context, transport Transport, to1d *cose.Sign1[protocol.To1d, []byte], info *OvhValidationContext, c *TO2Config) error {
	// If a delegate is used, verify the delegate chain is signed by the original owner.
	// This is critical security: without this check, an attacker could present a
	// self-signed delegate certificate and the client would trust it.
	if info.DelegateChain != nil {
		chain, err := info.DelegateChain.Chain()
		if err != nil {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			return fmt.Errorf("error parsing delegate chain: %w", err)
		}
		if err := VerifyDelegateChain(chain, &info.OriginalOwnerKey, nil); err != nil {
			// Check if this is a CertificateValidationError for detailed error reporting
			if certErr, ok := err.(*CertificateValidationError); ok {
				// Send detailed certificate validation error to client
				errorMsg := certErr.ToProtocolErrorMessage()
				captureErr(ctx, errorMsg.Code, errorMsg.ErrString)
				return fmt.Errorf("delegate chain verification failed: %w", certErr)
			}
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			return fmt.Errorf("delegate chain verification failed: %w", err)
		}
	}

	// Construct ownership voucher from parts received from the owner service
	var entries []cose.Sign1Tag[VoucherEntryPayload, []byte]
	for i := range info.NumVoucherEntries {
		entry, err := sendNextOVEntry(ctx, transport, i)
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

	if err := ov.VerifyCrypto(VerifyOptions{
		HmacSha256:         c.HmacSha256,
		HmacSha384:         c.HmacSha384,
		MfgPubKeyHash:      c.Cred.PublicKeyHash,
		OwnerPubToValidate: info.PublicKeyToValidate,
		To1d:               to1d,
	}); err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return err
	}

	return nil
}

type helloDeviceMsg struct {
	MaxDeviceMessageSize uint16
	GUID                 protocol.GUID
	NonceTO2ProveOV      protocol.Nonce
	KexSuiteName         kex.Suite
	CipherSuite          kex.CipherSuiteID
	SigInfoA             sigInfo
}

// OvhValidationContext holds context for ownership voucher header validation.
type OvhValidationContext struct {
	OVH                 VoucherHeader
	OVHHmac             protocol.Hmac
	NumVoucherEntries   int
	PublicKeyToValidate crypto.PublicKey
	OriginalOwnerKey    crypto.PublicKey
	DelegateChain       *protocol.PublicKey
}

// HelloDevice(60) -> ProveOVHdr(61)
//
//nolint:gocyclo // This is very complex validation that is better understood linearly
func sendHelloDevice(ctx context.Context, transport Transport, c *TO2Config) (protocol.Nonce, *OvhValidationContext, kex.Session, error) {
	// Generate a new nonce
	var proveOVNonce protocol.Nonce
	if _, err := rand.Read(proveOVNonce[:]); err != nil {
		return protocol.Nonce{}, nil, nil, fmt.Errorf("error generating new nonce for TO2.HelloDevice request: %w", err)
	}

	// Select SigInfo using SHA384 when available
	aSigInfo, err := sigInfoFor(c.Key, c.PSS)
	if err != nil {
		return protocol.Nonce{}, nil, nil, fmt.Errorf("error selecting aSigInfo for TO2.HelloDevice request: %w", err)
	}

	// Create a request structure
	hello := helloDeviceMsg{
		MaxDeviceMessageSize: 65535, // TODO: Make this configurable and match transport config
		GUID:                 c.Cred.GUID,
		NonceTO2ProveOV:      proveOVNonce,
		KexSuiteName:         c.KeyExchange,
		CipherSuite:          c.CipherSuite,
		SigInfoA:             *aSigInfo,
	}

	// Make a request
	typ, resp, err := transport.Send(ctx, protocol.TO2HelloDeviceMsgType, hello, nil)
	if err != nil {
		return protocol.Nonce{}, nil, nil, err
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	var proveOVHdr cose.Sign1Tag[ovhProof, []byte]
	switch typ {
	case protocol.TO2ProveOVHdrMsgType:
		captureMsgType(ctx, typ)
		if err := cbor.NewDecoder(resp).Decode(&proveOVHdr); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return protocol.Nonce{}, nil, nil, fmt.Errorf("error parsing TO2.ProveOVHdr contents: %w", err)
		}
		defer clear(proveOVHdr.Payload.Val.KeyExchangeA)

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return protocol.Nonce{}, nil, nil, fmt.Errorf("error parsing error message contents of TO2.HelloDevice response: %w", err)
		}
		return protocol.Nonce{}, nil, nil, fmt.Errorf("error received from TO2.HelloDevice request: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		return protocol.Nonce{}, nil, nil, fmt.Errorf("unexpected message type for response to TO2.HelloDevice: %d", typ)
	}

	// Validate the HelloDeviceHash
	helloDeviceHash := proveOVHdr.Payload.Val.HelloDeviceHash.Algorithm.HashFunc().New()
	if err := cbor.NewEncoder(helloDeviceHash).Encode(hello); err != nil {
		return protocol.Nonce{}, nil, nil, fmt.Errorf("error hashing HelloDevice message to verify against TO2.ProveOVHdr payload's hash: %w", err)
	}
	if !bytes.Equal(proveOVHdr.Payload.Val.HelloDeviceHash.Value, helloDeviceHash.Sum(nil)) {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return protocol.Nonce{}, nil, nil, fmt.Errorf("hash of HelloDevice message TO2.ProveOVHdr did not match the message sent")
	}

	// Parse owner public key
	var ownerPubKey protocol.PublicKey
	if found, err := proveOVHdr.Unprotected.Parse(to2OwnerPubKeyClaim, &ownerPubKey); !found {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return protocol.Nonce{}, nil, nil, fmt.Errorf("owner pubkey unprotected header missing from TO2.ProveOVHdr response message")
	} else if err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return protocol.Nonce{}, nil, nil, fmt.Errorf("owner pubkey unprotected header from TO2.ProveOVHdr could not be unmarshaled: %w", err)
	}

	// Parse delegate public key (if presented)
	var delegatePubKey protocol.PublicKey
	var delegateFound bool

	if delegateFound, err = proveOVHdr.Unprotected.Parse(to2DelegateClaim, &delegatePubKey); err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return protocol.Nonce{}, nil, nil, fmt.Errorf("delegate pubkey unprotected header missing from TO2.ProveOVHdr response message: %w", err)
	}

	// Validate response signature and nonce. While the payload signature
	// verification is performed using the untrusted owner public key from the
	// headers, this is acceptable, because the owner public key will be
	// subsequently verified when the voucher entry chain is built and
	// verified.

	var key crypto.PublicKey
	if delegateFound {
		key, err = delegatePubKey.Public()

	} else {
		key, err = ownerPubKey.Public()
	}
	if err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return protocol.Nonce{}, nil, nil, fmt.Errorf("error parsing owner public key to verify TO2.ProveOVHdr payload signature: %w", err)
	}

	if ok, err := proveOVHdr.Verify(key, nil, nil); err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return protocol.Nonce{}, nil, nil, fmt.Errorf("error verifying TO2.ProveOVHdr payload signature: %w", err)
	} else if !ok {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return protocol.Nonce{}, nil, nil, fmt.Errorf("TO2.ProveOVHdr payload signature verification failed: %w", ErrCryptoVerifyFailed)
	}
	if proveOVHdr.Payload.Val.NonceTO2ProveOV != proveOVNonce {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return protocol.Nonce{}, nil, nil, fmt.Errorf("nonce in TO2.ProveOVHdr did not match nonce sent in TO2.HelloDevice")
	}

	// proveOVHdr.Payload.Val.SigInfoB does not need to be validated. It is
	// just a formality for ECDSA/RSA keys, left over from EPID support.

	// TODO: Track proveOVHdr.Payload.Val.MaxOwnerMessageSize and later
	// calculate MTU=min(MaxOwnerMessageSize, MaxOwnerServiceInfoSize) for
	// better spec compliance, but honestly MaxOwnerMessageSize doesn't make
	// that much sense. What can you do with it that you can't with service
	// info max - fail early if TO2.ProveDevice is necessarily too large to be
	// received?

	// Parse nonce
	var cuphNonce protocol.Nonce
	if found, err := proveOVHdr.Unprotected.Parse(to2NonceClaim, &cuphNonce); !found {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return protocol.Nonce{}, nil, nil, fmt.Errorf("nonce unprotected header missing from TO2.ProveOVHdr response message")
	} else if err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return protocol.Nonce{}, nil, nil, fmt.Errorf("nonce unprotected header from TO2.ProveOVHdr could not be unmarshaled: %w", err)
	}

	var DelegateChain *protocol.PublicKey
	originalOwnerKey, err := ownerPubKey.Public()
	if err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return protocol.Nonce{}, nil, nil, fmt.Errorf("error re-parsing owner public key to verify TO2.ProveOVHdr payload signature: %w", err)
	}

	// When a delegate is used, PublicKeyToValidate must be the original owner key
	// (from the voucher chain), not the delegate key. The delegate key is only
	// used for signature verification.
	publicKeyToValidate := key
	if delegateFound {
		DelegateChain = &delegatePubKey
		publicKeyToValidate = originalOwnerKey
	}

	return cuphNonce,
		&OvhValidationContext{
			OVH:                 proveOVHdr.Payload.Val.OVH.Val,
			OVHHmac:             proveOVHdr.Payload.Val.OVHHmac,
			NumVoucherEntries:   int(proveOVHdr.Payload.Val.NumOVEntries),
			PublicKeyToValidate: publicKeyToValidate,
			OriginalOwnerKey:    originalOwnerKey,
			DelegateChain:       DelegateChain,
		},
		// The key exchange parameter is zeroed and a copy used to initialize
		// the key exchange session (which has its own Destroy method), because
		// when using fdotest the transport does not actually marshal the
		// server response. Therefore, after this function returns, proveOVHdr
		// goes out of scope and its finalizer will run (at some point),
		// zeroing the key exchange parameter and causing tests to be flaky.
		c.KeyExchange.New(bytes.Clone(proveOVHdr.Payload.Val.KeyExchangeA), c.CipherSuite),
		nil

}

type ovhProof struct {
	OVH                 cbor.Bstr[VoucherHeader]
	NumOVEntries        uint8
	OVHHmac             protocol.Hmac
	NonceTO2ProveOV     protocol.Nonce
	SigInfoB            sigInfo
	KeyExchangeA        []byte
	HelloDeviceHash     protocol.Hash
	MaxOwnerMessageSize uint16
}

// HelloDevice(60) -> ProveOVHdr(61)
//
// TODO: Handle MaxDeviceMessageSize
func (s *TO2Server) proveOVHdr(ctx context.Context, msg io.Reader) (*cose.Sign1Tag[ovhProof, []byte], error) { //nolint:gocyclo
	// Parse request
	var rawHello cbor.RawBytes
	if err := cbor.NewDecoder(msg).Decode(&rawHello); err != nil {
		return nil, fmt.Errorf("error decoding TO2.HelloDevice request: %w", err)
	}
	var hello helloDeviceMsg
	if err := cbor.Unmarshal(rawHello, &hello); err != nil {
		return nil, fmt.Errorf("error decoding TO2.HelloDevice request: %w", err)
	}

	// Retrieve voucher
	if err := s.Session.SetGUID(ctx, hello.GUID); err != nil {
		return nil, fmt.Errorf("error associating device GUID to proof session: %w", err)
	}
	ov, err := s.Vouchers.Voucher(ctx, hello.GUID)
	if err != nil || len(ov.Entries) == 0 {
		captureErr(ctx, protocol.ResourceNotFound, "")
		return nil, fmt.Errorf("error retrieving voucher for device %x: %w", hello.GUID, err)
	}
	// It is legal for this tag to have a value of zero (0), but this is
	// only useful in re-manufacturing situations, since the Rendezvous
	// Server cannot verify (or accept) these Ownership Proxies.
	numEntries := len(ov.Entries)
	if numEntries > math.MaxUint8 {
		return nil, fmt.Errorf("voucher for device %x has too many entries", hello.GUID)
	}

	// Assert that owner key matches voucher, in case the key was replaced or
	// the voucher was not extended before being stored
	keyType, opts, err := keyTypeFor(hello.SigInfoA.Type)
	if err != nil {
		return nil, fmt.Errorf("error getting key type from device sig info: %w", err)
	}
	var rsaBits int
	if keyType == protocol.Rsa2048RestrKeyType || keyType == protocol.RsaPkcsKeyType || keyType == protocol.RsaPssKeyType {
		switch hello.SigInfoA.Type.HashFunc() {
		case crypto.SHA256:
			rsaBits = 2048
		case crypto.SHA384:
			rsaBits = 3072
		}
	}
	ownerKey, ownerPublicKey, err := s.ownerKey(ctx, keyType, ov.Header.Val.ManufacturerKey.Encoding, rsaBits)
	if err != nil {
		return nil, err
	}

	expectedCUPHOwnerKey, err := ov.OwnerPublicKey()
	if err != nil {
		return nil, fmt.Errorf("error parsing owner public key from voucher: %w", err)
	}
	var delegateKey crypto.Signer
	var delegateChain *protocol.PublicKey

	if s.OnboardDelegate != "" {
		OnboardDelegateName := strings.ReplaceAll(s.OnboardDelegate, "=", (*ownerPublicKey).Type.KeyString())
		dk, chain, err := s.DelegateKeys.DelegateKey(OnboardDelegateName)
		if err != nil {
			return nil, fmt.Errorf("delegate chain %q not found: %w", OnboardDelegateName, err)
		}
		// Get key type from the delegate certificate's public key (leaf cert)
		delegateKeyType, err := protocol.KeyTypeFromPublicKey(chain[0].PublicKey)
		if err != nil {
			return nil, fmt.Errorf("error determining delegate key type: %w", err)
		}
		delegateChain, err = protocol.NewPublicKey(delegateKeyType, chain, false)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal delegate chain in proveOVHdr: %w", err)
		}
		//chain,err1 := delegatePublicKey.Chain()

		// Verify delegate chain is signed by owner and has any onboard permission
		err = VerifyDelegateChain(chain, &expectedCUPHOwnerKey, nil)
		if err != nil {
			return nil, fmt.Errorf("cert chain verification failed: %w", err)
		}
		// Check for any fdo-ekt-permit-onboard-* permission
		if !DelegateCanOnboard(chain) {
			return nil, fmt.Errorf("delegate certificate does not have any fdo-ekt-permit-onboard-* permission")
		}

		// Sign with delegate key instead of owner key (below)
		ownerKey = dk
		delegateKey = dk
	} else {
		// Make sure the server's ("owner") key matches the one in the voucher
		if !ownerKey.Public().(interface{ Equal(crypto.PublicKey) bool }).Equal(expectedCUPHOwnerKey) {
			return nil, fmt.Errorf("owner key to be used for CUPHOwnerKey does not match voucher")
		}
	}

	// Verify voucher using custom configuration option.
	if s.VerifyVoucher != nil {
		if err := s.VerifyVoucher(ctx, *ov); err != nil {
			captureErr(ctx, protocol.ResourceNotFound, "")
			return nil, fmt.Errorf("VerifyVoucher: %w", err)
		}
	} else if numEntries == 0 {
		captureErr(ctx, protocol.ResourceNotFound, "")
		return nil, fmt.Errorf("error retrieving voucher for device %x: %w", hello.GUID, ErrNotFound)
	}

	// Hash request
	helloDeviceHash := protocol.Hash{Algorithm: ov.Header.Val.CertChainHash.Algorithm}
	helloDeviceHasher := helloDeviceHash.Algorithm.HashFunc().New()
	_, _ = helloDeviceHasher.Write(rawHello)
	helloDeviceHash.Value = helloDeviceHasher.Sum(nil)

	// Generate nonce for ProveDevice
	var proveDeviceNonce protocol.Nonce
	if _, err := rand.Read(proveDeviceNonce[:]); err != nil {
		return nil, fmt.Errorf("error generating new nonce for TO2.ProveOVHdr response: %w", err)
	}
	if err := s.Session.SetProveDeviceNonce(ctx, proveDeviceNonce); err != nil {
		return nil, fmt.Errorf("error storing nonce for later use in TO2.Done: %w", err)
	}

	// Begin key exchange
	if !hello.KexSuiteName.Valid(hello.SigInfoA.Type, expectedCUPHOwnerKey) {
		return nil, fmt.Errorf(
			"key exchange %s is invalid for the device and owner attestation types",
			hello.KexSuiteName,
		)
	}
	if !kex.Available(hello.KexSuiteName, hello.CipherSuite) {
		return nil, fmt.Errorf("unsupported key exchange/cipher suite")
	}
	sess := hello.KexSuiteName.New(nil, hello.CipherSuite)
	rsaOwnerPublicKey, _ := expectedCUPHOwnerKey.(*rsa.PublicKey)
	xA, err := sess.Parameter(rand.Reader, rsaOwnerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("error generating client key exchange parameter: %w", err)
	}
	if err := s.Session.SetXSession(ctx, hello.KexSuiteName, sess); err != nil {
		clear(xA)
		return nil, fmt.Errorf("error storing key exchange session: %w", err)
	}

	// Send begin proof
	if mfgKeyType := ov.Header.Val.ManufacturerKey.Type; keyType != mfgKeyType {
		clear(xA)
		return nil, fmt.Errorf("device sig info has key type %q, must be %q to match manufacturer key", keyType, mfgKeyType)
	}

	var header = cose.Header{
		Unprotected: map[cose.Label]any{
			to2NonceClaim:       proveDeviceNonce,
			to2OwnerPubKeyClaim: ownerPublicKey,
		},
	}

	if delegateKey != nil {
		header.Unprotected[to2DelegateClaim] = delegateChain //delegatePublicKey
	}
	s1 := cose.Sign1[ovhProof, []byte]{
		Header: header,
		Payload: cbor.NewByteWrap(ovhProof{
			OVH:                 ov.Header,
			NumOVEntries:        uint8(numEntries),
			OVHHmac:             ov.Hmac,
			NonceTO2ProveOV:     hello.NonceTO2ProveOV,
			SigInfoB:            hello.SigInfoA,
			KeyExchangeA:        xA,
			HelloDeviceHash:     helloDeviceHash,
			MaxOwnerMessageSize: 65535, // TODO: Make this configurable and match handler config
		}),
	}
	if err := s1.Sign(ownerKey, nil, nil, opts); err != nil {
		clear(xA)
		return nil, fmt.Errorf("error signing TO2.ProveOVHdr payload: %w", err)
	}

	// The lifetime of xA is until the transport has marshaled and sent the proof. Therefore, the
	// best option for clearing the secret is to set a finalizer (unfortunately).
	proof := s1.Tag()
	runtime.SetFinalizer(proof, func(proof *cose.Sign1Tag[ovhProof, []byte]) {
		clear(proof.Payload.Val.KeyExchangeA)
	})
	return proof, nil
}

func (s *TO2Server) ownerKey(ctx context.Context, keyType protocol.KeyType, keyEncoding protocol.KeyEncoding, rsaBits int) (crypto.Signer, *protocol.PublicKey, error) {
	key, chain, err := s.OwnerKeys.OwnerKey(ctx, keyType, rsaBits)
	if errors.Is(err, ErrNotFound) {
		return nil, nil, fmt.Errorf("owner key type %s not supported", keyType)
	} else if err != nil {
		return nil, nil, fmt.Errorf("error getting owner key [type=%s]: %w", keyType, err)
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
		return nil, nil, fmt.Errorf("unsupported key encoding: %s", keyEncoding)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("error with owner public key: %w", err)
	}

	return key, pubkey, nil
}

// GetOVNextEntry(62) -> OVNextEntry(63)
func sendNextOVEntry(ctx context.Context, transport Transport, i int) (*cose.Sign1Tag[VoucherEntryPayload, []byte], error) {
	// Define request structure
	msg := struct {
		OVEntryNum int
	}{
		OVEntryNum: i,
	}

	// Make request
	typ, resp, err := transport.Send(ctx, protocol.TO2GetOVNextEntryMsgType, msg, nil)
	if err != nil {
		return nil, fmt.Errorf("TO2.GetOVNextEntry: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case protocol.TO2OVNextEntryMsgType:
		captureMsgType(ctx, typ)
		var ovNextEntry ovEntry
		if err := cbor.NewDecoder(resp).Decode(&ovNextEntry); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return nil, fmt.Errorf("error parsing TO2.OVNextEntry contents: %w", err)
		}
		if j := ovNextEntry.OVEntryNum; j != i {
			return nil, fmt.Errorf("TO2.OVNextEntry message contained entry number %d, requested %d", j, i)
		}
		return &ovNextEntry.OVEntry, nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return nil, fmt.Errorf("error parsing error message contents of TO2.GetOVNextEntry response: %w", err)
		}
		return nil, fmt.Errorf("error received from TO2.GetOVNextEntry request: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		return nil, fmt.Errorf("unexpected message type for response to TO2.GetOVNextEntry: %d", typ)
	}
}

type ovEntry struct {
	OVEntryNum int
	OVEntry    cose.Sign1Tag[VoucherEntryPayload, []byte]
}

// GetOVNextEntry(62) -> OVNextEntry(63)
func (s *TO2Server) ovNextEntry(ctx context.Context, msg io.Reader) (*ovEntry, error) {
	// Parse request
	var nextEntry struct {
		OVEntryNum int
	}
	if err := cbor.NewDecoder(msg).Decode(&nextEntry); err != nil {
		return nil, fmt.Errorf("error decoding TO2.GetOVNextEntry request: %w", err)
	}

	// Retrieve voucher
	guid, err := s.Session.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving associated device GUID of proof session: %w", err)
	}
	ov, err := s.Vouchers.Voucher(ctx, guid)
	if err != nil || len(ov.Entries) == 0 {
		return nil, fmt.Errorf("error retrieving voucher for device %x: %w", guid, err)
	}

	// Return entry
	if len(ov.Entries) < nextEntry.OVEntryNum {
		return nil, fmt.Errorf("invalid ownership voucher entry index %d", nextEntry.OVEntryNum)
	}
	return &ovEntry{
		OVEntryNum: nextEntry.OVEntryNum,
		OVEntry:    ov.Entries[nextEntry.OVEntryNum],
	}, nil
}

// ProveDevice(64) -> SetupDevice(65)
func proveDevice(ctx context.Context, transport Transport, proveDeviceNonce protocol.Nonce, ownerPublicKey crypto.PublicKey, originalOwnerKey crypto.PublicKey, sess kex.Session, c *TO2Config) (protocol.Nonce, *VoucherHeader, error) {
	// Generate a new nonce
	var setupDeviceNonce protocol.Nonce
	if _, err := rand.Read(setupDeviceNonce[:]); err != nil {
		return protocol.Nonce{}, nil, fmt.Errorf("error generating new nonce for TO2.ProveDevice request: %w", err)
	}

	// Define request structure
	rsaOwnerPublicKey, _ := ownerPublicKey.(*rsa.PublicKey)
	xB, err := sess.Parameter(rand.Reader, rsaOwnerPublicKey)
	if err != nil {
		return protocol.Nonce{}, nil, fmt.Errorf("error generating key exchange session parameters: %w", err)
	}
	defer clear(xB)
	token := cose.Sign1[eatoken, []byte]{
		Header: cose.Header{
			Unprotected: map[cose.Label]any{
				eatUnprotectedNonceClaim: setupDeviceNonce,
			},
		},
		Payload: cbor.NewByteWrap(newEAT(c.Cred.GUID, proveDeviceNonce, struct {
			KeyExchangeB []byte
		}{
			KeyExchangeB: xB,
		}, nil)),
	}
	opts, err := signOptsFor(c.Key, c.PSS)
	if err != nil {
		return protocol.Nonce{}, nil, fmt.Errorf("error determining signing options for TO2.ProveDevice: %w", err)
	}
	if err := token.Sign(c.Key, nil, nil, opts); err != nil {
		return protocol.Nonce{}, nil, fmt.Errorf("error signing EAT payload for TO2.ProveDevice: %w", err)
	}
	msg := token.Tag()

	// Make request
	typ, resp, err := transport.Send(ctx, protocol.TO2ProveDeviceMsgType, msg, kex.DecryptOnly{Session: sess})
	if err != nil {
		return protocol.Nonce{}, nil, fmt.Errorf("TO2.ProveDevice: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case protocol.TO2SetupDeviceMsgType:
		captureMsgType(ctx, typ)
		var setupDevice cose.Sign1Tag[deviceSetup, []byte]
		if err := cbor.NewDecoder(resp).Decode(&setupDevice); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return protocol.Nonce{}, nil, fmt.Errorf("error parsing TO2.SetupDevice contents: %w", err)
		}
		if setupDevice.Payload.Val.NonceTO2SetupDv != setupDeviceNonce {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			return protocol.Nonce{}, nil, fmt.Errorf("nonce in TO2.SetupDevice did not match nonce sent in TO2.ProveDevice")
		}
		replacementOVH := &VoucherHeader{
			GUID:            setupDevice.Payload.Val.GUID,
			RvInfo:          setupDevice.Payload.Val.RendezvousInfo,
			ManufacturerKey: setupDevice.Payload.Val.Owner2Key,
		}

		// If we are using Delgate, sinve ownerPublicKey is now the Delegate key,
		// we need to reset it back to what was in the OV.
		if credReuse, err := reuseCredentials(ctx, replacementOVH, originalOwnerKey, c); err != nil || credReuse {
			return setupDeviceNonce, nil, err
		}
		return setupDeviceNonce, replacementOVH, nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return protocol.Nonce{}, nil, fmt.Errorf("error parsing error message contents of TO2.ProveDevice response: %w", err)
		}
		return protocol.Nonce{}, nil, fmt.Errorf("error received from TO2.ProveDevice request: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		return protocol.Nonce{}, nil, fmt.Errorf("unexpected message type for response to TO2.ProveDevice: %d", typ)
	}
}

func reuseCredentials(ctx context.Context, replacementOVH *VoucherHeader, ownerPublicKey crypto.PublicKey, c *TO2Config) (bool, error) {
	replacementOwnerPublicKey, err := replacementOVH.ManufacturerKey.Public()
	if err != nil {
		captureErr(ctx, protocol.InvalidMessageErrCode, "")
		return false, fmt.Errorf("owner key in TO2.SetupDevice could not be parsed: %w", err)
	}

	if replacementOVH.GUID != c.Cred.GUID ||
		!reflect.DeepEqual(replacementOVH.RvInfo, c.Cred.RvInfo) ||
		!replacementOwnerPublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(ownerPublicKey) {
		return false, nil
	}
	if !c.AllowCredentialReuse {
		captureErr(ctx, protocol.CredReuseErrCode, "")
		return false, fmt.Errorf("credential reuse is not enabled")
	}
	return true, nil
}

type deviceSetup struct {
	RendezvousInfo  [][]protocol.RvInstruction // RendezvousInfo replacement
	GUID            protocol.GUID              // GUID replacement
	NonceTO2SetupDv protocol.Nonce             // proves freshness of signature
	Owner2Key       protocol.PublicKey         // Replacement for Owner key
}

// ProveDevice(64) -> SetupDevice(65)
//
//nolint:gocyclo // This is very complex validation that is better understood linearly
func (s *TO2Server) setupDevice(ctx context.Context, msg io.Reader) (*cose.Sign1Tag[deviceSetup, []byte], error) {
	// Decode a fully-parsed and raw COSE Sign1. The latter is used for
	// verifying in a more lenient way, as it doesn't require deterministic
	// encoding of CBOR (even though FDO requires this).
	var proof cose.Sign1Tag[cbor.RawBytes, []byte]
	if err := cbor.NewDecoder(msg).Decode(&proof); err != nil {
		return nil, fmt.Errorf("error decoding TO2.ProveDevice request: %w", err)
	}
	var eat eatoken
	if err := cbor.Unmarshal([]byte(proof.Payload.Val), &eat); err != nil {
		return nil, fmt.Errorf("error decoding TO2.ProveDevice request: %w", err)
	}

	// Parse and store SetupDevice nonce
	var setupDeviceNonce protocol.Nonce
	if ok, err := proof.Unprotected.Parse(eatUnprotectedNonceClaim, &setupDeviceNonce); err != nil {
		return nil, fmt.Errorf("error parsing SetupDevice nonce from TO2.ProveDevice request unprotected header: %w", err)
	} else if !ok {
		return nil, fmt.Errorf("TO2.ProveDevice request missing SetupDevice nonce in unprotected headers")
	}
	if err := s.Session.SetSetupDeviceNonce(ctx, setupDeviceNonce); err != nil {
		return nil, fmt.Errorf("error storing SetupDevice nonce from TO2.ProveDevice request: %w", err)
	}

	// Retrieve voucher
	guid, err := s.Session.GUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving associated device GUID of proof session: %w", err)
	}
	ov, err := s.Vouchers.Voucher(ctx, guid)
	if err != nil || len(ov.Entries) == 0 {
		return nil, fmt.Errorf("error retrieving voucher for device %x: %w", guid, err)
	}

	// Verify request signature based on device certificate chain in voucher
	devicePublicKey, err := ov.DevicePublicKey()
	if err != nil {
		return nil, fmt.Errorf("error parsing device public key from ownership voucher: %w", err)
	}
	if ok, err := proof.Verify(devicePublicKey, nil, nil); err != nil {
		return nil, fmt.Errorf("error verifying signature of device EAT: %w", err)
	} else if !ok {
		return nil, fmt.Errorf("device EAT verification failed")
	}

	// Validate EAT contents
	proveDeviceNonce, err := s.Session.ProveDeviceNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving ProveDevice nonce for session: %w", err)
	}
	nonceClaim, ok := eat[eatNonceClaim].([]byte)
	if !ok {
		return nil, fmt.Errorf("missing nonce claim from EAT")
	}
	if !bytes.Equal(nonceClaim, proveDeviceNonce[:]) {
		return nil, fmt.Errorf("nonce claim from EAT does not match ProveDevice nonce")
	}
	ueidClaim, ok := eat[eatUeidClaim].([]byte)
	if !ok {
		return nil, fmt.Errorf("missing UEID claim from EAT")
	}
	if !bytes.Equal(ueidClaim, append([]byte{eatRandUeid}, guid[:]...)) {
		return nil, fmt.Errorf("claim of UEID in EAT does not match the device GUID")
	}
	fdoClaim, ok := eat[eatFdoClaim].([]any)
	if !ok || len(fdoClaim) != 1 {
		return nil, fmt.Errorf("missing FDO claim from EAT")
	}

	// Complete key exchange using EAT FDO claim
	xB, ok := fdoClaim[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid EAT FDO claim: expected one item of type []byte")
	}
	suite, sess, err := s.Session.XSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting associated key exchange session: %w", err)
	}
	defer sess.Destroy()
	mfgKey := ov.Header.Val.ManufacturerKey
	keyType, rsaBits := mfgKey.Type, mfgKey.RsaBits()
	ownerKey, ownerPublicKey, err := s.ownerKey(ctx, keyType, ov.Header.Val.ManufacturerKey.Encoding, rsaBits)
	sessionOwnerKey := ownerKey
	if s.OnboardDelegate != "" {
		OnboardDelegateName := strings.ReplaceAll(s.OnboardDelegate, "=", keyType.KeyString())
		sessionOwnerKey, _, err = s.DelegateKeys.DelegateKey(OnboardDelegateName)
	}
	if err != nil {
		return nil, err
	}

	// For the sake of Session Parameters, must use delegate key
	// But for re-assignment below, must be owner in voucher
	rsaOwnerPrivateKey, _ := sessionOwnerKey.(*rsa.PrivateKey)
	if err := sess.SetParameter(xB, rsaOwnerPrivateKey); err != nil {
		return nil, fmt.Errorf("error completing key exchange: %w", err)
	}
	if err := s.Session.SetXSession(ctx, suite, sess); err != nil {
		return nil, fmt.Errorf("error updating associated key exchange session: %w", err)
	}

	// Get replacement GUID and rendezvous directives
	replacementGUID, replacementRvInfo, err := s.replacementCredential(ctx, ov)
	if err != nil {
		return nil, err
	}

	// Respond with device setup
	s1 := cose.Sign1[deviceSetup, []byte]{
		Payload: cbor.NewByteWrap(deviceSetup{
			RendezvousInfo:  replacementRvInfo,
			GUID:            replacementGUID,
			NonceTO2SetupDv: setupDeviceNonce,
			Owner2Key:       *ownerPublicKey,
		}),
	}
	opts, err := signOptsFor(ownerKey, keyType == protocol.RsaPssKeyType)
	if err != nil {
		return nil, fmt.Errorf("error determining signing options for TO2.SetupDevice message: %w", err)
	}
	if err := s1.Sign(ownerKey, nil, nil, opts); err != nil {
		return nil, fmt.Errorf("error signing TO2.SetupDevice payload: %w", err)
	}
	return s1.Tag(), nil
}

func (s *TO2Server) replacementCredential(ctx context.Context, ov *Voucher) (protocol.GUID, [][]protocol.RvInstruction, error) {
	if s.ReuseCredential != nil {
		reuse, err := s.ReuseCredential(ctx, *ov)
		if err != nil {
			return protocol.GUID{}, nil, fmt.Errorf("error checking if credential reuse should be performed for device based on voucher: %w", err)
		}
		if reuse {
			return ov.Header.Val.GUID, ov.Header.Val.RvInfo, nil
		}
	}

	var replacementGUID protocol.GUID
	if _, err := rand.Read(replacementGUID[:]); err != nil {
		return protocol.GUID{}, nil, fmt.Errorf("error generating replacement GUID for device: %w", err)
	}
	if err := s.Session.SetReplacementGUID(ctx, replacementGUID); err != nil {
		return protocol.GUID{}, nil, fmt.Errorf("error storing replacement GUID for device: %w", err)
	}
	replacementRvInfo, err := s.RvInfo(ctx, *ov)
	if err != nil {
		return protocol.GUID{}, nil, fmt.Errorf("error determining rendezvous info for device: %w", err)
	}
	if err := s.Session.SetRvInfo(ctx, replacementRvInfo); err != nil {
		return protocol.GUID{}, nil, fmt.Errorf("error storing rendezvous info for device: %w", err)
	}
	return replacementGUID, replacementRvInfo, nil
}

type deviceServiceInfoReady struct {
	Hmac                    *protocol.Hmac
	MaxOwnerServiceInfoSize *uint16 // maximum size service info that Device can receive
}

// DeviceServiceInfoReady(66) -> OwnerServiceInfoReady(67)
func sendReadyServiceInfo(ctx context.Context, transport Transport, alg protocol.HashAlg, replacementOVH *VoucherHeader, sess kex.Session, c *TO2Config) (maxDeviceServiceInfoSiz uint16, err error) {
	// Calculate the new OVH HMac similar to DI.SetHMAC
	var h hash.Hash
	switch alg {
	case protocol.Sha256Hash, protocol.HmacSha256Hash:
		h = c.HmacSha256
	case protocol.Sha384Hash, protocol.HmacSha384Hash:
		h = c.HmacSha384
	default:
		panic("only SHA256 and SHA384 are supported in FDO")
	}
	var hmac *protocol.Hash
	if replacementOVH != nil {
		replacementHmac, err := hmacHash(h, replacementOVH)
		if err != nil {
			return 0, fmt.Errorf("error computing HMAC of ownership voucher header: %w", err)
		}
		hmac = &replacementHmac
	}

	// Define request structure
	msg := deviceServiceInfoReady{
		Hmac:                    hmac,
		MaxOwnerServiceInfoSize: &c.MaxServiceInfoSizeReceive,
	}

	// Make request
	typ, resp, err := transport.Send(ctx, protocol.TO2DeviceServiceInfoReadyMsgType, msg, sess)
	if err != nil {
		return 0, fmt.Errorf("TO2.DeviceServiceInfoReady: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case protocol.TO2OwnerServiceInfoReadyMsgType:
		captureMsgType(ctx, typ)
		var ready ownerServiceInfoReady
		if err := cbor.NewDecoder(resp).Decode(&ready); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return 0, fmt.Errorf("error parsing TO2.OwnerServiceInfoReady contents: %w", err)
		}
		if ready.MaxDeviceServiceInfoSize == nil {
			return serviceinfo.DefaultMTU, nil
		}
		return *ready.MaxDeviceServiceInfoSize, nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return 0, fmt.Errorf("error parsing error message contents of TO2.OwnerServiceInfoReady response: %w", err)
		}
		return 0, fmt.Errorf("error received from TO2.DeviceServiceInfoReady request: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		return 0, fmt.Errorf("unexpected message type for response to TO2.DeviceServiceInfoReady: %d", typ)
	}
}

type ownerServiceInfoReady struct {
	MaxDeviceServiceInfoSize *uint16 // maximum size service info that Owner can receive
}

// DeviceServiceInfoReady(66) -> OwnerServiceInfoReady(67)
func (s *TO2Server) ownerServiceInfoReady(ctx context.Context, msg io.Reader) (*ownerServiceInfoReady, error) {
	// Parse request
	var deviceReady deviceServiceInfoReady
	if err := cbor.NewDecoder(msg).Decode(&deviceReady); err != nil {
		return nil, fmt.Errorf("error decoding TO2.DeviceServiceInfoReady request: %w", err)
	}

	// Set send MTU
	mtu := uint16(serviceinfo.DefaultMTU)
	if deviceReady.MaxOwnerServiceInfoSize != nil {
		mtu = *deviceReady.MaxOwnerServiceInfoSize
	}
	if err := s.Session.SetMTU(ctx, mtu); err != nil {
		return nil, fmt.Errorf("error storing max service info size to send to device: %w", err)
	}

	// Store the new HMAC if not using the Credential Reuse Protocol
	if deviceReady.Hmac != nil {
		if err := s.Session.SetReplacementHmac(ctx, *deviceReady.Hmac); err != nil {
			return nil, fmt.Errorf("error storing replacement voucher HMAC for device: %w", err)
		}
	}

	// Send response
	ownerReady := new(ownerServiceInfoReady)
	if s.MaxDeviceServiceInfoSize != nil {
		guid, err := s.Session.GUID(ctx)
		if err != nil {
			return nil, fmt.Errorf("error retrieving associated device GUID of proof session: %w", err)
		}
		ov, err := s.Vouchers.Voucher(ctx, guid)
		if err != nil || len(ov.Entries) == 0 {
			return nil, fmt.Errorf("error retrieving voucher for device %x: %w", guid, err)
		}
		size, err := s.MaxDeviceServiceInfoSize(ctx, *ov)
		if err != nil {
			return nil, fmt.Errorf("error getting service info size limit for device %x: %w", ov.Header.Val.GUID, err)
		}
		ownerReady.MaxDeviceServiceInfoSize = &size
	}
	return ownerReady, nil
}

type doneMsg struct {
	NonceTO2ProveDv protocol.Nonce
}

type done2Msg struct {
	NonceTO2SetupDv protocol.Nonce
}

// loop[DeviceServiceInfo(68) -> OwnerServiceInfo(69)]
func exchangeServiceInfo(ctx context.Context,
	transport Transport,
	proveDvNonce, setupDvNonce protocol.Nonce,
	mtu uint16,
	initInfo *serviceinfo.ChunkReader,
	sess kex.Session,
	c *TO2Config,
) error {
	// Shadow context to ensure that any goroutines still running after this
	// function exits will shutdown
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Subtract 3 bytes from MTU to account for a CBOR header indicating "array
	// of 256-65535 items" and 2 more bytes for "array of two" plus the first
	// item indicating "IsMoreServiceInfo"
	mtu -= 5

	// 1000 service info buffered in and out means up to ~1MB of data for
	// the default MTU. If both queues fill, the device will deadlock. This
	// should only happen for a poorly behaved owner service.
	ownerInfo, ownerInfoIn := serviceinfo.NewChunkInPipe(1000)

	// Send initial device info (devmod)
	totalRounds, done, err := exchangeServiceInfoRound(ctx, transport, mtu, initInfo, ownerInfoIn, sess)
	_ = initInfo.Close()
	if err != nil {
		return fmt.Errorf("error sending devmod: %w", err)
	}
	if err := ownerInfoIn.Close(); err != nil {
		return fmt.Errorf("error closing owner service info -> device module pipe: %w", err)
	}
	if totalRounds >= 1_000_000 {
		return fmt.Errorf("exceeded 1e6 rounds of service info exchange")
	}
	if done {
		return sendDone(ctx, transport, proveDvNonce, setupDvNonce, sess)
	}

	// Track active modules
	modules := deviceModuleMap{modules: c.DeviceModules, active: make(map[string]bool)}
	defer stopDevicePlugins(&modules)

	var prevModuleName string
	for {
		// Handle received owner service info and produce zero or more service
		// info to send. Each service info grouping is automatically chunked
		// and if it exceeds the MTU will have IsMoreServiceInfo=true.
		//
		// 1000 service info buffered in and out means up to ~1MB of data for
		// the default MTU. If both queues fill, the device will deadlock. This
		// should only happen for a poorly behaved owner module.
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
		rounds, done, err := exchangeServiceInfoRound(ctx, transport, mtu, deviceInfo, ownerInfoIn, sess)
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
			return sendDone(ctx, transport, proveDvNonce, setupDvNonce, sess)
		}

		// If there is no ServiceInfo to send and the last owner response did
		// not contain any service info, then this is just a regular interval
		// check to see if owner IsDone. In this case, add a delay to avoid
		// clobbering the owner service.
		//
		// TODO: Wait a few seconds if no service info was sent or received in
		// the last round.

		select {
		case <-ctx.Done():
			return ctx.Err()
		case prevModuleName = <-moduleName:
			ownerInfo = nextOwnerInfo
		}
	}
}

func discardDeviceInfo(deviceInfo *serviceinfo.ChunkReader) {
	for {
		kv, err := deviceInfo.ReadChunk(math.MaxUint16)
		if err != nil && !errors.Is(err, io.EOF) {
			slog.Warn("reading device service info for discard", "error", err)
		}
		if err != nil {
			return
		}
		prettyValue, err := cdn.FromCBOR(kv.Val)
		if err != nil {
			prettyValue = "h'" + hex.EncodeToString(kv.Val) + "'"
		}
		slog.Warn("discarding device service info message because owner sent IsDone",
			"name", kv.Key, "value", prettyValue,
		)
	}
}

// Done(70) -> Done2(71)
func sendDone(ctx context.Context, transport Transport, proveDvNonce, setupDvNonce protocol.Nonce, sess kex.Session) error {
	// Finalize TO2 by sending Done message
	msg := doneMsg{
		NonceTO2ProveDv: proveDvNonce,
	}

	// Make request
	typ, resp, err := transport.Send(ctx, protocol.TO2DoneMsgType, msg, sess)
	if err != nil {
		return fmt.Errorf("TO2.Done: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case protocol.TO2Done2MsgType:
		captureMsgType(ctx, typ)
		var done2 done2Msg
		if err := cbor.NewDecoder(resp).Decode(&done2); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return fmt.Errorf("error parsing TO2.Done2 contents: %w", err)
		}
		if done2.NonceTO2SetupDv != setupDvNonce {
			captureErr(ctx, protocol.InvalidMessageErrCode, "")
			return fmt.Errorf("nonce received in TO2.Done2 message did not match nonce received in TO2.SetupDevice")
		}
		return nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return fmt.Errorf("error parsing error message contents of TO2.Done response: %w", err)
		}
		return fmt.Errorf("error received from TO2.Done request: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		return fmt.Errorf("unexpected message type for response to TO2.Done: %d", typ)
	}
}

type deviceServiceInfo struct {
	IsMoreServiceInfo bool
	ServiceInfo       []*serviceinfo.KV
}

func (info deviceServiceInfo) String() string {
	return fmt.Sprintf("More: %t, Info: %v",
		info.IsMoreServiceInfo, info.ServiceInfo)
}

type ownerServiceInfo struct {
	IsMoreServiceInfo bool
	IsDone            bool
	ServiceInfo       []*serviceinfo.KV
}

func (info ownerServiceInfo) String() string {
	return fmt.Sprintf("More: %t, Done: %t, Info: %v",
		info.IsMoreServiceInfo, info.IsDone, info.ServiceInfo)
}

// Perform one iteration of send all device service info (may be across
// multiple FDO messages) and receive all owner service info (same applies).
//
// TODO: Track current round number and stop at 1e6 rather than only checking
// if exceeded after this recursive function completes.
func exchangeServiceInfoRound(ctx context.Context, transport Transport, mtu uint16,
	r *serviceinfo.ChunkReader, w *serviceinfo.ChunkWriter, sess kex.Session,
) (int, bool, error) {
	// Create DeviceServiceInfo request structure
	var msg deviceServiceInfo
	maxRead := mtu
	for {
		chunk, err := r.ReadChunk(maxRead)
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, serviceinfo.ErrSizeTooSmall) {
			msg.IsMoreServiceInfo = true
			if maxRead == mtu {
				msg.IsMoreServiceInfo = false // likely due to a yield... but also could be a malicious large key?
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
	ownerServiceInfo, err := sendDeviceServiceInfo(ctx, transport, msg, sess)
	if err != nil {
		return 0, false, err
	}

	// Receive all owner service info
	for _, kv := range ownerServiceInfo.ServiceInfo {
		if err := w.WriteChunk(kv); err != nil {
			return 0, false, fmt.Errorf("error piping owner service info to device module: %w", err)
		}
	}

	// Recurse when there's more service info to send from device or receive
	// from owner without allowing the other side to respond
	if msg.IsMoreServiceInfo || ownerServiceInfo.IsMoreServiceInfo {
		rounds, done, err := exchangeServiceInfoRound(ctx, transport, mtu, r, w, sess)
		return rounds + 1, done, err
	}

	return 1, ownerServiceInfo.IsDone, nil
}

// DeviceServiceInfo(68) -> OwnerServiceInfo(69)
func sendDeviceServiceInfo(ctx context.Context, transport Transport, msg deviceServiceInfo, sess kex.Session) (*ownerServiceInfo, error) {
	// Make request
	typ, resp, err := transport.Send(ctx, protocol.TO2DeviceServiceInfoMsgType, msg, sess)
	if err != nil {
		return nil, fmt.Errorf("TO2.DeviceServiceInfo: %w", err)
	}
	defer func() { _ = resp.Close() }()

	// Parse response
	switch typ {
	case protocol.TO2OwnerServiceInfoMsgType:
		captureMsgType(ctx, typ)
		var ownerServiceInfo ownerServiceInfo
		if err := cbor.NewDecoder(resp).Decode(&ownerServiceInfo); err != nil {
			captureErr(ctx, protocol.MessageBodyErrCode, "")
			return nil, fmt.Errorf("error parsing TO2.OwnerServiceInfo contents: %w", err)
		}
		return &ownerServiceInfo, nil

	case protocol.ErrorMsgType:
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(resp).Decode(&errMsg); err != nil {
			return nil, fmt.Errorf("error parsing error message contents of TO2.OwnerServiceInfo response: %w", err)
		}
		return nil, fmt.Errorf("error received from TO2.DeviceServiceInfo request: %w", errMsg)

	default:
		captureErr(ctx, protocol.MessageBodyErrCode, "")
		return nil, fmt.Errorf("unexpected message type for response to TO2.DeviceServiceInfo: %d", typ)
	}
}

// DeviceServiceInfo(68) -> OwnerServiceInfo(69)
func (s *TO2Server) ownerServiceInfo(ctx context.Context, msg io.Reader) (*ownerServiceInfo, error) { //nolint:gocyclo
	// Parse request
	var deviceInfo deviceServiceInfo
	if err := cbor.NewDecoder(msg).Decode(&deviceInfo); err != nil {
		return nil, fmt.Errorf("error decoding TO2.DeviceServiceInfo request: %w", err)
	}

	// Get next owner service info module
	var moduleName string
	var module serviceinfo.OwnerModule
	if devmod, modules, complete, err := s.Session.Devmod(ctx); errors.Is(err, ErrNotFound) || (err == nil && !complete) {
		moduleName, module = "devmod", &devmodOwnerModule{
			Devmod:  devmod,
			Modules: modules,
		}
	} else if err != nil {
		return nil, fmt.Errorf("error getting devmod state: %w", err)
	} else {
		var err error
		moduleName, module, err = s.Modules.Module(ctx)
		if err != nil {
			return nil, fmt.Errorf("error getting current service info module: %w", err)
		}

		// Set the context values that an FSIM expects
		guid, err := s.Session.GUID(ctx)
		if err != nil {
			return nil, fmt.Errorf("error retrieving associated device GUID of proof session: %w", err)
		}
		ov, err := s.Vouchers.Voucher(ctx, guid)
		if err != nil {
			return nil, fmt.Errorf("error retrieving voucher for device %x: %w", guid, err)
		}
		var deviceCertChain []*x509.Certificate
		if ov.CertChain != nil {
			deviceCertChain = make([]*x509.Certificate, len(*ov.CertChain))
			for i, cert := range *ov.CertChain {
				deviceCertChain[i] = (*x509.Certificate)(cert)
			}
		}
		ctx = serviceinfo.Context(ctx, &devmod, deviceCertChain)
	}

	// Handle data with owner module
	unchunked, unchunker := serviceinfo.NewChunkInPipe(len(deviceInfo.ServiceInfo))
	for _, kv := range deviceInfo.ServiceInfo {
		if err := unchunker.WriteChunk(kv); err != nil {
			return nil, fmt.Errorf("error unchunking received device service info: write: %w", err)
		}
	}
	if err := unchunker.Close(); err != nil {
		return nil, fmt.Errorf("error unchunking received device service info: close: %w", err)
	}
	for {
		key, messageBody, ok := unchunked.NextServiceInfo()
		if !ok {
			break
		}
		moduleName, messageName, _ := strings.Cut(key, ":")
		if err := module.HandleInfo(ctx, messageName, messageBody); err != nil {
			return nil, fmt.Errorf("error handling device service info %q: %w", key, err)
		}
		if n, err := io.Copy(io.Discard, messageBody); err != nil {
			return nil, err
		} else if n > 0 {
			return nil, fmt.Errorf(
				"owner module did not read full body of message '%s:%s'",
				moduleName, messageName)
		}
		if err := messageBody.Close(); err != nil {
			return nil, fmt.Errorf("error closing unchunked message body for %q: %w", key, err)
		}
	}

	// Save devmod state. All devmod messages are "sent by the Device in the
	// first Device ServiceInfo" but IsMoreServiceInfo may allow it to be sent
	// over multiple network roundtrips.
	if devmod, ok := module.(*devmodOwnerModule); ok {
		if err := s.Session.SetDevmod(ctx, devmod.Devmod, devmod.Modules, false); err != nil {
			return nil, fmt.Errorf("error storing devmod state: %w", err)
		}
	}

	// Allow owner module to produce data unless blocked by device
	if !deviceInfo.IsMoreServiceInfo {
		return s.produceOwnerServiceInfo(ctx, moduleName, module)
	}

	// Store the current module state
	if devmod, ok := module.(*devmodOwnerModule); ok {
		if err := s.Session.SetDevmod(ctx, devmod.Devmod, devmod.Modules, false); err != nil {
			return nil, fmt.Errorf("error storing devmod state: %w", err)
		}
	}
	if modules, ok := s.Modules.(serviceinfo.ModulePersister); ok {
		if err := modules.PersistModule(ctx, moduleName, module); err != nil {
			return nil, fmt.Errorf("error persisting service info module %q state: %w", moduleName, err)
		}
	}

	return &ownerServiceInfo{
		IsMoreServiceInfo: false,
		IsDone:            false,
		ServiceInfo:       nil,
	}, nil
}

// Allow owner module to produce data
func (s *TO2Server) produceOwnerServiceInfo(ctx context.Context, moduleName string, module serviceinfo.OwnerModule) (*ownerServiceInfo, error) {
	mtu, err := s.Session.MTU(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting max device service info size: %w", err)
	}

	// Get service info produced by the module
	producer := serviceinfo.NewProducer(moduleName, mtu)
	explicitBlock, complete, err := module.ProduceInfo(ctx, producer)
	if err != nil {
		return nil, fmt.Errorf("error producing owner service info from module: %w", err)
	}
	if explicitBlock && complete {
		slog.Warn("service info module completed but indicated that it had more service info to send", "module", moduleName)
		explicitBlock = false
	}
	serviceInfo := producer.ServiceInfo()
	if size := serviceinfo.ArraySizeCBOR(serviceInfo); size > int64(mtu) {
		return nil, fmt.Errorf("owner service info module produced service info exceeding the MTU=%d - 3 (message overhead), size=%d", mtu, size)
	}

	// Store the current module state
	if devmod, ok := module.(*devmodOwnerModule); ok {
		if err := s.Session.SetDevmod(ctx, devmod.Devmod, devmod.Modules, complete); err != nil {
			return nil, fmt.Errorf("error storing devmod state: %w", err)
		}
	}
	if modules, ok := s.Modules.(serviceinfo.ModulePersister); ok {
		if err := modules.PersistModule(ctx, moduleName, module); err != nil {
			return nil, fmt.Errorf("error persisting service info module %q state: %w", moduleName, err)
		}
	}

	// Progress the module state machine when the module completes
	allModulesDone := false
	if complete {
		// Cleanup current module
		if plugin, ok := module.(plugin.Module); ok {
			stopOwnerPlugin(ctx, moduleName, plugin)
		}

		// Find out if there will be more modules
		moreModules, err := s.Modules.NextModule(ctx)
		if err != nil {
			return nil, fmt.Errorf("error progressing service info module %q state: %w", moduleName, err)
		}
		allModulesDone = !moreModules
	}

	// Return chunked data
	return &ownerServiceInfo{
		IsMoreServiceInfo: explicitBlock,
		IsDone:            allModulesDone,
		ServiceInfo:       serviceInfo,
	}, nil
}

// Done(70) -> Done2(71)
func (s *TO2Server) to2Done2(ctx context.Context, msg io.Reader) (*done2Msg, error) {
	// Parse request
	var done doneMsg
	if err := cbor.NewDecoder(msg).Decode(&done); err != nil {
		return nil, fmt.Errorf("error decoding TO2.Done request: %w", err)
	}

	// Get session nonces
	proveDeviceNonce, err := s.Session.ProveDeviceNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving ProveDevice nonce for session: %w", err)
	}
	setupDeviceNonce, err := s.Session.SetupDeviceNonce(ctx)
	if err != nil {
		return nil, fmt.Errorf("error retrieving SetupDevice nonce for session: %w", err)
	}

	// Validate request nonce
	if !bytes.Equal(proveDeviceNonce[:], done.NonceTO2ProveDv[:]) {
		return nil, fmt.Errorf("nonce from TO2.ProveDevice did not match TO2.Done")
	}

	// If the Credential Reuse Protocol is being used (replacement HMAC is not
	// found), then immediately complete TO2 without replacing the voucher.
	replacementHmac, err := s.Session.ReplacementHmac(ctx)
	if errors.Is(err, ErrNotFound) {
		return &done2Msg{NonceTO2SetupDv: setupDeviceNonce}, nil
	} else if err != nil {
		return nil, fmt.Errorf("error retrieving replacement Hmac for device: %w", err)
	}

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

	// Respond with nonce
	return &done2Msg{NonceTO2SetupDv: setupDeviceNonce}, nil
}
