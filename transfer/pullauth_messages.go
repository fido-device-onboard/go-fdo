// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package transfer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// NonceSize is the size of nonces used in the PullAuth protocol (16 bytes / 128 bits),
// matching the FDO specification nonce size.
const NonceSize = 16

// ProtocolVersion is the current PullAuth protocol version.
const ProtocolVersion uint = 1

// ContentTypeCBOR is the HTTP Content-Type for PullAuth messages.
const ContentTypeCBOR = "application/cbor"

// Nonce is a 16-byte random value used for freshness in the PullAuth protocol.
//
//	Nonce = bstr .size 16
type Nonce [NonceSize]byte

// GenerateNonce creates a cryptographically random 16-byte nonce.
func GenerateNonce() (Nonce, error) {
	var n Nonce
	if _, err := rand.Read(n[:]); err != nil {
		return n, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return n, nil
}

// CertChain is an X5CHAIN encoded as an array of DER-encoded X.509 certificates,
// root first, leaf last.
//
//	X5CHAIN = [ + bstr ]
type CertChain []*cbor.X509Certificate

// PullAuthHello is the first message in the PullAuth protocol, sent from
// Recipient to Holder.
//
//	PullAuth.Hello = [
//	    OwnerKey:              PublicKey,
//	    DelegateChain:         CertChainOrNull,
//	    NoncePullRecipient_Prep,
//	    ProtocolVersion:       uint
//	]
type PullAuthHello struct {
	OwnerKey        protocol.PublicKey
	DelegateChain   *CertChain // nil encodes as CBOR null
	NonceRecipient  Nonce
	ProtocolVersion uint
}

// HolderInfo contains optional metadata about the Holder, encoded as a CBOR array.
//
//	HolderInfo = [
//	    holder_id:     tstr,
//	    voucher_count: uint,
//	    algorithms:    [ * int ]
//	]
type HolderInfo struct {
	HolderID     string
	VoucherCount uint
	Algorithms   []int
}

// PullAuthChallenge is the response to PullAuth.Hello, sent from Holder to Recipient.
//
//	PullAuth.Challenge = [
//	    SessionId:             bstr,
//	    NoncePullHolder_Prep,
//	    NoncePullRecipient,
//	    HashPullHello:         Hash,
//	    HolderSignature:       bstr,     ;; COSE_Sign1 bytes
//	    HolderInfo:            HolderInfoOrNull
//	]
type PullAuthChallenge struct {
	SessionID       []byte
	NonceHolder     Nonce
	NonceRecipient  Nonce         // echo of Recipient's nonce from Hello
	HashHello       protocol.Hash // hash of CBOR-encoded PullAuth.Hello body
	HolderSignature []byte        // COSE_Sign1 encoded bytes
	HolderInfo      *HolderInfo   // nil encodes as CBOR null
}

// PullAuthChallengeSignedPayload is the CBOR structure signed by the Holder
// inside the HolderSignature COSE_Sign1.
//
//	PullAuthChallengeSignedPayload = [
//	    "PullAuth.Challenge",
//	    NoncePullRecipient,
//	    NoncePullHolder_Prep,
//	    HashPullHello: Hash,
//	    OwnerKey: PublicKey
//	]
type PullAuthChallengeSignedPayload struct {
	TypeTag        string // always "PullAuth.Challenge"
	NonceRecipient Nonce
	NonceHolder    Nonce
	HashHello      protocol.Hash
	OwnerKey       protocol.PublicKey
}

// PullAuthProve is the second request message, sent from Recipient to Holder.
//
//	PullAuth.Prove = [
//	    SessionId:             bstr,
//	    NoncePullHolder,
//	    HashPullChallenge:     Hash,
//	    RecipientSignature:    bstr      ;; COSE_Sign1 encoded bytes
//	]
type PullAuthProve struct {
	SessionID          []byte
	NonceHolder        Nonce         // echo of Holder's nonce from Challenge
	HashChallenge      protocol.Hash // hash of CBOR-encoded PullAuth.Challenge body
	RecipientSignature []byte        // COSE_Sign1 encoded bytes
}

// PullAuthProveSignedPayload is the CBOR structure signed by the Recipient
// inside the RecipientSignature COSE_Sign1.
//
//	PullAuthProveSignedPayload = [
//	    "PullAuth.Prove",
//	    NoncePullHolder,
//	    NoncePullRecipient,
//	    HashPullChallenge: Hash,
//	    OwnerKey: PublicKey
//	]
type PullAuthProveSignedPayload struct {
	TypeTag        string // always "PullAuth.Prove"
	NonceHolder    Nonce
	NonceRecipient Nonce
	HashChallenge  protocol.Hash
	OwnerKey       protocol.PublicKey
}

// PullAuthResult is the final response from Holder to Recipient after
// successful authentication.
//
//	PullAuth.Result = [
//	    Status:                tstr,
//	    SessionToken:          tstr,
//	    TokenExpiresAt:        uint,
//	    OwnerKeyFingerprint:   bstr,
//	    VoucherCount:          uint    ;; 0 if unknown
//	]
type PullAuthResult struct {
	Status              string
	SessionToken        string
	TokenExpiresAt      uint64
	OwnerKeyFingerprint []byte
	VoucherCount        uint
}

// StatusAuthenticated is the success status value in PullAuth.Result.
const StatusAuthenticated = "authenticated"

// HashCBOR computes a hash of the CBOR-encoded value using the specified algorithm.
// Because CBOR encoding is deterministic, this produces unambiguous hashes.
func HashCBOR(alg protocol.HashAlg, val any) (protocol.Hash, error) {
	data, err := cbor.Marshal(val)
	if err != nil {
		return protocol.Hash{}, fmt.Errorf("failed to CBOR-encode for hashing: %w", err)
	}
	return HashBytes(alg, data), nil
}

// HashBytes computes a hash of raw bytes using the specified algorithm.
func HashBytes(alg protocol.HashAlg, data []byte) protocol.Hash {
	switch alg {
	case protocol.Sha256Hash:
		sum := sha256.Sum256(data)
		return protocol.Hash{Algorithm: alg, Value: sum[:]}
	case protocol.Sha384Hash:
		sum := sha512.Sum384(data)
		return protocol.Hash{Algorithm: alg, Value: sum[:]}
	default:
		panic(fmt.Sprintf("unsupported hash algorithm: %d", alg))
	}
}

// SignPayload creates a COSE_Sign1 signature over a CBOR-encoded payload.
// The payload is first CBOR-encoded, then signed using the provided key.
// Set usePSS to true for RSA-PSS signing; false uses PKCS1v15 for RSA keys.
func SignPayload(signer crypto.Signer, usePSS bool, payload any) ([]byte, error) {
	payloadBytes, err := cbor.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to CBOR-encode payload for signing: %w", err)
	}

	var sig cose.Sign1[cbor.RawBytes, []byte]
	sig.Payload = cbor.NewByteWrap(cbor.RawBytes(payloadBytes))

	opts, err := signerOpts(signer, usePSS)
	if err != nil {
		return nil, err
	}

	if err := sig.Sign(signer, nil, nil, opts); err != nil {
		return nil, fmt.Errorf("COSE_Sign1 signing failed: %w", err)
	}

	return cbor.Marshal(sig.Tag())
}

// VerifyPayload verifies a COSE_Sign1 signature and returns the decoded payload.
// The caller must unmarshal the returned bytes into the expected payload type.
func VerifyPayload(key crypto.PublicKey, sigBytes []byte) ([]byte, error) {
	var sig cose.Sign1Tag[cbor.RawBytes, []byte]
	if err := cbor.Unmarshal(sigBytes, &sig); err != nil {
		return nil, fmt.Errorf("failed to decode COSE_Sign1: %w", err)
	}

	ok, err := sig.Untag().Verify(key, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("COSE_Sign1 verification error: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("COSE_Sign1 signature verification failed")
	}

	if sig.Payload == nil {
		return nil, fmt.Errorf("COSE_Sign1 payload is nil")
	}
	return []byte(sig.Payload.Val), nil
}

// signerOpts returns the appropriate crypto.SignerOpts for the given signer's key type.
// This mirrors the unexported signOptsFor in the fdo package.
func signerOpts(signer crypto.Signer, usePSS bool) (crypto.SignerOpts, error) {
	var opts crypto.SignerOpts
	if rsaPub, ok := signer.Public().(*rsa.PublicKey); ok {
		switch rsaPub.Size() {
		case 2048 / 8:
			opts = crypto.SHA256
		case 3072 / 8:
			opts = crypto.SHA384
		default:
			return nil, fmt.Errorf("unsupported RSA key size: %d bits", rsaPub.Size()*8)
		}
		if usePSS {
			opts = &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       opts.(crypto.Hash),
			}
		}
	}
	return opts, nil
}
