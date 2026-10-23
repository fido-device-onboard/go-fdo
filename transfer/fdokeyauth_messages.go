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

// NonceSize is the size of nonces used in the FDOKeyAuth protocol (16 bytes / 128 bits),
// matching the FDO specification nonce size.
const NonceSize = 16

// ProtocolVersion is the current FDOKeyAuth protocol version.
const ProtocolVersion uint = 1

// ContentTypeCBOR is the HTTP Content-Type for FDOKeyAuth messages.
const ContentTypeCBOR = "application/cbor"

// Nonce is a 16-byte random value used for freshness in the FDOKeyAuth protocol.
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

// FDOKeyAuthHello is the first message in the FDOKeyAuth protocol, sent from
// Caller to Server.
//
//	FDOKeyAuth.Hello = [
//	    CallerKey:             PublicKey,
//	    DelegateChain:         CertChainOrNull,
//	    NonceAuthCaller_Prep,
//	    ProtocolVersion:       uint
//	]
type FDOKeyAuthHello struct {
	CallerKey       protocol.PublicKey
	DelegateChain   *CertChain // nil encodes as CBOR null
	NonceCaller     Nonce
	ProtocolVersion uint
}

// ServerInfo contains optional metadata about the Server, encoded as a CBOR map
// with text string keys per the spec:
//
//	ServerInfo = {
//	    ? "server_id":     tstr,
//	    ? "voucher_count": uint,
//	    ? "algorithms":    [ + int ]
//	}
type ServerInfo struct {
	ServerID     string
	VoucherCount uint
	Algorithms   []int
}

// MarshalCBOR encodes ServerInfo as a CBOR map with text string keys.
// Only non-zero fields are included (all fields are optional per spec).
func (h ServerInfo) MarshalCBOR() ([]byte, error) {
	m := make(map[string]any)
	if h.ServerID != "" {
		m["server_id"] = h.ServerID
	}
	if h.VoucherCount > 0 {
		m["voucher_count"] = h.VoucherCount
	}
	if len(h.Algorithms) > 0 {
		m["algorithms"] = h.Algorithms
	}
	return cbor.Marshal(m)
}

// UnmarshalCBOR decodes ServerInfo from a CBOR map with text string keys.
func (h *ServerInfo) UnmarshalCBOR(data []byte) error {
	var m map[string]any
	if err := cbor.Unmarshal(data, &m); err != nil {
		return err
	}
	if v, ok := m["server_id"]; ok {
		if s, ok := v.(string); ok {
			h.ServerID = s
		}
	}
	if v, ok := m["voucher_count"]; ok {
		if n, ok := v.(int64); ok {
			if n < 0 {
				return fmt.Errorf("voucher_count cannot be negative: %d", n)
			}
			h.VoucherCount = uint(n)
		}
	}
	if v, ok := m["algorithms"]; ok {
		if arr, ok := v.([]any); ok {
			h.Algorithms = make([]int, 0, len(arr))
			for _, elem := range arr {
				if n, ok := elem.(int64); ok {
					h.Algorithms = append(h.Algorithms, int(n))
				}
			}
		}
	}
	return nil
}

// FDOKeyAuthChallenge is the response to FDOKeyAuth.Hello, sent from Server to Caller.
//
//	FDOKeyAuth.Challenge = [
//	    SessionId:             bstr,
//	    NonceAuthServer_Prep,
//	    NonceAuthCaller,
//	    HashAuthHello:         Hash,
//	    ServerSignature:       bstr,     ;; COSE_Sign1 bytes
//	    ServerInfo:            ServerInfoOrNull
//	]
type FDOKeyAuthChallenge struct {
	SessionID       []byte
	NonceServer     Nonce
	NonceCaller     Nonce         // echo of Caller's nonce from Hello
	HashHello       protocol.Hash // hash of CBOR-encoded FDOKeyAuth.Hello body
	ServerSignature []byte        // COSE_Sign1 encoded bytes
	ServerInfo      *ServerInfo   // nil encodes as CBOR null
}

// FDOKeyAuthChallengeSignedPayload is the CBOR structure signed by the Server
// inside the ServerSignature COSE_Sign1.
//
//	FDOKeyAuthChallengeSignedPayload = [
//	    "FDOKeyAuth.Challenge",
//	    NonceAuthCaller,
//	    NonceAuthServer_Prep,
//	    HashAuthHello: Hash,
//	    CallerKey: PublicKey
//	]
type FDOKeyAuthChallengeSignedPayload struct {
	TypeTag     string // always "FDOKeyAuth.Challenge"
	NonceCaller Nonce
	NonceServer Nonce
	HashHello   protocol.Hash
	CallerKey   protocol.PublicKey
}

// FDOKeyAuthProve is the second request message, sent from Caller to Server.
//
//	FDOKeyAuth.Prove = [
//	    SessionId:             bstr,
//	    NonceAuthServer,
//	    HashAuthChallenge:     Hash,
//	    CallerSignature:       bstr      ;; COSE_Sign1 encoded bytes
//	]
type FDOKeyAuthProve struct {
	SessionID       []byte
	NonceServer     Nonce         // echo of Server's nonce from Challenge
	HashChallenge   protocol.Hash // hash of CBOR-encoded FDOKeyAuth.Challenge body
	CallerSignature []byte        // COSE_Sign1 encoded bytes
}

// FDOKeyAuthProveSignedPayload is the CBOR structure signed by the Caller
// inside the CallerSignature COSE_Sign1.
//
//	FDOKeyAuthProveSignedPayload = [
//	    "FDOKeyAuth.Prove",
//	    NonceAuthServer,
//	    NonceAuthCaller,
//	    HashAuthChallenge: Hash,
//	    CallerKey: PublicKey
//	]
type FDOKeyAuthProveSignedPayload struct {
	TypeTag       string // always "FDOKeyAuth.Prove"
	NonceServer   Nonce
	NonceCaller   Nonce
	HashChallenge protocol.Hash
	CallerKey     protocol.PublicKey
}

// FDOKeyAuthResult is the final response from Server to Caller after
// successful authentication.
//
//	FDOKeyAuth.Result = [
//	    Status:                tstr,
//	    SessionToken:          tstr,
//	    TokenExpiresAt:        uint,
//	    KeyFingerprint:        bstr,
//	    VoucherCount:          uint    ;; 0 if unknown
//	]
type FDOKeyAuthResult struct {
	Status         string
	SessionToken   string
	TokenExpiresAt uint64
	KeyFingerprint []byte
	VoucherCount   uint
}

// StatusAuthenticated is the success status value in FDOKeyAuth.Result.
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

// SignChallengePayload creates a COSE_Sign1 signature over a CBOR-encoded
// FDOKeyAuth.Challenge payload, using the FDO-KeyAuth-Challenge-v1 domain
// separation tag in external_aad.
func SignChallengePayload(signer crypto.Signer, usePSS bool, payload any) ([]byte, error) {
	return signPayloadWithAAD(signer, usePSS, payload, cose.AADKeyAuthChallenge)
}

// VerifyChallengePayload verifies a COSE_Sign1 FDOKeyAuth.Challenge signature
// and returns the decoded payload. Uses the FDO-KeyAuth-Challenge-v1 domain
// separation tag in external_aad.
func VerifyChallengePayload(key crypto.PublicKey, sigBytes []byte) ([]byte, error) {
	return verifyPayloadWithAAD(key, sigBytes, cose.AADKeyAuthChallenge)
}

// SignProvePayload creates a COSE_Sign1 signature over a CBOR-encoded
// FDOKeyAuth.Prove payload, using the FDO-KeyAuth-Prove-v1 domain
// separation tag in external_aad.
func SignProvePayload(signer crypto.Signer, usePSS bool, payload any) ([]byte, error) {
	return signPayloadWithAAD(signer, usePSS, payload, cose.AADKeyAuthProve)
}

// VerifyProvePayload verifies a COSE_Sign1 FDOKeyAuth.Prove signature
// and returns the decoded payload. Uses the FDO-KeyAuth-Prove-v1 domain
// separation tag in external_aad.
func VerifyProvePayload(key crypto.PublicKey, sigBytes []byte) ([]byte, error) {
	return verifyPayloadWithAAD(key, sigBytes, cose.AADKeyAuthProve)
}

// signPayloadWithAAD creates a COSE_Sign1 signature with the given external_aad.
func signPayloadWithAAD(signer crypto.Signer, usePSS bool, payload any, aad []byte) ([]byte, error) {
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

	if err := sig.Sign(signer, nil, aad, opts); err != nil {
		return nil, fmt.Errorf("COSE_Sign1 signing failed: %w", err)
	}

	return cbor.Marshal(sig.Tag())
}

// verifyPayloadWithAAD verifies a COSE_Sign1 signature with the given external_aad.
func verifyPayloadWithAAD(key crypto.PublicKey, sigBytes []byte, aad []byte) ([]byte, error) {
	var sig cose.Sign1Tag[cbor.RawBytes, []byte]
	if err := cbor.Unmarshal(sigBytes, &sig); err != nil {
		return nil, fmt.Errorf("failed to decode COSE_Sign1: %w", err)
	}

	ok, err := sig.Untag().Verify(key, nil, aad)
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
