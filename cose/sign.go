// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// Signature is a COSE_Signature, which carries the signature and information
// about the signature.
type Signature struct {
	Header
	Signature []byte // non-empty byte string
}

const (
	sigContext     = "Signature"
	sig1Context    = "Signature1"
	sigCtrContext  = "CounterSignature"
	sigCtr0Context = "CounterSignature0"
)

// Underlying signature struct
type signature struct {
	Context       string
	BodyProtected serializedOrEmptyHeaderMap
	SignProtected serializedOrEmptyHeaderMap
	ExternalAad   []byte
	Payload       []byte
}

// Omit SignProtected field when using Signature1 or CounterSignature0.
func (sig signature) MarshalCBOR() ([]byte, error) {
	switch sig.Context {
	case sigContext, sigCtrContext:
		return cbor.Marshal(struct {
			Context       string
			BodyProtected serializedOrEmptyHeaderMap
			SignProtected serializedOrEmptyHeaderMap
			ExternalAad   []byte
			Payload       []byte
		}(sig))
	case sig1Context, sigCtr0Context:
		return cbor.Marshal(struct {
			Context       string
			BodyProtected serializedOrEmptyHeaderMap
			ExternalAad   []byte
			Payload       []byte
		}{
			Context:       sig.Context,
			BodyProtected: sig.BodyProtected,
			ExternalAad:   sig.ExternalAad,
			Payload:       sig.Payload,
		})
	default:
		return nil, fmt.Errorf("unknown signature context: %s", sig.Context)
	}
}

// SignProtected field may be omitted when context is Signature1 or
// CounterSignature0.
func (sig *signature) UnmarshalCBOR(b []byte) error {
	var ss struct {
		Context       string
		BodyProtected serializedOrEmptyHeaderMap
		SignProtected serializedOrEmptyHeaderMap `cbor:",omitempty"`
		ExternalAad   []byte
		Payload       []byte
	}
	if err := cbor.Unmarshal(b, &ss); err != nil {
		return err
	}
	*sig = signature(ss)
	return nil
}

// Sign is a COSE_Sign signature structure, which is used for multi-signature
// messages.
//
// TODO: Implement Sign/Verify
type Sign[T any] struct {
	Header
	Payload    *cbor.Bstr[T] // byte string or null
	Signatures []Signature   // non-empty array of Signature
}

// Sign1 is a COSE_Sign1 signature structure, which is used when only one
// signature is being placed on a message.
type Sign1[T any] struct {
	Header
	Payload   *cbor.Bstr[T] // non-empty byte string or null
	Signature []byte        // non-empty byte string
}

// Sign using a single private key. Unless it was transported independently of
// the signature, payload may be nil.
//
// For RSA keys, opts must either be type *rsa.PSSOptions with a SaltLength
// value of PSSSaltLengthEqualsHash or equivalent numerical value or a valid
// hash function for PKCS1 v1.5 signing.
func (s1 *Sign1[T]) Sign(key crypto.Signer, payload []byte, opts crypto.SignerOpts) error {
	// Check that some payload was given
	if s1.Payload == nil && len(payload) == 0 {
		return errors.New("payload was transported independently but not given as an argument to Sign")
	}

	// Determine hash and signing algorithm
	var algID cbor.RawBytes
	switch pub := key.Public().(type) {
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			algID = es256AlgCbor
			opts = crypto.SHA256
		case elliptic.P384():
			algID = es384AlgCbor
			opts = crypto.SHA384
		case elliptic.P521():
			algID = es512AlgCbor
			opts = crypto.SHA512
		default:
			return fmt.Errorf("unsupported curve: %s", pub.Params().Name)
		}

		// When an *ecdsa.PrivateKey is used, override its Sign implementation
		// to use RFC8152 signature encoding rather than ASN1.
		if eckey, ok := key.(*ecdsa.PrivateKey); ok {
			key = rfc8152ecSigner{eckey}
		}

	case *rsa.PublicKey:
		// Ensure that a hash func was specified
		if opts == nil {
			return errors.New("required signer opts were missing; must specify hash type")
		}

		// When using RSASSA-PSS, salt length must equal hash length
		pssOpts, usingPss := opts.(*rsa.PSSOptions)
		if usingPss && pssOpts.SaltLength != rsa.PSSSaltLengthEqualsHash && pssOpts.SaltLength != pssOpts.Hash.Size() {
			return fmt.Errorf("PSS salt length must match hash size")
		}

		switch {
		case usingPss && opts.HashFunc().Size() == 32:
			algID = ps256AlgCbor
		case usingPss && opts.HashFunc().Size() == 48:
			algID = ps384AlgCbor
		case usingPss && opts.HashFunc().Size() == 64:
			algID = ps512AlgCbor
		case !usingPss && opts.HashFunc().Size() == 32:
			algID = rs256AlgCbor
		case !usingPss && opts.HashFunc().Size() == 48:
			algID = rs384AlgCbor
		case !usingPss && opts.HashFunc().Size() == 64:
			algID = rs512AlgCbor
		default:
			return fmt.Errorf("unsupported hash size: %d bit", opts.HashFunc().Size()*8)
		}

	default:
		return fmt.Errorf("unsupported public key type: %T", pub)
	}

	// Sign contents of Sig_structure
	if len(payload) == 0 {
		var err error
		payload, err = cbor.Marshal(s1.Payload)
		if err != nil {
			return fmt.Errorf("error marshaling payload: %w", err)
		}
	}
	sig := signature{
		Context:       sig1Context,
		BodyProtected: s1.Protected,
		Payload:       payload,
	}
	// Put algorithm ID in the signature protected header before signing
	mapSet(&sig.BodyProtected, AlgLabel, algID)
	digest := opts.HashFunc().New()
	if err := cbor.NewEncoder(digest).Encode(sig); err != nil {
		return err
	}
	sigBytes, err := key.Sign(rand.Reader, digest.Sum(nil)[:], opts)
	if err != nil {
		return err
	}

	// Set signature and algorithm ID for top-level signing structure
	mapSet(&s1.Protected, AlgLabel, algID)
	s1.Signature = sigBytes

	return nil
}

// Verify using a single public key. Unless it was transported independently of
// the signature, payload may be nil.
func (s1 *Sign1[T]) Verify(key crypto.PublicKey, payload []byte) (bool, error) {
	// Check that some payload was given
	if s1.Payload == nil && len(payload) == 0 {
		return false, errors.New("payload was transported independently but not given as an argument to Verify")
	}
	if len(payload) == 0 {
		var err error
		payload, err = cbor.Marshal(s1.Payload)
		if err != nil {
			return false, fmt.Errorf("error marshaling payload: %w", err)
		}
	}
	if len(s1.Signature) < 2 {
		return false, errors.New("signature length insufficient")
	}
	if len(s1.Signature)%2 != 0 {
		return false, errors.New("signature length must be even")
	}

	// Marshal signature to bytes
	data, err := cbor.Marshal(signature{
		Context:       sig1Context,
		BodyProtected: s1.Protected,
		ExternalAad:   []byte{},
		Payload:       payload,
	})
	if err != nil {
		return false, err
	}

	// Hash and verify
	var hash []byte
	var hashAlg crypto.Hash
	switch s1.Algorithm() {
	case ES256Alg, RS256Alg, PS256Alg:
		hashBytes := sha256.Sum256(data)
		hash = hashBytes[:]
		hashAlg = crypto.SHA256
	case ES384Alg, RS384Alg, PS384Alg:
		hashBytes := sha512.Sum384(data)
		hash = hashBytes[:]
		hashAlg = crypto.SHA384
	case ES512Alg, RS512Alg, PS512Alg:
		hashBytes := sha512.Sum512(data)
		hash = hashBytes[:]
		hashAlg = crypto.SHA512
	default:
		return false, errors.New("unsupported algorithm")
	}

	switch pub := key.(type) {
	case *ecdsa.PublicKey:
		// Decode signature following RFC8152 8.1.
		n := (pub.Params().N.BitLen() + 7) / 8
		r := big.NewInt(0).SetBytes(s1.Signature[:n])
		s := big.NewInt(0).SetBytes(s1.Signature[n:])
		return ecdsa.Verify(pub, hash, r, s), nil

	case *rsa.PublicKey:
		var err error
		switch s1.Algorithm() {
		case RS256Alg, RS384Alg, RS512Alg:
			err = rsa.VerifyPKCS1v15(pub, hashAlg, hash, s1.Signature)
		case PS256Alg, PS384Alg, PS512Alg:
			err = rsa.VerifyPSS(pub, hashAlg, hash, s1.Signature, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hashAlg,
			})
		}
		return err == nil, nil

	default:
		return false, fmt.Errorf("")
	}
}

type rfc8152ecSigner struct {
	*ecdsa.PrivateKey
}

func (key rfc8152ecSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand, key.PrivateKey, digest)
	if err != nil {
		return nil, err
	}

	// Encode signature following RFC8152 8.1.
	n := (key.Params().N.BitLen() + 7) / 8
	sigBytes := make([]byte, n*2)
	r.FillBytes(sigBytes[:n])
	s.FillBytes(sigBytes[n:])
	return sigBytes, nil
}
