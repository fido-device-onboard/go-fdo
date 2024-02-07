// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// Sign1 is a COSE_Sign1 signature structure, which is used when only one
// signature is being placed on a message.
type Sign1[T any] struct {
	Header
	Payload   *cbor.ByteWrap[T] // non-empty byte string or null
	Signature []byte            // non-empty byte string
}

// Tag is a helper for converting to a tag value.
func (s1 Sign1[T]) Tag() *Sign1Tag[T] { return &Sign1Tag[T]{s1} }

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
	algID, opts, err := signAlg(key, opts)
	if err != nil {
		return err
	}

	// When an *ecdsa.PrivateKey is used, override its Sign implementation
	// to use RFC8152 signature encoding rather than ASN1.
	if eckey, ok := key.(*ecdsa.PrivateKey); ok {
		key = RFC8152Signer{eckey}
	}

	// Put algorithm ID in the signature protected header before signing
	if s1.Protected == nil {
		s1.Protected = make(map[Label]any)
	}
	s1.Protected[AlgLabel] = algID
	body, err := newEmptyOrSerializedMap(s1.Protected)
	if err != nil {
		return fmt.Errorf("error marshaling signature protected body: %W", err)
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
		BodyProtected: body,
		ExternalAad:   cbor.RawBytes([]byte{0x40}),
		Payload:       cbor.RawBytes(payload),
	}
	digest := opts.HashFunc().New()
	if err := cbor.NewEncoder(digest).Encode(sig); err != nil {
		return err
	}
	sigBytes, err := key.Sign(rand.Reader, digest.Sum(nil)[:], opts)
	if err != nil {
		return err
	}
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
	body, err := newEmptyOrSerializedMap(s1.Protected)
	if err != nil {
		return false, fmt.Errorf("error marshaling signature protected body: %W", err)
	}
	data, err := cbor.Marshal(signature{
		Context:       sig1Context,
		BodyProtected: body,
		ExternalAad:   cbor.RawBytes([]byte{0x40}),
		Payload:       cbor.RawBytes(payload),
	})
	if err != nil {
		return false, err
	}

	// Hash and verify
	hashAlg := SignatureAlgorithm(s1.Algorithm()).HashFunc()
	if !hashAlg.Available() {
		return false, errors.New("unsupported algorithm")
	}
	digest := hashAlg.New()
	if _, err := digest.Write(data); err != nil {
		return false, err
	}
	hash := digest.Sum(nil)

	switch pub := key.(type) {
	case *ecdsa.PublicKey:
		// Decode signature following RFC8152 8.1.
		n := (pub.Params().N.BitLen() + 7) / 8
		r := big.NewInt(0).SetBytes(s1.Signature[:n])
		s := big.NewInt(0).SetBytes(s1.Signature[n:])
		return ecdsa.Verify(pub, hash, r, s), nil

	case *rsa.PublicKey:
		var err error
		switch SignatureAlgorithm(s1.Algorithm()) {
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

const (
	sigContext     = "Signature"
	sig1Context    = "Signature1"
	sigCtrContext  = "CounterSignature"
	sigCtr0Context = "CounterSignature0"
)

// Underlying signature struct
type signature struct {
	Context       string
	BodyProtected emptyOrSerializedMap
	SignProtected emptyOrSerializedMap
	ExternalAad   cbor.RawBytes
	Payload       cbor.RawBytes
}

// Omit SignProtected field when using Signature1 or CounterSignature0.
func (sig signature) MarshalCBOR() ([]byte, error) {
	switch sig.Context {
	case sigContext, sigCtrContext:
		return cbor.Marshal(struct {
			Context       string
			BodyProtected emptyOrSerializedMap
			SignProtected emptyOrSerializedMap
			ExternalAad   cbor.RawBytes
			Payload       cbor.RawBytes
		}(sig))
	case sig1Context, sigCtr0Context:
		return cbor.Marshal(struct {
			Context       string
			BodyProtected emptyOrSerializedMap
			ExternalAad   cbor.RawBytes
			Payload       cbor.RawBytes
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
		BodyProtected emptyOrSerializedMap
		SignProtected emptyOrSerializedMap `cbor:",omitempty"`
		ExternalAad   cbor.RawBytes
		Payload       cbor.RawBytes
	}
	if err := cbor.Unmarshal(b, &ss); err != nil {
		return err
	}
	*sig = signature(ss)
	return nil
}

// RFC8152Signer wraps an ECDSA private key and uses the signature encoding
// required by COSE.
type RFC8152Signer struct {
	PrivateKey *ecdsa.PrivateKey
}

// Public returns the public key corresponding to the opaque,
// private key.
func (key RFC8152Signer) Public() crypto.PublicKey { return key.PrivateKey.Public() }

// Sign implements crypto.Signer.
func (key RFC8152Signer) Sign(rand io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand, key.PrivateKey, digest)
	if err != nil {
		return nil, err
	}

	// Encode signature following RFC8152 8.1.
	n := (key.PrivateKey.Params().N.BitLen() + 7) / 8
	sigBytes := make([]byte, n*2)
	r.FillBytes(sigBytes[:n])
	s.FillBytes(sigBytes[n:])
	return sigBytes, nil
}

// SignatureAlgorithmFor returns the Signature Algorithm identifier for the
// given key and options.
func SignatureAlgorithmFor(key crypto.Signer, opts crypto.SignerOpts) (SignatureAlgorithm, error) {
	id, _, err := signAlg(key, opts)
	return id, err
}

// signAlg returns the already marshaled algorithm ID and possibly modified
// SignerOpts.
//
// This function has a high cyclomatic complexity, but should NOT be reduced
// further, because indirection will only make the code harder to read.
//
//nolint:gocyclo
func signAlg(key crypto.Signer, opts crypto.SignerOpts) (algID SignatureAlgorithm, _ crypto.SignerOpts, _ error) {
	switch pub := key.Public().(type) {
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			return ES256Alg, crypto.SHA256, nil
		case elliptic.P384():
			return ES384Alg, crypto.SHA384, nil
		case elliptic.P521():
			return ES512Alg, crypto.SHA512, nil
		default:
			return 0, nil, fmt.Errorf("unsupported curve: %s", pub.Params().Name)
		}

	case *rsa.PublicKey:
		// Ensure that a hash func was specified
		if opts == nil {
			return 0, nil, errors.New("required signer opts were missing; must specify hash type")
		}

		// When using RSASSA-PSS, salt length must equal hash length
		pssOpts, usingPss := opts.(*rsa.PSSOptions)
		if usingPss && pssOpts.SaltLength != rsa.PSSSaltLengthEqualsHash && pssOpts.SaltLength != pssOpts.Hash.Size() {
			return 0, nil, fmt.Errorf("PSS salt length must match hash size")
		}

		switch {
		case usingPss && opts.HashFunc().Size() == 32:
			return PS256Alg, opts, nil
		case usingPss && opts.HashFunc().Size() == 48:
			return PS384Alg, opts, nil
		case usingPss && opts.HashFunc().Size() == 64:
			return PS512Alg, opts, nil
		case !usingPss && opts.HashFunc().Size() == 32:
			return RS256Alg, opts, nil
		case !usingPss && opts.HashFunc().Size() == 48:
			return RS384Alg, opts, nil
		case !usingPss && opts.HashFunc().Size() == 64:
			return RS512Alg, opts, nil
		default:
			return 0, nil, fmt.Errorf("unsupported hash size: %d bit", opts.HashFunc().Size()*8)
		}

	default:
		return 0, nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// Sign1Tag encodes to a CBOR tag while ensuring the right tag number.
type Sign1Tag[T any] struct {
	Sign1[T]
}

// Untag is a helper for accessing the tag value.
func (t Sign1Tag[T]) Untag() *Sign1[T] { return &t.Sign1 }

// MarshalCBOR implements cbor.Marshaler.
func (t Sign1Tag[T]) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(cbor.Tag[Sign1[T]]{
		Num: Sign1TagNum,
		Val: t.Sign1,
	})
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (t *Sign1Tag[T]) UnmarshalCBOR(data []byte) error {
	var tag cbor.Tag[Sign1[T]]
	if err := cbor.Unmarshal(data, &tag); err != nil {
		return err
	}
	if tag.Num != Sign1TagNum {
		return fmt.Errorf("mismatched tag number %d for Sign1, expected %d", tag.Num, Sign1TagNum)
	}
	*t = Sign1Tag[T]{tag.Val}
	return nil
}
