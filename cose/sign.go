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
	"math/big"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// SignFuncOptions implements crypto.SignerOpts to allow providing a signing
// function without a key. This is helpful when the signing is done in a key
// enclave, such as a TPM.
type SignFuncOptions struct {
	Algorithm Algorithm
	Sign      func([]byte) ([]byte, error)
}

func (o *SignFuncOptions) HashFunc() crypto.Hash {
	switch o.Algorithm {
	case ES256Alg, RS256Alg, PS256Alg:
		return crypto.SHA256
	case ES384Alg, RS384Alg, PS384Alg:
		return crypto.SHA384
	case ES512Alg, RS512Alg, PS512Alg:
		return crypto.SHA512
	}
	panic("invalid algorithm option")
}

// hashOpt implements crypto.SignerOpts trivially to explicitly select a hash
// function.
type hashOpt crypto.Hash

func (o hashOpt) HashFunc() crypto.Hash { return crypto.Hash(o) }

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
// For RSA keys, opts should be type *rsa.PSSOptions and SaltLength must be
// PSSSaltLengthEqualsHash or equivalent. If opts is not provided, then PKCS1
// v1.5 signing is used.
//
// When a key enclave is used for signing, key must be nil and opts must be
// *SignFuncOptions.
func (s1 *Sign1[T]) Sign(key crypto.PrivateKey, payload []byte, opts crypto.SignerOpts) error {
	// Check that some payload was given
	if s1.Payload == nil && len(payload) == 0 {
		return errors.New("payload was transported independently but not given as an argument to Sign")
	}

	// Determine hash algorithm and signing function
	var algID cbor.RawBytes
	var signFn func([]byte) ([]byte, error)
	switch key := key.(type) {
	case nil:
		signFnOpts, ok := opts.(*SignFuncOptions)
		if !ok {
			return fmt.Errorf("signing function options must be provided when key is nil")
		}
		alg, err := cbor.Marshal(signFnOpts.Algorithm)
		if err != nil {
			return fmt.Errorf("error marshaling algorithm: %w", err)
		}
		algID = cbor.RawBytes(alg)
		signFn = signFnOpts.Sign

	case *ecdsa.PrivateKey:
		switch key.Curve {
		case elliptic.P256():
			algID = es256AlgCbor
			opts = hashOpt(crypto.SHA256)
			signFn = signEc(key)
		case elliptic.P384():
			algID = es384AlgCbor
			opts = hashOpt(crypto.SHA384)
			signFn = signEc(key)
		case elliptic.P521():
			algID = es512AlgCbor
			opts = hashOpt(crypto.SHA512)
			signFn = signEc(key)
		default:
			return fmt.Errorf("unsupported curve: %s", key.Params().Name)
		}

	case *rsa.PrivateKey:
		_, usingPss := opts.(*rsa.PSSOptions)
		switch opts.HashFunc().Size() {
		case 32:
			algID = ps256AlgCbor
			if !usingPss {
				algID = rs256AlgCbor
				opts = hashOpt(crypto.SHA256)
			}
			signFn = signRsa(key, opts)
		case 48:
			algID = ps384AlgCbor
			if !usingPss {
				algID = rs384AlgCbor
				opts = hashOpt(crypto.SHA384)
			}
			signFn = signRsa(key, opts)
		case 64:
			algID = ps512AlgCbor
			if usingPss {
				algID = rs512AlgCbor
				opts = hashOpt(crypto.SHA512)
			}
			signFn = signRsa(key, opts)
		default:
			return fmt.Errorf("unsupported hash size: %d bit", opts.HashFunc().Size()*8)
		}

	default:
		return fmt.Errorf("unsupported key type: %T", key)
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
	sigBytes, err := signFn(digest.Sum(nil)[:])
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

func signEc(key *ecdsa.PrivateKey) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		r, s, err := ecdsa.Sign(rand.Reader, key, data)
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
}

func signRsa(key *rsa.PrivateKey, opts crypto.SignerOpts) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		pssOpts, usingPss := opts.(*rsa.PSSOptions)
		if usingPss && pssOpts.SaltLength != rsa.PSSSaltLengthEqualsHash && pssOpts.SaltLength != pssOpts.Hash.Size() {
			return nil, fmt.Errorf("PSS salt length must match hash size")
		}
		if usingPss {
			return rsa.SignPSS(rand.Reader, key, opts.HashFunc(), data, pssOpts)
		}
		return rsa.SignPKCS1v15(rand.Reader, key, opts.HashFunc(), data)
	}
}
