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
type Sign1[T, E any] struct {
	Header
	Payload   *cbor.ByteWrap[T] // non-empty byte string or null
	Signature []byte            // non-empty byte string
}

// Tag is a helper for converting to a tag value.
func (s1 Sign1[T, E]) Tag() *Sign1Tag[T, E] { return &Sign1Tag[T, E]{s1} }

// Sign using a single private key. Unless it was transported independently of
// the signature, payload may be nil. If no external AAD is supplied, the type
// should be []byte and the value nil.
//
// For RSA keys, opts must either be type *rsa.PSSOptions with a SaltLength
// value of PSSSaltLengthEqualsHash or equivalent numerical value or a valid
// hash function for PKCS1 v1.5 signing.
func (s1 *Sign1[T, E]) Sign(key crypto.Signer, payload *T, externalAAD E, opts crypto.SignerOpts) error {
	// Check that some payload was given
	if s1.Payload == nil && payload == nil {
		return errors.New("payload was transported independently but not given as an argument to Sign")
	}
	if payload != nil {
		s1.Payload = cbor.NewByteWrap(*payload)
	}

	// Determine hash and signing algorithm
	algID, err := SignatureAlgorithmFor(key, opts)
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
	sig := signature1[T, E]{
		Context:       sig1Context,
		BodyProtected: body,
		ExternalAad:   *cbor.NewByteWrap(externalAAD),
		Payload:       *s1.Payload,
	}
	digest := algID.HashFunc().New()
	if err := cbor.NewEncoder(digest).Encode(sig); err != nil {
		return err
	}
	fmt.Printf("%x\n", digest.Sum(nil))
	sigBytes, err := key.Sign(rand.Reader, digest.Sum(nil)[:], opts)
	if err != nil {
		return err
	}
	s1.Signature = sigBytes

	return nil
}

// Verify using a single public key. Unless it was transported independently of
// the signature, payload may be nil. If no external AAD is supplied, the type
// should be []byte and the value nil.
func (s1 *Sign1[T, E]) Verify(key crypto.PublicKey, payload *T, externalAAD E) (bool, error) {
	// Check that some payload was given
	if s1.Payload == nil && payload == nil {
		return false, errors.New("payload was transported independently but not given as an argument to Verify")
	}
	if payload != nil {
		s1.Payload = cbor.NewByteWrap(*payload)
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
	data, err := cbor.Marshal(signature1[T, E]{
		Context:       sig1Context,
		BodyProtected: body,
		ExternalAad:   *cbor.NewByteWrap(externalAAD),
		Payload:       *s1.Payload,
	})
	if err != nil {
		return false, err
	}

	// Hash and verify
	if s1.Protected == nil {
		s1.Protected = make(HeaderMap)
	}
	algID, ok := s1.Protected[AlgLabel].(int64)
	if !ok {
		return false, fmt.Errorf("no algorithm in protected headers")
	}
	hashAlg := SignatureAlgorithm(algID).HashFunc()
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
		return verifyRSA(pub, hashAlg, hash, s1.Signature, SignatureAlgorithm(algID))

	default:
		return false, fmt.Errorf("")
	}
}

func verifyRSA(pub *rsa.PublicKey, hash crypto.Hash, digest []byte, sig []byte, alg SignatureAlgorithm) (bool, error) {
	switch alg {
	case RS256Alg, RS384Alg, RS512Alg:
		return rsa.VerifyPKCS1v15(pub, hash, digest, sig) == nil, nil
	case PS256Alg, PS384Alg, PS512Alg:
		return rsa.VerifyPSS(pub, hash, digest, sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hash,
		}) == nil, nil
	}
	return false, fmt.Errorf("invalid algorithm for verifying with RSA public key: %d", alg)
}

const (
	sigContext     = "Signature"
	sig1Context    = "Signature1"
	sigCtrContext  = "CounterSignature"
	sigCtr0Context = "CounterSignature0"
)

// Underlying signature struct for
//   - sigContext
//   - sigCtrContext
//
//nolint:unused
type signature[T, E any] struct {
	Context       string
	BodyProtected emptyOrSerializedMap
	SignProtected emptyOrSerializedMap
	ExternalAad   cbor.ByteWrap[E]
	Payload       cbor.ByteWrap[T]
}

// Underlying signature struct for
//   - sig1Context
//   - sigCtr0Context
type signature1[T, E any] struct {
	Context       string
	BodyProtected emptyOrSerializedMap
	ExternalAad   cbor.ByteWrap[E]
	Payload       cbor.ByteWrap[T]
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
	switch pub := key.Public().(type) {
	case *ecdsa.PublicKey:
		return ecSigAlg(pub)

	case *rsa.PublicKey:
		return rsaSigAlg(pub, opts)

	default:
		return 0, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

func ecSigAlg(pub *ecdsa.PublicKey) (SignatureAlgorithm, error) {
	switch pub.Curve {
	case elliptic.P256():
		return ES256Alg, nil
	case elliptic.P384():
		return ES384Alg, nil
	case elliptic.P521():
		return ES512Alg, nil
	}
	return 0, fmt.Errorf("unsupported curve: %s", pub.Params().Name)
}

func rsaSigAlg(pub *rsa.PublicKey, opts crypto.SignerOpts) (SignatureAlgorithm, error) {
	// Ensure that a hash func was specified
	if opts == nil {
		return 0, errors.New("required signer opts were missing; must specify hash type")
	}

	// When using RSASSA-PSS, salt length must equal hash length
	pssOpts, usingPss := opts.(*rsa.PSSOptions)
	if usingPss && pssOpts.SaltLength != rsa.PSSSaltLengthEqualsHash && pssOpts.SaltLength != pssOpts.Hash.Size() {
		return 0, fmt.Errorf("PSS salt length must match hash size")
	}

	if usingPss {
		switch opts.HashFunc() {
		case crypto.SHA256:
			return PS256Alg, nil
		case crypto.SHA384:
			return PS384Alg, nil
		case crypto.SHA512:
			return PS512Alg, nil
		}
	} else {
		switch opts.HashFunc() {
		case crypto.SHA256:
			return RS256Alg, nil
		case crypto.SHA384:
			return RS384Alg, nil
		case crypto.SHA512:
			return RS512Alg, nil
		}
	}

	return 0, fmt.Errorf("unsupported hash: %d", opts.HashFunc())
}

// Sign1Tag encodes to a CBOR tag while ensuring the right tag number.
type Sign1Tag[T, E any] struct {
	Sign1[T, E]
}

// Untag is a helper for accessing the tag value.
func (t Sign1Tag[T, E]) Untag() *Sign1[T, E] { return &t.Sign1 }

// MarshalCBOR implements cbor.Marshaler.
func (t Sign1Tag[T, E]) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(cbor.Tag[Sign1[T, E]]{
		Num: Sign1TagNum,
		Val: t.Sign1,
	})
}

// UnmarshalCBOR implements cbor.Unmarshaler.
func (t *Sign1Tag[T, E]) UnmarshalCBOR(data []byte) error {
	var tag cbor.Tag[Sign1[T, E]]
	if err := cbor.Unmarshal(data, &tag); err != nil {
		return err
	}
	if tag.Num != Sign1TagNum {
		return fmt.Errorf("mismatched tag number %d for Sign1, expected %d", tag.Num, Sign1TagNum)
	}
	*t = Sign1Tag[T, E]{tag.Val}
	return nil
}
