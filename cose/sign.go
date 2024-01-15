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
// PSSSaltLengthEqualsHash. If opts is not provided, then the PSS hash used
// will be SHA256.
func (s1 *Sign1[T]) Sign(key crypto.PrivateKey, payload []byte, opts crypto.SignerOpts) error {
	// Check that some payload was given
	if s1.Payload == nil && len(payload) == 0 {
		return errors.New("payload was transported independently but not given as an argument to Sign")
	}
	if len(payload) == 0 {
		var err error
		payload, err = cbor.Marshal(s1.Payload)
		if err != nil {
			return fmt.Errorf("error marshaling payload: %w", err)
		}
	}

	// Sign contents of Sig_structure
	var sig *Signature
	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		var err error
		sig, err = signEc(key, signature{
			Context:       sig1Context,
			BodyProtected: s1.Protected,
			Payload:       payload,
		})
		if err != nil {
			return err
		}
	case *rsa.PrivateKey:
		var err error
		sig, err = signRsa(key, signature{
			Context:       sig1Context,
			BodyProtected: s1.Protected,
			Payload:       payload,
		}, opts)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported key type: %T", key)
	}

	// Set signature and algorithm ID for top-level signing structure
	algID, _ := mapGet(sig.Protected, AlgLabel)
	mapSet(&s1.Protected, AlgLabel, algID)
	s1.Signature = sig.Signature

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
	switch algorithm(s1.Protected) {
	case es256AlgId, ps256AlgId:
		hashBytes := sha256.Sum256(data)
		hash = hashBytes[:]
		hashAlg = crypto.SHA256
	case es384AlgId, ps384AlgId:
		hashBytes := sha512.Sum384(data)
		hash = hashBytes[:]
		hashAlg = crypto.SHA384
	case es512AlgId, ps512AlgId:
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
		err := rsa.VerifyPSS(pub, hashAlg, hash, s1.Signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hashAlg,
		})
		return err == nil, nil

	default:
		return false, fmt.Errorf("")
	}
}

// Algorithm returns the ID of the algorithm set in the protected headers. If
// no algorithm is set or the value is not an int64, then 0 is returned.
func algorithm(protected serializedOrEmptyHeaderMap) (id int64) {
	data, ok := mapGet(protected, AlgLabel)
	if !ok {
		return 0
	}
	if err := cbor.Unmarshal(data, &id); err != nil {
		return 0
	}
	return id
}

func signEc(key *ecdsa.PrivateKey, sig signature) (*Signature, error) {
	// Put algorithm ID in the signature protected header before signing
	var algID cbor.RawBytes
	switch key.Curve {
	case elliptic.P256():
		algID = es256AlgIdCbor
	case elliptic.P384():
		algID = es384AlgIdCbor
	case elliptic.P521():
		algID = es512AlgIdCbor
	default:
		return nil, fmt.Errorf("unsupported curve: %s", key.Params().Name)
	}
	mapSet(&sig.BodyProtected, AlgLabel, algID)

	// Serialize signature structure
	data, err := cbor.Marshal(sig)
	if err != nil {
		return nil, err
	}

	// Hash and sign with the appropriate algorithm
	var r, s *big.Int
	switch key.Curve {
	case elliptic.P256():
		hash := sha256.Sum256(data)
		r, s, err = ecdsa.Sign(rand.Reader, key, hash[:])
		if err != nil {
			return nil, err
		}
	case elliptic.P384():
		hash := sha512.Sum384(data)
		r, s, err = ecdsa.Sign(rand.Reader, key, hash[:])
		if err != nil {
			return nil, err
		}
	}

	// Encode signature following RFC8152 8.1.
	n := (key.Params().N.BitLen() + 7) / 8
	sigBytes := make([]byte, n*2)
	r.FillBytes(sigBytes[:n])
	s.FillBytes(sigBytes[n:])

	// Return COSE_Signature structure with algorithm header and signed bytes
	header := Header{}
	mapSet(&header.Protected, AlgLabel, algID)
	return &Signature{
		Header:    header,
		Signature: sigBytes,
	}, nil
}

func signRsa(key *rsa.PrivateKey, sig signature, opts crypto.SignerOpts) (*Signature, error) {
	// Validate opts
	pss, ok := opts.(*rsa.PSSOptions)
	if !ok || opts == nil {
		pss = &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash}
	}
	if pss.SaltLength != rsa.PSSSaltLengthEqualsHash && pss.SaltLength != pss.Hash.Size() {
		return nil, fmt.Errorf("PSS salt length must match hash size")
	}

	// Put algorithm ID in the signature protected header before signing
	var algID cbor.RawBytes
	switch pss.Hash.Size() {
	case 32:
		algID = ps256AlgIdCbor
	case 48:
		algID = ps384AlgIdCbor
	case 64:
		algID = ps512AlgIdCbor
	default:
		return nil, fmt.Errorf("unsupported hash size: %d bit", pss.Hash.Size()*8)
	}
	mapSet(&sig.BodyProtected, AlgLabel, algID)

	// Serialize and hash signature structure then sign
	digest := pss.Hash.New()
	if err := cbor.NewEncoder(digest).Encode(sig); err != nil {
		return nil, err
	}
	hash := digest.Sum(nil)
	sigBytes, err := rsa.SignPSS(rand.Reader, key, opts.HashFunc(), hash[:], pss)
	if err != nil {
		return nil, err
	}

	// Return COSE_Signature structure with algorithm header and signed bytes
	header := Header{}
	mapSet(&header.Protected, AlgLabel, algID)
	return &Signature{
		Header:    header,
		Signature: sigBytes,
	}, nil
}
