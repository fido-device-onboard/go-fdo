// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

// AsTag returns the CBOR tag representation.
func (s Sign[T]) AsTag() cbor.Tag[Sign[T]] {
	return cbor.Tag[Sign[T]]{
		Num: signTag,
		Val: s,
	}
}

// Sign1 is a COSE_Sign1 signature structure, which is used when only one
// signature is being placed on a message.
type Sign1[T any] struct {
	Header
	Payload   *cbor.Bstr[T] // non-empty byte string or null
	Signature []byte        // non-empty byte string
}

// AsTag returns the CBOR tag representation.
func (s1 Sign1[T]) AsTag() cbor.Tag[Sign1[T]] {
	return cbor.Tag[Sign1[T]]{
		Num: signTag,
		Val: s1,
	}
}

// Sign using a single private key. Unless it was transported independently of
// the signature, payload may be nil.
func (s1 *Sign1[T]) Sign(key crypto.PrivateKey, payload []byte) error {
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
	sig, err := sign(key, signature{
		Context:       sig1Context,
		BodyProtected: s1.Protected,
		Payload:       payload,
	})
	if err != nil {
		return err
	}

	// Set signature and algorithm ID for top-level signing structure
	algID, _ := sig.Protected.Get(AlgLabel)
	s1.Protected.Set(AlgLabel, algID)
	s1.Signature = sig.Signature

	return nil
}

// Verify using a single public key. Unless it was transported independently of
// the signature, payload may be nil.
func (s1 *Sign1[T]) Verify(key crypto.PublicKey, payload []byte) (bool, error) {
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		panic("invalid key for verifying: only *ecdsa.PublicKey supported")
	}

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
	switch algorithm(s1.Protected) {
	case es256AlgId:
		hashBytes := sha256.Sum256(data)
		hash = hashBytes[:]
	case es384AlgId:
		hashBytes := sha512.Sum384(data)
		hash = hashBytes[:]
	default:
		return false, errors.New("unsupported algorithm")
	}
	// Decode signature following RFC8152 8.1.
	n := (pub.Params().N.BitLen() + 7) / 8
	r := big.NewInt(0).SetBytes(s1.Signature[:n])
	s := big.NewInt(0).SetBytes(s1.Signature[n:])
	return ecdsa.Verify(pub, hash, r, s), nil
}

// Algorithm returns the ID of the algorithm set in the protected headers. If
// no algorithm is set or the value is not an int64, then 0 is returned.
func algorithm(protected serializedOrEmptyHeaderMap) (id int64) {
	data, ok := protected.Get(AlgLabel)
	if !ok {
		return 0
	}
	if err := cbor.Unmarshal(data, &id); err != nil {
		return 0
	}
	return id
}

func sign(key crypto.PrivateKey, sig signature) (*Signature, error) {
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		panic("invalid key for signing: only *ecdsa.PrivateKey supported")
	}

	// Put algorithm ID in the signature protected header before signing
	var algID cbor.RawBytes
	switch priv.Curve {
	case elliptic.P256():
		algID = es256AlgIdCbor
	case elliptic.P384():
		algID = es384AlgIdCbor
	default:
		return nil, fmt.Errorf("unsupported curve: %s", priv.Params().Name)
	}
	sig.BodyProtected.Set(AlgLabel, algID)

	// Serialize signature structure
	data, err := cbor.Marshal(sig)
	if err != nil {
		return nil, err
	}

	// Hash and sign with the appropriate algorithm
	var r, s *big.Int
	switch priv.Curve {
	case elliptic.P256():
		hash := sha256.Sum256(data)
		r, s, err = ecdsa.Sign(rand.Reader, priv, hash[:])
		if err != nil {
			return nil, err
		}
	case elliptic.P384():
		hash := sha512.Sum384(data)
		r, s, err = ecdsa.Sign(rand.Reader, priv, hash[:])
		if err != nil {
			return nil, err
		}
	}

	// Encode signature following RFC8152 8.1.
	n := (priv.Params().N.BitLen() + 7) / 8
	sigBytes := make([]byte, n*2)
	r.FillBytes(sigBytes[:n])
	s.FillBytes(sigBytes[n:])

	// Return COSE_Signature structure with algorithm header and signed bytes
	header := Header{}
	header.Protected.Set(AlgLabel, algID)
	return &Signature{
		Header:    header,
		Signature: sigBytes,
	}, nil

}
