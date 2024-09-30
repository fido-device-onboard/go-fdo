// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math"
	"math/big"
	"strconv"

	"github.com/google/go-tpm/tpm2"
)

// Key is a closeable signer. Resources are limited in TPMs, so keys should be closed when not in
// use.
type Key interface {
	crypto.Signer
	Close() error
}

// GenerateECKey creates a new EC private key.
func GenerateECKey(t TPM, curve elliptic.Curve) (Key, error) {
	switch curve {
	case elliptic.P256():
		return generateECKey(t, tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256)
	case elliptic.P384():
		return generateECKey(t, tpm2.TPMECCNistP384, tpm2.TPMAlgSHA384)
	default:
		return nil, fmt.Errorf("unsupported curve: %s", curve.Params().Name)
	}
}

func generateECKey(t TPM, curveID tpm2.TPMECCCurve, hashAlg tpm2.TPMAlgID) (Key, error) {
	handle, err := newPrimaryKey(t, ecKeyTemplate(curveID, hashAlg))
	if err != nil {
		return nil, fmt.Errorf("creating EC private key: %w", err)
	}
	public, err := readPublicECKey(t, *handle)
	if err != nil {
		return nil, fmt.Errorf("reading EC public key: %w", err)
	}

	return &key{
		Device:    t,
		Handle:    handle,
		PublicKey: public,
	}, nil
}

func ecKeyTemplate(curveID tpm2.TPMECCCurve, hashAlg tpm2.TPMAlgID) tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true, // Key can never be duplicated
			FixedParent:         true, // Key can never be changed to a new parent
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				CurveID: curveID,
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{HashAlg: hashAlg}),
				},
			},
		),
	}
}

func readPublicECKey(t TPM, handle tpm2.NamedHandle) (*ecdsa.PublicKey, error) {
	resp, err := tpm2.ReadPublic{ObjectHandle: handle.Handle}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("reading public data: %w", err)
	}

	// Parse public key
	data, err := resp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("unmarshaling data: %w", err)
	}
	ecUnique, err := data.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("EC pubkey: %w", err)
	}

	// Determine the curve based on the key size
	var curve elliptic.Curve
	switch len(ecUnique.X.Buffer) {
	case 32: // EC256
		curve = elliptic.P256()
	case 48: // EC384
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("unsupported curve size: %d bits", 8*len(ecUnique.X.Buffer))
	}

	pubkey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(ecUnique.X.Buffer),
		Y:     new(big.Int).SetBytes(ecUnique.Y.Buffer),
	}

	return pubkey, nil
}

// GenerateRSAKey creates a new RSA key of either 2048 or 3072 bit size. If 2048 is used, the key
// will use an exponent of 65537.
func GenerateRSAKey(t TPM, bits int) (Key, error) {
	return generateRSAKey(t, bits, false)
}

// GenerateRSAPSSKey creates a new RSA key of either 2048 or 3072 bit size to be used for PSS
// signatures.
func GenerateRSAPSSKey(t TPM, bits int) (Key, error) {
	return generateRSAKey(t, bits, true)
}

func generateRSAKey(t TPM, bits int, pss bool) (Key, error) {
	handle, err := newPrimaryKey(t, rsaKeyTemplate(bits, pss))
	if err != nil {
		return nil, fmt.Errorf("creating RSA private key: %w", err)
	}
	public, err := readPublicRsaKey(t, *handle)
	if err != nil {
		return nil, fmt.Errorf("reading RSA public key: %w", err)
	}

	return &key{
		Device:    t,
		Handle:    handle,
		PublicKey: public,
	}, nil
}

type key struct {
	Device    TPM
	Handle    *tpm2.NamedHandle
	PublicKey crypto.PublicKey
}

func (key *key) Close() error {
	if key.Handle == nil {
		return nil
	}
	if _, err := (tpm2.FlushContext{FlushHandle: key.Handle}).Execute(key.Device); err != nil {
		return fmt.Errorf("release key failed: %w", err)
	}
	return nil
}

func (key *key) Public() crypto.PublicKey { return key.PublicKey }

func (key *key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := tpm2.Sign{
		KeyHandle:  key.Handle,
		Digest:     tpm2.TPM2BDigest{Buffer: digest},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}.Execute(key.Device)
	if err != nil {
		return nil, fmt.Errorf("unable to sign digest: %w", err)
	}

	switch key.PublicKey.(type) {
	case *ecdsa.PublicKey:
		ecdsaSig, err := sig.Signature.Signature.ECDSA()
		if err != nil {
			return nil, fmt.Errorf("unable to extract ECDSA signature data: %w", err)
		}
		r := new(big.Int).SetBytes(ecdsaSig.SignatureR.Buffer)
		s := new(big.Int).SetBytes(ecdsaSig.SignatureS.Buffer)
		return asn1.Marshal(struct {
			R *big.Int
			S *big.Int
		}{R: r, S: s})

	case *rsa.PublicKey:
		if _, ok := opts.(*rsa.PSSOptions); ok {
			rsaPSSSig, err := sig.Signature.Signature.RSAPSS()
			if err != nil {
				return nil, fmt.Errorf("unable to extract RSA-PSS signature data: %w", err)
			}
			return rsaPSSSig.Sig.Buffer, nil
		}

		rsaSSASig, err := sig.Signature.Signature.RSASSA()
		if err != nil {
			return nil, fmt.Errorf("unable to extract RSA-SSA signature data: %w", err)
		}
		return rsaSSASig.Sig.Buffer, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %T", key.PublicKey)
	}
}

// Primary Keys are all derived from the TPM seed, so we don't need to retrieve or persist a key
// unless there is a performance (time-sensitive) requirement. This requires that a well-known
// template is used.
//
// A primary key must only be persisted if a child key will be generated, in which case the primary
// key is used to wrap the child key.
//
// Seed + Template will always generate the same key.
func newPrimaryKey(t TPM, template tpm2.TPMTPublic) (*tpm2.NamedHandle, error) {
	resp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(template),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("unable to create primary key: %w", err)
	}
	return &tpm2.NamedHandle{
		Handle: resp.ObjectHandle,
		Name:   resp.Name,
	}, nil
}

func rsaKeyTemplate(bits int, pss bool) tpm2.TPMTPublic {
	if bits < 0 || bits > math.MaxUint16 {
		panic("invalid key size: " + strconv.Itoa(bits))
	}
	keyBits := tpm2.TPMKeyBits(bits)

	var hashAlg tpm2.TPMAlgID
	switch bits {
	case 2048:
		hashAlg = tpm2.TPMAlgSHA256
	case 3072:
		hashAlg = tpm2.TPMAlgSHA384
	default:
		panic("unsupported RSA key size: " + strconv.Itoa(bits))
	}

	scheme := tpm2.TPMTRSAScheme{
		Scheme: tpm2.TPMAlgRSASSA,
		Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA,
			&tpm2.TPMSSigSchemeRSASSA{HashAlg: hashAlg}),
	}
	if pss {
		// Salt length is dependent on TPM2 manufacturer and may either be the max length available
		// or the hash length. Unfortunately, this may be difficult to figure out.
		scheme = tpm2.TPMTRSAScheme{
			Scheme: tpm2.TPMAlgRSAPSS,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSAPSS,
				&tpm2.TPMSSigSchemeRSAPSS{HashAlg: hashAlg}),
		}
	}
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true, // Key can never be duplicated
			FixedParent:         true, // Key can never be changed to a new parent
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme:  scheme,
				KeyBits: keyBits,
			},
		),
	}
}

func readPublicRsaKey(t TPM, handle tpm2.NamedHandle) (*rsa.PublicKey, error) {
	resp, err := tpm2.ReadPublic{ObjectHandle: handle.Handle}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("reading public data: %w", err)
	}

	// Parse public key
	data, err := resp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("unmarshaling data: %w", err)
	}
	rsaDetail, err := data.Parameters.RSADetail()
	if err != nil {
		return nil, fmt.Errorf("RSA params: %w", err)
	}
	rsaUnique, err := data.Unique.RSA()
	if err != nil {
		return nil, fmt.Errorf("RSA pubkey: %w", err)
	}
	pubkey, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		return nil, fmt.Errorf("marshaling rsa.PublicKey: %w", err)
	}

	return pubkey, nil
}
