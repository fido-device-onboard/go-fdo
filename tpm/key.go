// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package tpm

import (
	"crypto"
	"crypto/rsa"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// 2048-bit keys are the minimum FDO requires and largest TPM2 supports, so
// no choice is given. Similarly, for 2048-bit RSA keys, FDO requires the use
// of SHA-256 digests. The only choice is whether to use RSASSA or RSAPSS
// signatures.
func keyTemplate(pss bool) tpm2.TPMTPublic {
	scheme := tpm2.TPMTRSAScheme{
		Scheme: tpm2.TPMAlgRSASSA,
		Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA,
			&tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA256}),
	}
	if pss {
		// TODO: Where does salt length go?
		scheme = tpm2.TPMTRSAScheme{
			Scheme: tpm2.TPMAlgRSAPSS,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSAPSS,
				&tpm2.TPMSSigSchemeRSAPSS{HashAlg: tpm2.TPMAlgSHA256}),
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
				KeyBits: tpm2.TPMKeyBits(2048), // maximum size
			},
		),
	}
}

// Primary Keys are all derived from the TPM seed, so we don't need to retrieve or persist
// a key unless there is a performance (time-sensitive) requirement. This requires that
// a well-known template is used.
//
// A primary key must only be persisted if a child key will be generated, in which case
// the primary key is used to wrap the child key.
//
// Seed + Template will always generate the same key.
func newPrimaryRsaKey(t transport.TPM, template tpm2.TPMTPublic) (*tpm2.NamedHandle, error) {
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

func readPublicRsaKey(t transport.TPM, handle *tpm2.NamedHandle) (*rsa.PublicKey, crypto.SignerOpts, error) {
	resp, err := tpm2.ReadPublic{ObjectHandle: handle.Handle}.Execute(t)
	if err != nil {
		return nil, nil, fmt.Errorf("reading public data: %w", err)
	}

	// Parse public key
	data, err := resp.OutPublic.Contents()
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshaling data: %w", err)
	}
	rsaDetail, err := data.Parameters.RSADetail()
	if err != nil {
		return nil, nil, fmt.Errorf("RSA params: %w", err)
	}
	rsaUnique, err := data.Unique.RSA()
	if err != nil {
		return nil, nil, fmt.Errorf("RSA pubkey: %w", err)
	}
	pubkey, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	if err != nil {
		return nil, nil, fmt.Errorf("marshaling rsa.PublicKey: %w", err)
	}

	// Parse scheme to determine hash and signature type
	var opts crypto.SignerOpts
	switch rsaDetail.Scheme.Scheme {
	case tpm2.TPMAlgRSASSA:
		scheme, err := rsaDetail.Scheme.Details.RSASSA()
		if err != nil {
			return nil, nil, fmt.Errorf("RSA SSA scheme details: %w", err)
		}
		alg, err := scheme.HashAlg.Hash()
		if err != nil {
			return nil, nil, fmt.Errorf("RSA SSA scheme hash: %w", err)
		}
		opts = alg

	case tpm2.TPMAlgRSAPSS:
		scheme, err := rsaDetail.Scheme.Details.RSAPSS()
		if err != nil {
			return nil, nil, fmt.Errorf("RSA PSS scheme details: %w", err)
		}
		alg, err := scheme.HashAlg.Hash()
		if err != nil {
			return nil, nil, fmt.Errorf("RSA PSS scheme hash: %w", err)
		}
		opts = &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       alg,
		}

	default:
		return nil, nil, fmt.Errorf("unsupported RSA scheme")
	}

	return pubkey, opts, nil
}
