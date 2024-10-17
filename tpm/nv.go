// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package tpm

import (
	"crypto"
	"fmt"
	"math"

	"github.com/google/go-tpm/tpm2"
)

var nvAttr = tpm2.TPMANV{
	OwnerRead:   true,
	OwnerWrite:  true,
	PolicyRead:  true,
	PolicyWrite: true,
}

// PCRList is a selection of PCRs to use for an operation with a particular
// policy. An nil or zero length slice means all PCRs will be used for the hash.
type PCRList map[crypto.Hash][]int

func (pcrs PCRList) selection() (sel tpm2.TPMLPCRSelection) {
	for alg, slots := range pcrs {
		var hash tpm2.TPMIAlgHash
		switch alg {
		case crypto.SHA1:
			hash = tpm2.TPMAlgSHA1
		case crypto.SHA256:
			hash = tpm2.TPMAlgSHA256
		case crypto.SHA384:
			hash = tpm2.TPMAlgSHA384
		case crypto.SHA512:
			hash = tpm2.TPMAlgSHA512
		default:
			continue
		}

		var pcrSelect [3]byte
		if len(slots) == 0 {
			pcrSelect[0], pcrSelect[1], pcrSelect[2] = 0xFF, 0xFF, 0xFF
		}
		for _, slot := range slots {
			if slot < 0 || slot > 23 {
				continue
			}
			pcrSelect[slot/8] |= 1 << (slot % 8)
		}

		sel.PCRSelections = append(sel.PCRSelections, tpm2.TPMSPCRSelection{
			Hash:      hash,
			PCRSelect: pcrSelect[:],
		})
	}
	return
}

func (pcrs PCRList) policySession(t TPM) (tpm2.Session, func() error, error) {
	// Read PCRs
	selection := pcrs.selection()
	pcrRead := tpm2.PCRRead{PCRSelectionIn: selection}
	pcrReadRsp, err := pcrRead.Execute(t)
	if err != nil {
		return nil, nil, fmt.Errorf("error calling TPM2_PCR_Read: %w", err)
	}

	// Hash PCRs
	hash := crypto.SHA256.New()
	for _, digest := range pcrReadRsp.PCRValues.Digests {
		_, _ = hash.Write(digest.Buffer)
	}
	pcrDigest := tpm2.TPM2BDigest{Buffer: hash.Sum(nil)}

	// Create a PCR policy session
	sess, cleanup, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating policy session: %w", err)
	}
	policyPCR := tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		PcrDigest:     pcrDigest,
		Pcrs:          selection,
	}
	if _, err := policyPCR.Execute(t); err != nil {
		_ = cleanup()
		return nil, nil, fmt.Errorf("error calling TPM2_PolicyPCR: %w", err)
	}

	return sess, cleanup, nil
}

// ReadNV reads data from the specified NV index.
func ReadNV(t TPM, index uint32, pcrs PCRList) ([]byte, error) {
	auth, cleanup, err := pcrs.policySession(t)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cleanup() }()

	return readNV(t, tpm2.TPMHandle(index), auth)
}

func readNV(t TPM, nv tpm2.TPMHandle, auth tpm2.Session) ([]byte, error) {
	readPub := tpm2.NVReadPublic{NVIndex: nv}
	readPubRsp, err := readPub.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("error calling TPM2_NV_ReadPublic: %w", err)
	}
	nvPublic, err := readPubRsp.NVPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("error getting NV public contents: %w", err)
	}

	nvName, err := tpm2.NVName(nvPublic)
	if err != nil {
		return nil, fmt.Errorf("error calculating name of NV index: %w", err)
	}

	read := tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{
			Handle: nv,
			Name:   *nvName,
			Auth:   auth,
		},
		NVIndex: tpm2.NamedHandle{
			Handle: nv,
			Name:   *nvName,
		},
		Size: nvPublic.DataSize,
	}
	readRsp, err := read.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("error calling TPM2_NV_Read: %w", err)
	}

	return readRsp.Data.Buffer, nil
}

// WriteNV writes data to the specified NV index, deleting existing data if
// present.
func WriteNV(t TPM, index uint32, data []byte, pcrs PCRList) error {
	auth, cleanup, err := pcrs.policySession(t)
	if err != nil {
		return err
	}
	defer func() { _ = cleanup() }()

	// Get policy digest
	policyGetDigest, err := (tpm2.PolicyGetDigest{PolicySession: auth.Handle()}).Execute(t)
	if err != nil {
		return fmt.Errorf("error calling TPM2_PolicyGetDigest: %w", err)
	}
	authPolicy := policyGetDigest.PolicyDigest

	return writeNV(t, tpm2.TPMHandle(index), auth, authPolicy, data)
}

func writeNV(t TPM, nv tpm2.TPMHandle, auth tpm2.Session, authPolicy tpm2.TPM2BDigest, data []byte) error {
	// Delete existing data from the NV index
	if readPubRsp, err := (tpm2.NVReadPublic{NVIndex: nv}).Execute(t); err == nil {
		nvPublic, err := readPubRsp.NVPublic.Contents()
		if err != nil {
			return fmt.Errorf("error getting NV public contents: %w", err)
		}
		if nvPublic.DataSize > 0 {
			if err := undefineNV(t, nvPublic); err != nil {
				return err
			}
		}
	}

	// Define the NV index with the new data size
	dataSize := len(data)
	if dataSize > math.MaxUint16 {
		return fmt.Errorf("data is too long to store in NVRAM")
	}
	if err := defineNV(t, nv, authPolicy, uint16(dataSize)); err != nil {
		return fmt.Errorf("error defining NV index: %w", err)
	}

	// Write the new data to the NV index
	nvName, err := tpm2.NVName(&tpm2.TPMSNVPublic{
		NVIndex:    nv,
		NameAlg:    tpm2.TPMAlgSHA256,
		Attributes: nvAttr,
		AuthPolicy: authPolicy,
		DataSize:   uint16(dataSize),
	})
	if err != nil {
		return fmt.Errorf("error calculating name of NV index: %w", err)
	}
	write := tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{
			Handle: nv,
			Name:   *nvName,
			Auth:   auth,
		},
		NVIndex: tpm2.NamedHandle{
			Handle: nv,
			Name:   *nvName,
		},
		Data: tpm2.TPM2BMaxNVBuffer{
			Buffer: data,
		},
	}
	if _, err := write.Execute(t); err != nil {
		return fmt.Errorf("error calling TPM2_NV_Write: %w", err)
	}
	return nil
}

func defineNV(t TPM, nv tpm2.TPMHandle, authPolicy tpm2.TPM2BDigest, dataSize uint16) error {
	def := tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex:    nv,
				NameAlg:    tpm2.TPMAlgSHA256,
				Attributes: nvAttr,
				AuthPolicy: authPolicy,
				DataSize:   dataSize,
			}),
	}
	if _, err := def.Execute(t); err != nil {
		return fmt.Errorf("error calling TPM2_NV_DefineSpace: %w", err)
	}
	return nil
}

func undefineNV(t TPM, nvPublic *tpm2.TPMSNVPublic) error {
	nvName, err := tpm2.NVName(nvPublic)
	if err != nil {
		return fmt.Errorf("error calculating name of NV index: %w", err)
	}
	undef := tpm2.NVUndefineSpace{
		// Policy auth is only possible with Platform auth and
		// NVUndefineSpaceSpecial
		AuthHandle: tpm2.TPMRHOwner,
		NVIndex: tpm2.NamedHandle{
			Handle: nvPublic.NVIndex,
			Name:   *nvName,
		},
	}
	if _, err := undef.Execute(t); err != nil {
		return fmt.Errorf("error calling TPM2_NV_UndefineSpace: %w", err)
	}
	return nil
}
