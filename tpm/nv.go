// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

// NV Index range reserved for FDO per "Securing FDO Credentials in the TPM".
const (
	DCTPMIndex = 0x01D10001 // Single consolidated NV index for all FDO credentials (CBOR-encoded)
)

// DCTPMMagic identifies the DCTPM NV data as FDO version 1 ("FDO1").
// Readers MUST verify this value before interpreting the structure.
const DCTPMMagic uint32 = 0x46444F31

// Legacy NV index constants — kept for CleanupFDOState to remove old-format indices.
const (
	legacyDCActiveIndex = 0x01D10000
	legacyDCOVIndex     = 0x01D10002
	legacyHMACUSIndex   = 0x01D10003
	legacyDevKeyUSIndex = 0x01D10004
	legacyFDOCertIndex  = 0x01D10005
)

// Persistent object handles reserved for FDO.
const (
	DAKHandle     = 0x81020002 // ECC signing key (Device Attestation Key)
	HMACKeyHandle = 0x81020003 // HMAC key
)

// NVCredentialInfo holds credential data read from the consolidated DCTPM NV index.
type NVCredentialInfo struct {
	HasDCTPM  bool   // true if DCTPM NV index exists and contains valid data
	RawDCTPM  []byte // raw CBOR from DCTPM NV index
	DCTPMSize uint16

	// Persistent key presence
	HasDAK     bool
	HasHMACKey bool
}

// ReadNVCredentials reads FDO credential data from the consolidated DCTPM NV index.
// It also checks for persistent key handles.
func ReadNVCredentials(t TPM) (*NVCredentialInfo, error) {
	info := &NVCredentialInfo{}

	// DCTPM consolidated NV index (Owner+Auth R/W)
	if nvPub, err := (tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(DCTPMIndex)}).Execute(t); err == nil {
		pub, _ := nvPub.NVPublic.Contents()
		info.DCTPMSize = pub.DataSize
		data, err := nvReadOwner(t, DCTPMIndex, nvPub.NVName, pub.DataSize)
		if err != nil {
			return nil, fmt.Errorf("read DCTPM: %w", err)
		}
		info.HasDCTPM = len(data) > 0
		info.RawDCTPM = data
	}

	// Check persistent key handles
	if _, err := (tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(DAKHandle)}).Execute(t); err == nil {
		info.HasDAK = true
	}
	if _, err := (tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(HMACKeyHandle)}).Execute(t); err == nil {
		info.HasHMACKey = true
	}

	return info, nil
}

// ReadDAKPublicKey reads the Device Attestation Key's public key from the
// persistent handle. Returns the public key as a crypto.PublicKey (currently
// *ecdsa.PublicKey for ECC keys).
func ReadDAKPublicKey(t TPM) (crypto.PublicKey, error) {
	resp, err := (tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(DAKHandle)}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("ReadPublic DAK (0x%08X): %w", DAKHandle, err)
	}

	pub, err := resp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("parse DAK public: %w", err)
	}

	switch pub.Type {
	case tpm2.TPMAlgECC:
		ecc, err := pub.Unique.ECC()
		if err != nil {
			return nil, fmt.Errorf("extract ECC point: %w", err)
		}
		var curve elliptic.Curve
		switch len(ecc.X.Buffer) {
		case 32:
			curve = elliptic.P256()
		case 48:
			curve = elliptic.P384()
		default:
			return nil, fmt.Errorf("unsupported ECC key size: %d bytes", len(ecc.X.Buffer))
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(ecc.X.Buffer),
			Y:     new(big.Int).SetBytes(ecc.Y.Buffer),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported DAK key type: %v", pub.Type)
	}
}

// DAKProof contains the result of a DAK possession proof.
type DAKProof struct {
	PublicKey crypto.PublicKey // DAK public key
	Challenge [32]byte         // SHA-256 hash that was signed
	Signature []byte           // ASN.1-encoded ECDSA signature
}

// ProveDAKPossession signs a random challenge with the Device Attestation Key
// using empty password authorization (userWithAuth=1 with empty authValue per
// spec Table 11). This proves the TPM holds the private key corresponding to
// the DAK public key.
//
// If challenge is nil, a random 32-byte challenge is generated.
func ProveDAKPossession(t TPM, challenge []byte) (*DAKProof, error) {
	// Read DAK public key
	pubKey, err := ReadDAKPublicKey(t)
	if err != nil {
		return nil, err
	}

	// Generate or hash challenge
	var digest [32]byte
	if challenge == nil {
		if _, err := rand.Read(digest[:]); err != nil {
			return nil, fmt.Errorf("generate random challenge: %w", err)
		}
	} else {
		digest = sha256.Sum256(challenge)
	}

	// Discover DAK name
	dkResp, err := (tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(DAKHandle)}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("ReadPublic DAK: %w", err)
	}

	// Sign with empty password auth (userWithAuth=1, empty authValue)
	sigResp, err := (tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(DAKHandle),
			Name:   dkResp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digest:     tpm2.TPM2BDigest{Buffer: digest[:]},
		Validation: tpm2.TPMTTKHashCheck{Tag: tpm2.TPMSTHashCheck},
	}).Execute(t)
	if err != nil {
		return nil, fmt.Errorf("DAK Sign: %w", err)
	}

	// Extract signature
	ecSig, err := sigResp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("extract ECDSA signature: %w", err)
	}
	r := new(big.Int).SetBytes(ecSig.SignatureR.Buffer)
	s := new(big.Int).SetBytes(ecSig.SignatureS.Buffer)
	sigBytes, err := asn1.Marshal(struct {
		R, S *big.Int
	}{R: r, S: s})
	if err != nil {
		return nil, fmt.Errorf("marshal ECDSA signature: %w", err)
	}

	return &DAKProof{
		PublicKey: pubKey,
		Challenge: digest,
		Signature: sigBytes,
	}, nil
}

// nvReadOwner reads NV data using Owner hierarchy authorization.
func nvReadOwner(t TPM, index uint32, nvName tpm2.TPM2BName, size uint16) ([]byte, error) {
	resp, err := (tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(index), Name: nvName},
		Size:       size,
	}).Execute(t)
	if err != nil {
		return nil, err
	}
	return resp.Data.Buffer, nil
}

// =========================================================================
// NV Write/Provisioning — Production counterparts to read functions above
// =========================================================================

// NVProfile identifies the NV attribute profile per spec Table 9.
type NVProfile int

const (
	// NVProfileB is for Unique String indices: Owner+Auth R/W, NoDA, PlatformCreate.
	// Per spec Table 9, ALL NV indices have OWNERWRITE=1, OWNERREAD=1.
	NVProfileB NVProfile = iota
	// NVProfileDCTPM is for the consolidated DCTPM index: Owner+Auth R/W, NoDA.
	// Per spec: "OWNERWRITE=1, OWNERREAD=1, AuthWrite=1, AuthRead=1" with
	// empty authValue. PLATFORMCREATE SHOULD be 1 when Platform hierarchy
	// is available (survives TPM2_Clear).
	NVProfileDCTPM
)

// nvProfileAttrs returns the TPMANV attributes for a given profile.
func nvProfileAttrs(profile NVProfile) tpm2.TPMANV {
	switch profile {
	case NVProfileB:
		return tpm2.TPMANV{
			OwnerWrite: true, AuthWrite: true, OwnerRead: true, AuthRead: true,
			NoDA: true, PlatformCreate: true, NT: tpm2.TPMNTOrdinary,
		}
	case NVProfileDCTPM:
		return tpm2.TPMANV{
			OwnerWrite: true, AuthWrite: true, OwnerRead: true, AuthRead: true,
			NoDA: true, NT: tpm2.TPMNTOrdinary,
		}
	default:
		return tpm2.TPMANV{NT: tpm2.TPMNTOrdinary}
	}
}

// nvProfileAuthHandle returns the hierarchy handle used to define the NV index.
func nvProfileAuthHandle(profile NVProfile) tpm2.TPMHandle {
	switch profile {
	case NVProfileB:
		return tpm2.TPMRHPlatform
	default:
		return tpm2.TPMRHOwner
	}
}

// DefineNVSpace creates an NV index with the specified profile attributes.
// Returns the NV Name needed for subsequent operations.
//
// Profile B indices are created under Platform hierarchy (PlatformCreate=1)
// per the spec. If usePlatform is false, Owner hierarchy is used instead
// (PlatformCreate will be cleared — not fully spec-compliant but works in
// userspace contexts where Platform hierarchy is locked).
//
// DCTPM indices: if usePlatform is true, PlatformCreate=1 is set (SHOULD per spec)
// so the index survives TPM2_Clear. Otherwise Owner hierarchy is used.
func DefineNVSpace(t TPM, index uint32, size uint16, profile NVProfile, usePlatform bool) (tpm2.TPM2BName, error) {
	attrs := nvProfileAttrs(profile)
	authHandle := nvProfileAuthHandle(profile)

	if !usePlatform && profile == NVProfileB {
		authHandle = tpm2.TPMRHOwner
		attrs.PlatformCreate = false
	}
	if usePlatform && profile == NVProfileDCTPM {
		authHandle = tpm2.TPMRHPlatform
		attrs.PlatformCreate = true
	}

	def := tpm2.NVDefineSpace{
		AuthHandle: authHandle,
		PublicInfo: tpm2.New2B(tpm2.TPMSNVPublic{
			NVIndex:    tpm2.TPMHandle(index),
			NameAlg:    tpm2.TPMAlgSHA256,
			Attributes: attrs,
			DataSize:   size,
		}),
	}
	if _, err := def.Execute(t); err != nil {
		return tpm2.TPM2BName{}, fmt.Errorf("NVDefineSpace 0x%08X: %w", index, err)
	}
	pub, err := def.PublicInfo.Contents()
	if err != nil {
		return tpm2.TPM2BName{}, fmt.Errorf("getting NV public for 0x%08X: %w", index, err)
	}
	nvName, err := tpm2.NVName(pub)
	if err != nil {
		return tpm2.TPM2BName{}, fmt.Errorf("computing NV name for 0x%08X: %w", index, err)
	}
	return *nvName, nil
}

// WriteNV writes data to an NV index using the appropriate authorization
// for the given profile (Owner auth for profiles A/C, NV index auth for B).
func WriteNV(t TPM, index uint32, nvName tpm2.TPM2BName, data []byte, profile NVProfile) error {
	var authHandle tpm2.AuthHandle
	if profile == NVProfileB {
		// Profile B: NV index self-auth
		authHandle = tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(index),
			Name:   nvName,
			Auth:   tpm2.PasswordAuth(nil),
		}
	} else {
		// Profile A, C: Owner hierarchy auth
		authHandle = tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		}
	}

	if _, err := (tpm2.NVWrite{
		AuthHandle: authHandle,
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(index), Name: nvName},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: data},
	}).Execute(t); err != nil {
		return fmt.Errorf("NVWrite 0x%08X: %w", index, err)
	}
	return nil
}

// ComputeFDOAuthPolicy computes the auth policy digest for FDO keys using
// a trial session:
//
//	PolicyNV(US_NV, offset=0, operand=0x00, UnsignedGE) || PolicySecret(US_NV)
//
// LEGACY: With the current spec (userWithAuth=1, empty authValue), this function
// is not needed for default key creation. Keys no longer require an AuthPolicy
// for usage. This is retained for compatibility with the old model and for reference.
func ComputeFDOAuthPolicy(t TPM, usIndex uint32, usName tpm2.TPM2BName) (tpm2.TPM2BDigest, error) {
	sess, cleanup, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("trial PolicySession: %w", err)
	}
	defer func() { _ = cleanup() }()

	ah := tpm2.AuthHandle{Handle: tpm2.TPMHandle(usIndex), Name: usName, Auth: tpm2.PasswordAuth(nil)}
	nh := tpm2.NamedHandle{Handle: tpm2.TPMHandle(usIndex), Name: usName}

	if _, err := (tpm2.PolicyNV{
		AuthHandle: ah, NVIndex: nh, PolicySession: sess.Handle(),
		OperandB: tpm2.TPM2BOperand{Buffer: []byte{0}}, Operation: tpm2.TPMEOUnsignedGE,
	}).Execute(t); err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("PolicyNV (trial): %w", err)
	}
	if _, err := (tpm2.PolicySecret{
		AuthHandle: ah, PolicySession: sess.Handle(),
	}).Execute(t); err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("PolicySecret (trial): %w", err)
	}

	pgd, err := tpm2.PolicyGetDigest{PolicySession: sess.Handle()}.Execute(t)
	if err != nil {
		return tpm2.TPM2BDigest{}, fmt.Errorf("PolicyGetDigest: %w", err)
	}
	return pgd.PolicyDigest, nil
}

// PersistKey makes a transient key persistent at the given handle via
// TPM2_EvictControl, then flushes the transient copy.
func PersistKey(t TPM, transient tpm2.NamedHandle, persistentHandle uint32) error {
	if _, err := (tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     &transient,
		PersistentHandle: tpm2.TPMHandle(persistentHandle),
	}).Execute(t); err != nil {
		return fmt.Errorf("EvictControl 0x%08X: %w", persistentHandle, err)
	}
	_, _ = (tpm2.FlushContext{FlushHandle: transient.Handle}).Execute(t)
	return nil
}

// EvictPersistentHandle removes a persistent object from the TPM.
func EvictPersistentHandle(t TPM, handle uint32) error {
	readResp, err := (tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(handle)}).Execute(t)
	if err != nil {
		return fmt.Errorf("ReadPublic 0x%08X: %w", handle, err)
	}
	if _, err := (tpm2.EvictControl{
		Auth:             tpm2.TPMRHOwner,
		ObjectHandle:     &tpm2.NamedHandle{Handle: tpm2.TPMHandle(handle), Name: readResp.Name},
		PersistentHandle: tpm2.TPMHandle(handle),
	}).Execute(t); err != nil {
		return fmt.Errorf("EvictControl (remove) 0x%08X: %w", handle, err)
	}
	return nil
}

// UndefineNVSpace removes an NV index from the TPM.
// It tries Platform hierarchy first, then Owner hierarchy.
func UndefineNVSpace(t TPM, index uint32) error {
	nvPub, err := (tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(index)}).Execute(t)
	if err != nil {
		return fmt.Errorf("NVReadPublic 0x%08X: %w", index, err)
	}
	nh := tpm2.NamedHandle{Handle: tpm2.TPMHandle(index), Name: nvPub.NVName}
	// Try Platform first, then Owner
	if _, err := (tpm2.NVUndefineSpace{AuthHandle: tpm2.TPMRHPlatform, NVIndex: nh}).Execute(t); err == nil {
		return nil
	}
	if _, err := (tpm2.NVUndefineSpace{AuthHandle: tpm2.TPMRHOwner, NVIndex: nh}).Execute(t); err != nil {
		return fmt.Errorf("NVUndefineSpace 0x%08X: %w", index, err)
	}
	return nil
}

// CleanupFDOState removes all FDO NV indices and persistent handles,
// ignoring errors for indices/handles that don't exist.
// Also cleans up legacy indices from the old multi-NV model.
func CleanupFDOState(t TPM) {
	for _, idx := range []uint32{
		DCTPMIndex,
		// Legacy indices from old model — clean up if they exist
		legacyDCActiveIndex, legacyDCOVIndex,
		legacyHMACUSIndex, legacyDevKeyUSIndex, legacyFDOCertIndex,
	} {
		_ = UndefineNVSpace(t, idx)
	}
	for _, h := range []uint32{DAKHandle, HMACKeyHandle} {
		_ = EvictPersistentHandle(t, h)
	}
}
