// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

//go:build tpm || tpmsim

package cred

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"hash"
	"log/slog"
	"os"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/tpm"

	"github.com/google/go-tpm/tpm2"
)

// dctpmNVData is the consolidated CBOR structure stored in the single DCTPM NV index.
// Per the spec CDDL: DCTPM = [DCTPMMagic, DCActive, DCProtVer, DCDeviceInfo,
//   DCGuid, DCRVInfo, DCPubKeyHash, DeviceKeyType, DeviceKeyHandle, HMACKeyHandle]
//
// The Go CBOR library encodes structs as CBOR arrays (not maps), with field
// ordering determined by the keyasint tags. This matches the spec's array encoding.
type dctpmNVData struct {
	Magic           uint32                     `cbor:"0,keyasint"`
	Active          bool                       `cbor:"1,keyasint"`
	Version         uint16                     `cbor:"2,keyasint"`
	DeviceInfo      string                     `cbor:"3,keyasint"`
	GUID            protocol.GUID              `cbor:"4,keyasint"`
	RvInfo          [][]protocol.RvInstruction `cbor:"5,keyasint"`
	PublicKeyHash   protocol.Hash              `cbor:"6,keyasint"`
	KeyType         protocol.KeyType           `cbor:"7,keyasint"`
	DeviceKeyHandle uint32                     `cbor:"8,keyasint"`
	HMACKeyHandle   uint32                     `cbor:"9,keyasint,omitempty"`
}

type tpmStore struct {
	tpmc           tpm.Closer
	h256           tpm.Hmac
	h384           tpm.Hmac
	key            tpm.Key
	keyType        protocol.KeyType
	dakHandle      uint32 // resolved DAK handle (from DCTPM or default)
	hmacHandle     uint32 // resolved HMAC key handle (from DCTPM or default)
	usePlatform    bool   // true = use Platform hierarchy for Profile B NV indices
}

// Open returns a TPM-backed credential store.
// The TPM transport is selected by build tag (hardware or simulator).
// The path argument is accepted for interface compatibility but ignored —
// all credential data is stored in TPM NV indices.
func Open(path string) (Store, error) {
	t, err := tpm.DefaultOpen()
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	// Default to Platform hierarchy; set FDO_TPM_OWNER_HIERARCHY=1 to
	// use Owner hierarchy (not fully spec-compliant but works in userspace).
	usePlatform := os.Getenv("FDO_TPM_OWNER_HIERARCHY") != "1"
	return &tpmStore{tpmc: t, usePlatform: usePlatform}, nil
}

// NewDI provisions NV indices, creates spec-compliant persistent keys,
// and returns HMAC + signing key handles for Device Initialization.
//
// This implements the manufacturer provisioning step:
//  1. Cleanup any existing FDO state in the TPM
//  2. Generate random Unique Strings for device key and HMAC key
//  3. Define and write Unique String NV indices (Profile B)
//  4. Compute auth policies (PolicyNV + PolicySecret)
//  5. Create ECC signing key with AuthPolicy → persist to DAKHandle
//  6. Create HMAC key with AuthPolicy → persist to HMACKeyHandle
//  7. Return spec-compliant HMAC (SHA-256) + legacy HMAC (SHA-384) + persistent key
//
// Note: The consolidated DCTPM NV index is NOT written here — it is written
// by Save() after DI completes with the full credential data.
func (s *tpmStore) NewDI(keyType protocol.KeyType) (hash.Hash, hash.Hash, crypto.Signer, error) {
	s.keyType = keyType

	// Derive curve-dependent parameters from keyType
	var (
		curveID   tpm2.TPMECCCurve
		hashAlg   tpm2.TPMAlgID
		coordSize int // bytes per coordinate (X or Y)
	)
	switch keyType {
	case protocol.Secp256r1KeyType:
		curveID, hashAlg, coordSize = tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256, 32
	case protocol.Secp384r1KeyType:
		curveID, hashAlg, coordSize = tpm2.TPMECCNistP384, tpm2.TPMAlgSHA384, 48
	default:
		return nil, nil, nil, fmt.Errorf("unsupported key type for TPM: %v", keyType)
	}
	dkUSSize := uint16(coordSize * 2) // X + Y

	// Step 1: Clean up any existing FDO NV indices and persistent handles
	tpm.CleanupFDOState(s.tpmc)
	slog.Debug("tpm: cleaned up previous FDO state")

	// Step 2: Generate random Unique Strings
	deviceKeyUS := make([]byte, dkUSSize)
	if _, err := rand.Read(deviceKeyUS); err != nil {
		return nil, nil, nil, fmt.Errorf("generating device key unique string: %w", err)
	}
	hmacUS := make([]byte, 32) // HMAC SHA-256 key derivation seed (not curve-dependent)
	if _, err := rand.Read(hmacUS); err != nil {
		return nil, nil, nil, fmt.Errorf("generating HMAC unique string: %w", err)
	}

	// Step 3: Define and write DeviceKey_US NV index (Profile B)
	dkUSName, err := tpm.DefineNVSpace(s.tpmc, tpm.DeviceKeyUSIndex, dkUSSize, tpm.NVProfileB, s.usePlatform)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("define DeviceKey_US NV: %w", err)
	}
	if err := tpm.WriteNV(s.tpmc, tpm.DeviceKeyUSIndex, dkUSName, deviceKeyUS, tpm.NVProfileB); err != nil {
		return nil, nil, nil, fmt.Errorf("write DeviceKey_US NV: %w", err)
	}
	slog.Debug("tpm: provisioned DeviceKey_US NV", "index", fmt.Sprintf("0x%08X", tpm.DeviceKeyUSIndex))

	// Step 3b: Define and write HMAC_US NV index (Profile B)
	hmacUSName, err := tpm.DefineNVSpace(s.tpmc, tpm.HMACUSIndex, 32, tpm.NVProfileB, s.usePlatform)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("define HMAC_US NV: %w", err)
	}
	if err := tpm.WriteNV(s.tpmc, tpm.HMACUSIndex, hmacUSName, hmacUS, tpm.NVProfileB); err != nil {
		return nil, nil, nil, fmt.Errorf("write HMAC_US NV: %w", err)
	}
	slog.Debug("tpm: provisioned HMAC_US NV", "index", fmt.Sprintf("0x%08X", tpm.HMACUSIndex))

	// Step 4: Compute auth policies for both keys
	dkPolicy, err := tpm.ComputeFDOAuthPolicy(s.tpmc, tpm.DeviceKeyUSIndex, dkUSName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compute device key auth policy: %w", err)
	}
	hmacPolicy, err := tpm.ComputeFDOAuthPolicy(s.tpmc, tpm.HMACUSIndex, hmacUSName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compute HMAC key auth policy: %w", err)
	}

	// Step 5: Create ECC signing key (DAK) with spec-compliant template → persist
	dkHandle, pubKey, err := tpm.GenerateSpecECKey(s.tpmc, curveID, hashAlg, deviceKeyUS, dkPolicy)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create spec ECC key: %w", err)
	}
	if err := tpm.PersistKey(s.tpmc, *dkHandle, tpm.DAKHandle); err != nil {
		return nil, nil, nil, fmt.Errorf("persist DAK: %w", err)
	}
	slog.Debug("tpm: created and persisted DAK", "handle", fmt.Sprintf("0x%08X", tpm.DAKHandle))
	_ = pubKey // used later by the FDO protocol via the Key interface

	// Step 6: Create HMAC key with spec-compliant template → persist
	hmacHandle, err := tpm.GenerateSpecHMACKey(s.tpmc, hmacUS, hmacPolicy)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create spec HMAC key: %w", err)
	}
	if err := tpm.PersistKey(s.tpmc, *hmacHandle, tpm.HMACKeyHandle); err != nil {
		return nil, nil, nil, fmt.Errorf("persist HMAC key: %w", err)
	}
	slog.Debug("tpm: created and persisted HMAC key", "handle", fmt.Sprintf("0x%08X", tpm.HMACKeyHandle))

	// Store resolved handles
	s.dakHandle = tpm.DAKHandle
	s.hmacHandle = tpm.HMACKeyHandle

	// Step 7: Create spec-compliant HMAC (SHA-256) from persistent key
	s.h256, err = tpm.NewSpecHmac(s.tpmc, crypto.SHA256, tpm.HMACKeyHandle)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("spec HMAC SHA-256: %w", err)
	}

	// SHA-384 HMAC: use legacy ephemeral key (spec only defines SHA-256 HMAC key)
	s.h384, err = tpm.NewHmac(s.tpmc, crypto.SHA384)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("TPM HMAC SHA-384: %w", err)
	}

	// Step 8: Load persistent DAK as signing key with policy session auth
	s.key, err = tpm.LoadPersistentKey(s.tpmc, tpm.DAKHandle, tpm.DeviceKeyUSIndex)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load persistent DAK: %w", err)
	}

	return s.h256, s.h384, s.key, nil
}

// Save persists all credential data to the single consolidated DCTPM NV index.
//
// Per the spec, DCTPM is a CBOR array:
//   [Magic, Active, Version, DeviceInfo, GUID, RvInfo, PubKeyHash,
//    KeyType, DeviceKeyHandle, HMACKeyHandle]
//
// No separate DCActive or DCOV indices are written.
func (s *tpmStore) Save(dc fdo.DeviceCredential) error {
	dctpm := dctpmNVData{
		Magic:           tpm.DCTPMMagic,
		Active:          true,
		Version:         dc.Version,
		DeviceInfo:      dc.DeviceInfo,
		GUID:            dc.GUID,
		RvInfo:          dc.RvInfo,
		PublicKeyHash:   dc.PublicKeyHash,
		KeyType:         s.keyType,
		DeviceKeyHandle: s.dakHandle,
		HMACKeyHandle:   s.hmacHandle,
	}
	// Default handles if not yet set (e.g. loaded from old-format TPM)
	if dctpm.DeviceKeyHandle == 0 {
		dctpm.DeviceKeyHandle = tpm.DAKHandle
	}
	if dctpm.HMACKeyHandle == 0 {
		dctpm.HMACKeyHandle = tpm.HMACKeyHandle
	}

	dctpmBytes, err := cbor.Marshal(dctpm)
	if err != nil {
		return fmt.Errorf("encoding DCTPM: %w", err)
	}

	// Undefine first in case this is a re-save (TO2 credential update);
	// CBOR size may change if RvInfo or DeviceInfo differs.
	_ = tpm.UndefineNVSpace(s.tpmc, tpm.DCTPMIndex)
	dctpmName, err := tpm.DefineNVSpace(s.tpmc, tpm.DCTPMIndex, uint16(len(dctpmBytes)), tpm.NVProfileDCTPM, s.usePlatform)
	if err != nil {
		return fmt.Errorf("define DCTPM NV: %w", err)
	}
	if err := tpm.WriteNV(s.tpmc, tpm.DCTPMIndex, dctpmName, dctpmBytes, tpm.NVProfileDCTPM); err != nil {
		return fmt.Errorf("write DCTPM NV: %w", err)
	}
	slog.Debug("tpm: wrote consolidated DCTPM NV",
		"size", len(dctpmBytes),
		"guid", fmt.Sprintf("%x", dc.GUID),
		"version", dc.Version,
		"active", true,
	)

	return nil
}

// Load reads credentials from the consolidated DCTPM NV index and loads persistent keys.
//
// This reads:
//   - DCTPM NV: CBOR-decode consolidated structure (Magic, Active, Version,
//     DeviceInfo, GUID, RvInfo, PubKeyHash, KeyType, DeviceKeyHandle, HMACKeyHandle)
//   - Persistent DAK at DeviceKeyHandle with policy session auth
//   - Persistent HMAC key at HMACKeyHandle with policy session auth
func (s *tpmStore) Load() (*fdo.DeviceCredential, hash.Hash, hash.Hash, crypto.Signer, error) {
	dc, err := s.loadFromNV()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("loading credentials from TPM NV: %w", err)
	}

	// Load persistent DAK key with policy session auth
	var loadErr error
	s.key, loadErr = tpm.LoadPersistentKey(s.tpmc, s.dakHandle, tpm.DeviceKeyUSIndex)
	if loadErr != nil {
		return nil, nil, nil, nil, fmt.Errorf("load persistent DAK: %w", loadErr)
	}

	// Create spec HMAC (SHA-256) from persistent key at resolved handle
	s.h256, loadErr = tpm.NewSpecHmac(s.tpmc, crypto.SHA256, s.hmacHandle)
	if loadErr != nil {
		return nil, nil, nil, nil, fmt.Errorf("spec HMAC SHA-256: %w", loadErr)
	}

	// SHA-384 HMAC: use legacy ephemeral key
	s.h384, loadErr = tpm.NewHmac(s.tpmc, crypto.SHA384)
	if loadErr != nil {
		return nil, nil, nil, nil, fmt.Errorf("TPM HMAC SHA-384: %w", loadErr)
	}

	return dc, s.h256, s.h384, s.key, nil
}

// loadFromNV reads credential data from the consolidated DCTPM NV index.
func (s *tpmStore) loadFromNV() (*fdo.DeviceCredential, error) {
	info, err := tpm.ReadNVCredentials(s.tpmc)
	if err != nil {
		return nil, fmt.Errorf("reading NV credentials: %w", err)
	}

	// Verify DCTPM index exists
	if !info.HasDCTPM || len(info.RawDCTPM) == 0 {
		return nil, fmt.Errorf("DCTPM NV not found or empty")
	}

	// Decode consolidated DCTPM CBOR structure
	var dctpm dctpmNVData
	if err := cbor.Unmarshal(info.RawDCTPM, &dctpm); err != nil {
		return nil, fmt.Errorf("decoding DCTPM NV: %w", err)
	}

	// Verify magic
	if dctpm.Magic != tpm.DCTPMMagic {
		return nil, fmt.Errorf("DCTPM magic mismatch: got 0x%08X, want 0x%08X", dctpm.Magic, tpm.DCTPMMagic)
	}

	// Verify device is active
	if !dctpm.Active {
		return nil, fmt.Errorf("device not active (DCActive == false)")
	}

	s.keyType = dctpm.KeyType

	// Resolve DAK handle: use stored value if present, else default
	if dctpm.DeviceKeyHandle != 0 {
		s.dakHandle = dctpm.DeviceKeyHandle
	} else {
		s.dakHandle = tpm.DAKHandle
	}

	// Resolve HMAC handle: use stored value if present, else default
	if dctpm.HMACKeyHandle != 0 {
		s.hmacHandle = dctpm.HMACKeyHandle
	} else {
		s.hmacHandle = tpm.HMACKeyHandle
	}

	// Verify DAK exists at the resolved handle
	if _, err := (tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(s.dakHandle)}).Execute(s.tpmc); err != nil {
		return nil, fmt.Errorf("DAK not found at 0x%08X: %w", s.dakHandle, err)
	}

	// Verify HMAC key exists at the resolved handle
	if _, err := (tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(s.hmacHandle)}).Execute(s.tpmc); err != nil {
		return nil, fmt.Errorf("HMAC key not found at 0x%08X: %w", s.hmacHandle, err)
	}

	dc := &fdo.DeviceCredential{
		Version:       dctpm.Version,
		DeviceInfo:    dctpm.DeviceInfo,
		GUID:          dctpm.GUID,
		RvInfo:        dctpm.RvInfo,
		PublicKeyHash: dctpm.PublicKeyHash,
	}

	slog.Debug("tpm: loaded credentials from consolidated DCTPM NV",
		"guid", fmt.Sprintf("%x", dc.GUID),
		"version", dc.Version,
		"keyType", s.keyType,
		"dakHandle", fmt.Sprintf("0x%08X", s.dakHandle),
		"hmacHandle", fmt.Sprintf("0x%08X", s.hmacHandle),
	)
	return dc, nil
}

func (s *tpmStore) Close() error {
	if s.h256 != nil {
		_ = s.h256.Close()
	}
	if s.h384 != nil {
		_ = s.h384.Close()
	}
	if s.key != nil {
		_ = s.key.Close()
	}
	if s.tpmc != nil {
		return s.tpmc.Close()
	}
	return nil
}
