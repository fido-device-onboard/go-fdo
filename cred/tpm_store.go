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

// dcovNVData is the CBOR structure stored in the DCOV NV index.
// It holds the credential fields not in DCTPM (which has GUID + DeviceInfo).
type dcovNVData struct {
	Version       uint16                     `cbor:"0,keyasint"`
	RvInfo        [][]protocol.RvInstruction `cbor:"1,keyasint"`
	PublicKeyHash protocol.Hash              `cbor:"2,keyasint"`
	KeyType       protocol.KeyType           `cbor:"3,keyasint"`
}

type tpmStore struct {
	tpmc        tpm.Closer
	h256        tpm.Hmac
	h384        tpm.Hmac
	key         tpm.Key
	keyType     protocol.KeyType
	usePlatform bool // true = use Platform hierarchy for Profile A/B NV indices
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
//  7. Define DCActive NV (Profile A) → write 0x00 (pending)
//  8. Return spec-compliant HMAC (SHA-256) + legacy HMAC (SHA-384) + persistent key
func (s *tpmStore) NewDI(keyType protocol.KeyType) (hash.Hash, hash.Hash, crypto.Signer, error) {
	s.keyType = keyType

	// Step 1: Clean up any existing FDO NV indices and persistent handles
	tpm.CleanupFDOState(s.tpmc)
	slog.Debug("tpm: cleaned up previous FDO state")

	// Step 2: Generate random Unique Strings
	deviceKeyUS := make([]byte, 64) // ECC P-256: 32 bytes X + 32 bytes Y
	if _, err := rand.Read(deviceKeyUS); err != nil {
		return nil, nil, nil, fmt.Errorf("generating device key unique string: %w", err)
	}
	hmacUS := make([]byte, 32) // HMAC SHA-256 key derivation seed
	if _, err := rand.Read(hmacUS); err != nil {
		return nil, nil, nil, fmt.Errorf("generating HMAC unique string: %w", err)
	}

	// Step 3: Define and write DeviceKey_US NV index (Profile B)
	dkUSName, err := tpm.DefineNVSpace(s.tpmc, tpm.DeviceKeyUSIndex, 64, tpm.NVProfileB, s.usePlatform)
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
	dkHandle, pubKey, err := tpm.GenerateSpecECKey(s.tpmc, tpm2.TPMECCNistP256, tpm2.TPMAlgSHA256, deviceKeyUS, dkPolicy)
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

	// Step 7: Define DCActive NV (Profile A) → write 0x00 (not yet fully initialized)
	dcActiveName, err := tpm.DefineNVSpace(s.tpmc, tpm.DCActiveIndex, 1, tpm.NVProfileA, s.usePlatform)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("define DCActive NV: %w", err)
	}
	if err := tpm.WriteNV(s.tpmc, tpm.DCActiveIndex, dcActiveName, []byte{0x00}, tpm.NVProfileA); err != nil {
		return nil, nil, nil, fmt.Errorf("write DCActive NV: %w", err)
	}
	slog.Debug("tpm: DCActive = 0x00 (DI in progress)")

	// Step 8: Create spec-compliant HMAC (SHA-256) from persistent key
	s.h256, err = tpm.NewSpecHmac(s.tpmc, crypto.SHA256)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("spec HMAC SHA-256: %w", err)
	}

	// SHA-384 HMAC: use legacy ephemeral key (spec only defines SHA-256 HMAC key)
	s.h384, err = tpm.NewHmac(s.tpmc, crypto.SHA384)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("TPM HMAC SHA-384: %w", err)
	}

	// Step 9: Load persistent DAK as signing key with policy session auth
	s.key, err = tpm.LoadPersistentKey(s.tpmc, tpm.DAKHandle, tpm.DeviceKeyUSIndex)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load persistent DAK: %w", err)
	}

	return s.h256, s.h384, s.key, nil
}

// Save persists credential metadata to TPM NV indices after DI completes.
//
// This writes:
//   - DCTPM NV: GUID (16 bytes) + DeviceInfo string
//   - DCOV NV: CBOR-encoded {Version, RvInfo, PublicKeyHash, KeyType}
//   - DCActive NV: updated to 0x01 (device initialized)
//
// No file is written — all credential data lives in the TPM.
func (s *tpmStore) Save(dc fdo.DeviceCredential) error {
	// Write DCTPM NV: GUID + DeviceInfo (Profile B)
	// Undefine first in case this is a re-save (TO2 credential update);
	// size may change if DeviceInfo differs.
	dctpmData := make([]byte, 0, 16+len(dc.DeviceInfo))
	dctpmData = append(dctpmData, dc.GUID[:]...)
	dctpmData = append(dctpmData, []byte(dc.DeviceInfo)...)

	_ = tpm.UndefineNVSpace(s.tpmc, tpm.DCTPMIndex) // ignore error if not defined
	dctpmName, err := tpm.DefineNVSpace(s.tpmc, tpm.DCTPMIndex, uint16(len(dctpmData)), tpm.NVProfileB, s.usePlatform)
	if err != nil {
		return fmt.Errorf("define DCTPM NV: %w", err)
	}
	if err := tpm.WriteNV(s.tpmc, tpm.DCTPMIndex, dctpmName, dctpmData, tpm.NVProfileB); err != nil {
		return fmt.Errorf("write DCTPM NV: %w", err)
	}
	slog.Debug("tpm: wrote DCTPM NV", "guid", fmt.Sprintf("%x", dc.GUID), "info", dc.DeviceInfo)

	// Write DCOV NV: CBOR-encoded credential data (Profile C)
	// Undefine first in case this is a re-save; CBOR size may differ.
	dcovPayload := dcovNVData{
		Version:       dc.Version,
		RvInfo:        dc.RvInfo,
		PublicKeyHash: dc.PublicKeyHash,
		KeyType:       s.keyType,
	}
	dcovBytes, err := cbor.Marshal(dcovPayload)
	if err != nil {
		return fmt.Errorf("encoding DCOV: %w", err)
	}

	_ = tpm.UndefineNVSpace(s.tpmc, tpm.DCOVIndex) // ignore error if not defined
	dcovName, err := tpm.DefineNVSpace(s.tpmc, tpm.DCOVIndex, uint16(len(dcovBytes)), tpm.NVProfileC, s.usePlatform)
	if err != nil {
		return fmt.Errorf("define DCOV NV: %w", err)
	}
	if err := tpm.WriteNV(s.tpmc, tpm.DCOVIndex, dcovName, dcovBytes, tpm.NVProfileC); err != nil {
		return fmt.Errorf("write DCOV NV: %w", err)
	}
	slog.Debug("tpm: wrote DCOV NV", "size", len(dcovBytes))

	// Update DCActive to 0x01 (device fully initialized)
	nvPub, err := (tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(tpm.DCActiveIndex)}).Execute(s.tpmc)
	if err != nil {
		return fmt.Errorf("reading DCActive NV public: %w", err)
	}
	if err := tpm.WriteNV(s.tpmc, tpm.DCActiveIndex, nvPub.NVName, []byte{0x01}, tpm.NVProfileA); err != nil {
		return fmt.Errorf("update DCActive NV: %w", err)
	}
	slog.Debug("tpm: DCActive = 0x01 (device initialized)")

	return nil
}

// Load reads credentials from TPM NV indices and loads persistent keys.
//
// This reads:
//   - DCActive NV: verify device is initialized (0x01)
//   - DCTPM NV: extract GUID + DeviceInfo
//   - DCOV NV: CBOR-decode {Version, RvInfo, PublicKeyHash, KeyType}
//   - Persistent DAK at DAKHandle with policy session auth
//   - Persistent HMAC key at HMACKeyHandle with policy session auth
func (s *tpmStore) Load() (*fdo.DeviceCredential, hash.Hash, hash.Hash, crypto.Signer, error) {
	dc, err := s.loadFromNV()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("loading credentials from TPM NV: %w", err)
	}

	// Load persistent DAK key with policy session auth
	var loadErr error
	s.key, loadErr = tpm.LoadPersistentKey(s.tpmc, tpm.DAKHandle, tpm.DeviceKeyUSIndex)
	if loadErr != nil {
		return nil, nil, nil, nil, fmt.Errorf("load persistent DAK: %w", loadErr)
	}

	// Create spec HMAC (SHA-256) from persistent key
	s.h256, loadErr = tpm.NewSpecHmac(s.tpmc, crypto.SHA256)
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

// loadFromNV reads all credential data from TPM NV indices.
func (s *tpmStore) loadFromNV() (*fdo.DeviceCredential, error) {
	info, err := tpm.ReadNVCredentials(s.tpmc)
	if err != nil {
		return nil, fmt.Errorf("reading NV credentials: %w", err)
	}

	// Verify device is initialized
	if !info.Active {
		return nil, fmt.Errorf("device not initialized (DCActive != 0x01)")
	}

	// Verify persistent keys exist
	if !info.HasDAK {
		return nil, fmt.Errorf("DAK not found at 0x%08X", tpm.DAKHandle)
	}
	if !info.HasHMACKey {
		return nil, fmt.Errorf("HMAC key not found at 0x%08X", tpm.HMACKeyHandle)
	}

	// Read DCOV NV to get full credential data
	if !info.HasDCOV || len(info.DCOVData) == 0 {
		return nil, fmt.Errorf("DCOV NV not found or empty")
	}

	var dcov dcovNVData
	if err := cbor.Unmarshal(info.DCOVData, &dcov); err != nil {
		return nil, fmt.Errorf("decoding DCOV NV: %w", err)
	}
	s.keyType = dcov.KeyType

	dc := &fdo.DeviceCredential{
		Version:       dcov.Version,
		DeviceInfo:    info.DeviceInfo,
		GUID:          info.GUID,
		RvInfo:        dcov.RvInfo,
		PublicKeyHash: dcov.PublicKeyHash,
	}

	slog.Debug("tpm: loaded credentials from NV",
		"guid", fmt.Sprintf("%x", dc.GUID),
		"version", dc.Version,
		"keyType", s.keyType,
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
