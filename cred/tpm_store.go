// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

//go:build tpm || tpmsim

package cred

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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
// DCGuid, DCRVInfo, DCPubKeyHash, DeviceKeyType, DeviceKeyHandle, HMACKeyHandle,
// DCMinFirmwareRev].
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
	DeviceKeyType   uint8                      `cbor:"7,keyasint"` // 0 = DAK (spec); not the protocol key type
	DeviceKeyHandle uint32                     `cbor:"8,keyasint"`
	HMACKeyHandle   uint32                     `cbor:"9,keyasint"`
	MinFirmwareRev  uint64                     `cbor:"10,keyasint"` // DCMinFirmwareRev; 0 = no minimum
}

// dctpmNVRead is dctpmNVData for decoding: DCMinFirmwareRev may be absent
// (an older ten-item DCTPM), which the spec says to read as 0. Writers always
// write all eleven items.
type dctpmNVRead struct {
	Magic           uint32                     `cbor:"0,keyasint"`
	Active          bool                       `cbor:"1,keyasint"`
	Version         uint16                     `cbor:"2,keyasint"`
	DeviceInfo      string                     `cbor:"3,keyasint"`
	GUID            protocol.GUID              `cbor:"4,keyasint"`
	RvInfo          [][]protocol.RvInstruction `cbor:"5,keyasint"`
	PublicKeyHash   protocol.Hash              `cbor:"6,keyasint"`
	DeviceKeyType   uint8                      `cbor:"7,keyasint"`
	DeviceKeyHandle uint32                     `cbor:"8,keyasint"`
	HMACKeyHandle   uint32                     `cbor:"9,keyasint"`
	MinFirmwareRev  uint64                     `cbor:"10,keyasint,omitempty"`
}

// rvMinFirmwareRev returns the highest RVMinFirmwareRev (RV tag 18) in the
// device RendezvousInfo, or 0.
func rvMinFirmwareRev(rvInfo [][]protocol.RvInstruction) uint64 {
	var rev uint64
	for _, d := range protocol.ParseDeviceRvInfo(rvInfo) {
		rev = max(rev, d.MinFirmwareRev)
	}
	return rev
}

// storedMinFirmwareRev returns DCMinFirmwareRev from the DCTPM currently in
// the TPM, and whether a valid DCTPM was found.
func (s *tpmStore) storedMinFirmwareRev() (uint64, bool) {
	info, err := tpm.ReadNVCredentials(s.tpmc)
	if err != nil || !info.HasDCTPM {
		return 0, false
	}
	var cur dctpmNVRead
	if err := tpm.DecodeDCTPM(info.RawDCTPM, &cur); err != nil || cur.Magic != tpm.DCTPMMagic {
		return 0, false
	}
	return cur.MinFirmwareRev, true
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
	useChildMethod bool   // true = child-of-SRK (default), false = primary with unique string
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
	// Default to Owner hierarchy (Platform is locked post-boot on Linux).
	// Set FDO_TPM_PLATFORM_HIERARCHY=1 to use Platform hierarchy instead
	// (only works during manufacturing or early boot when Platform is unlocked).
	usePlatform := os.Getenv("FDO_TPM_PLATFORM_HIERARCHY") == "1"
	// Default to child-of-SRK method; set FDO_TPM_KEY_METHOD=primary to
	// use primary key with unique string (rollback-resistant but WinPE-incompatible).
	useChildMethod := os.Getenv("FDO_TPM_KEY_METHOD") != "primary"
	return &tpmStore{tpmc: t, usePlatform: usePlatform, useChildMethod: useChildMethod}, nil
}

// NewDI provisions persistent keys and returns HMAC + signing key handles
// for Device Initialization.
//
// Supports two creation methods (same outcome — persistent key at handle):
//   - useChildMethod=true:  Child key under SRK (WinPE-compatible, RNG-based)
//   - useChildMethod=false: Primary key with unique string (rollback-resistant)
//
// Both produce: persistent ECC signing key at DAKHandle and HMAC key at
// HMACKeyHandle, with userWithAuth=1, adminWithPolicy=1, empty authValue.
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

	// Step 1: Clean up any existing FDO NV indices and persistent handles
	tpm.CleanupFDOState(s.tpmc)
	slog.Debug("tpm: cleaned up previous FDO state")

	// Step 2: Create keys using the selected method
	if s.useChildMethod {
		// Approach 1: Child key under deterministic SRK (WinPE-compatible)
		slog.Info("tpm: creating keys as children of SRK (child method)")

		srk, err := tpm.CreateSRK(s.tpmc)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("create SRK: %w", err)
		}
		defer func() { _, _ = (tpm2.FlushContext{FlushHandle: srk.Handle}).Execute(s.tpmc) }()

		// Create + persist DAK
		dkHandle, _, err := tpm.CreateChildECKey(s.tpmc, *srk, curveID, hashAlg)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("create child ECC key: %w", err)
		}
		if err := tpm.PersistKey(s.tpmc, *dkHandle, tpm.DAKHandle); err != nil {
			return nil, nil, nil, fmt.Errorf("persist DAK: %w", err)
		}
		slog.Info("tpm: DAK persisted (child method)", "handle", fmt.Sprintf("0x%08X", tpm.DAKHandle))

		// Create + persist HMAC key
		hmacHandle, err := tpm.CreateChildHMACKey(s.tpmc, *srk, hashAlg)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("create child HMAC key: %w", err)
		}
		if err := tpm.PersistKey(s.tpmc, *hmacHandle, tpm.HMACKeyHandle); err != nil {
			return nil, nil, nil, fmt.Errorf("persist HMAC key: %w", err)
		}
		slog.Info("tpm: HMAC key persisted (child method)", "handle", fmt.Sprintf("0x%08X", tpm.HMACKeyHandle))
	} else {
		// Approach 2: Primary key with unique string (rollback-resistant)
		slog.Info("tpm: creating keys as primaries with unique strings (primary method)")

		dkUSSize := uint16(coordSize * 2) // X + Y
		deviceKeyUS := make([]byte, dkUSSize)
		if _, err := rand.Read(deviceKeyUS); err != nil {
			return nil, nil, nil, fmt.Errorf("generating device key unique string: %w", err)
		}
		hmacUS := make([]byte, coordSize) // 32 (SHA-256) or 48 (SHA-384) bytes
		if _, err := rand.Read(hmacUS); err != nil {
			return nil, nil, nil, fmt.Errorf("generating HMAC unique string: %w", err)
		}

		dkHandle, _, err := tpm.GenerateSpecECKey(s.tpmc, curveID, hashAlg, deviceKeyUS)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("create primary ECC key: %w", err)
		}
		if err := tpm.PersistKey(s.tpmc, *dkHandle, tpm.DAKHandle); err != nil {
			return nil, nil, nil, fmt.Errorf("persist DAK: %w", err)
		}
		slog.Info("tpm: DAK persisted (primary method)", "handle", fmt.Sprintf("0x%08X", tpm.DAKHandle))

		hmacHandle, err := tpm.GenerateSpecHMACKey(s.tpmc, hashAlg, hmacUS)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("create primary HMAC key: %w", err)
		}
		if err := tpm.PersistKey(s.tpmc, *hmacHandle, tpm.HMACKeyHandle); err != nil {
			return nil, nil, nil, fmt.Errorf("persist HMAC key: %w", err)
		}
		slog.Info("tpm: HMAC key persisted (primary method)", "handle", fmt.Sprintf("0x%08X", tpm.HMACKeyHandle))
	}

	// Store resolved handles
	s.dakHandle = tpm.DAKHandle
	s.hmacHandle = tpm.HMACKeyHandle

	// Step 3: HMAC-SHA256 and HMAC-SHA384 from the persistent HMAC key
	if err := s.openHMACs(keyType == protocol.Secp384r1KeyType); err != nil {
		return nil, nil, nil, err
	}
	var err error

	// Step 7: Load persistent DAK as signing key (empty password auth)
	s.key, err = tpm.LoadPersistentKey(s.tpmc, tpm.DAKHandle)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load persistent DAK: %w", err)
	}

	return s.h256, s.h384, s.key, nil
}

// Save persists all credential data to the single consolidated DCTPM NV index.
//
// Per the spec, DCTPM is a CBOR array: [Magic, Active, Version, DeviceInfo,
// GUID, RvInfo, PubKeyHash, DeviceKeyType, DeviceKeyHandle, HMACKeyHandle,
// DCMinFirmwareRev].
//
// DCMinFirmwareRev is seeded from RVMinFirmwareRev when no DCTPM exists yet
// (DI) and otherwise preserved, never decreased (TO2 replaces RvInfo).
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
		DeviceKeyType:   tpm.DeviceKeyTypeDAK,
		DeviceKeyHandle: s.dakHandle,
		HMACKeyHandle:   s.hmacHandle,
	}
	if cur, ok := s.storedMinFirmwareRev(); ok {
		dctpm.MinFirmwareRev = cur
	} else {
		dctpm.MinFirmwareRev = rvMinFirmwareRev(dc.RvInfo)
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

	// Single in-place NV_Write when the index exists (TO2 credential update),
	// so an interruption leaves the old or the new credentials, never none.
	if err := tpm.WriteDCTPM(s.tpmc, dctpmBytes, s.usePlatform); err != nil {
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

	// Load persistent DAK key (empty password auth, userWithAuth=1)
	var loadErr error
	s.key, loadErr = tpm.LoadPersistentKey(s.tpmc, s.dakHandle)
	if loadErr != nil {
		return nil, nil, nil, nil, fmt.Errorf("load persistent DAK: %w", loadErr)
	}

	ec, _ := s.key.Public().(*ecdsa.PublicKey)
	if loadErr = s.openHMACs(ec != nil && ec.Curve == elliptic.P384()); loadErr != nil {
		return nil, nil, nil, nil, loadErr
	}

	return dc, s.h256, s.h384, s.key, nil
}

// openHMACs sets h256 and h384 from the persistent HMAC key at s.hmacHandle.
// The key's hash matches the Device key (TPM spec Table 10) and the Device
// uses that hash for every HMAC it computes (DI.SetHMAC, TO2 replacement), so
// only the matching one is ever used; the other fails when used (the TPM
// refuses it). A P-384 device provisioned before the HMAC key followed the
// Device key has an HMAC-SHA256 key; for it, h384 is the old key re-derived
// from a fixed template (not persisted, not in DCTPM), so its existing
// HMAC-SHA384 vouchers still verify.
func (s *tpmStore) openHMACs(deviceP384 bool) error {
	var err error
	if s.h256, err = tpm.NewSpecHmac(s.tpmc, crypto.SHA256, s.hmacHandle); err != nil {
		return fmt.Errorf("spec HMAC SHA-256: %w", err)
	}
	pub, err := (tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(s.hmacHandle)}).Execute(s.tpmc)
	if err != nil {
		return fmt.Errorf("ReadPublic HMAC key: %w", err)
	}
	keyHash := tpm2.TPMAlgSHA256
	if pt, err := pub.OutPublic.Contents(); err == nil {
		keyHash = pt.NameAlg
		if kh, err := pt.Parameters.KeyedHashDetail(); err == nil && kh.Scheme.Scheme == tpm2.TPMAlgHMAC {
			if d, err := kh.Scheme.Details.HMAC(); err == nil {
				keyHash = d.HashAlg
			}
		}
	}
	if keyHash == tpm2.TPMAlgSHA384 || !deviceP384 {
		if s.h384, err = tpm.NewSpecHmac(s.tpmc, crypto.SHA384, s.hmacHandle); err != nil {
			return fmt.Errorf("spec HMAC SHA-384: %w", err)
		}
		return nil
	}
	slog.Warn("tpm: P-384 device with an HMAC-SHA256 key (provisioned before the HMAC key followed the Device key); HMAC-SHA384 uses a re-derived legacy key",
		"handle", fmt.Sprintf("0x%08X", s.hmacHandle))
	if s.h384, err = tpm.NewHmac(s.tpmc, crypto.SHA384); err != nil {
		return fmt.Errorf("TPM HMAC SHA-384: %w", err)
	}
	return nil
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
	var dctpm dctpmNVRead
	if err := tpm.DecodeDCTPM(info.RawDCTPM, &dctpm); err != nil {
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
		"deviceKeyType", dctpm.DeviceKeyType,
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
