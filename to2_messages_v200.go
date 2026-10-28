// SPDX-FileCopyrightText: (C) 2024 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"bytes"
	"fmt"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// FDO 2.0 TO2 Message Structures
//
// Key difference from 1.01: Device proves itself FIRST (anti-DoS measure)
// Flow: HelloDeviceProbe(80) -> HelloDeviceAck20(81) -> ProveDevice20(82) ->
//       ProveOVHdr20(83) -> GetOVNextEntry20(84) -> OVNextEntry20(85) ->
//       DeviceSvcInfoRdy20(86) -> SetupDevice20(87) -> DeviceSvcInfo20(88) ->
//       OwnerSvcInfo20(89) -> Done20(90) -> DoneAck20(91)

// hashMessage computes the hashPrev/hashPrev2 value over an encoded TO2
// message, as transmitted.
func hashMessage(alg protocol.HashAlg, msg []byte) (protocol.Hash, error) {
	switch alg {
	case protocol.Sha256Hash, protocol.Sha384Hash:
	default:
		return protocol.Hash{}, fmt.Errorf("unsupported hash type %d", alg)
	}
	h := alg.HashFunc().New()
	_, _ = h.Write(msg)
	return protocol.Hash{Algorithm: alg, Value: h.Sum(nil)}, nil
}

// newProveDevice20EAT builds the TO2.ProveDevice20 EAT: the nonce claim is
// NonceTO2ProveDv and the EAT-FDO claim is TO2ProveDevicePayload20.
func newProveDevice20EAT(guid protocol.GUID, nonceTO2ProveDv protocol.Nonce, payload ProveDevice20Payload) eatoken {
	return newEAT(guid, nonceTO2ProveDv, payload, nil)
}

// parseProveDevice20EAT checks the EAT nonce and UEID claims of a
// signature-verified TO2.ProveDevice20 and extracts its payload.
func parseProveDevice20EAT(eat eatoken, nonceTO2ProveDv protocol.Nonce, guid protocol.GUID) (*ProveDevice20Payload, error) {
	nonce, ok := eat[eatNonceClaim].([]byte)
	if !ok {
		return nil, fmt.Errorf("TO2.ProveDevice20 EAT missing nonce claim")
	}
	if !bytes.Equal(nonce, nonceTO2ProveDv[:]) {
		return nil, fmt.Errorf("TO2.ProveDevice20 EAT nonce does not match NonceTO2ProveDv")
	}
	ueid, ok := eat[eatUeidClaim].([]byte)
	if !ok {
		return nil, fmt.Errorf("TO2.ProveDevice20 EAT missing UEID claim")
	}
	if !bytes.Equal(ueid, append([]byte{eatRandUeid}, guid[:]...)) {
		return nil, fmt.Errorf("TO2.ProveDevice20 EAT UEID does not match the device GUID")
	}
	fdoClaim, ok := eat[eatFdoClaim]
	if !ok {
		return nil, fmt.Errorf("TO2.ProveDevice20 EAT missing FDO claim")
	}
	raw, err := cbor.Marshal(fdoClaim)
	if err != nil {
		return nil, fmt.Errorf("error re-encoding TO2.ProveDevice20 FDO claim: %w", err)
	}
	var payload ProveDevice20Payload
	if err := cbor.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("error decoding TO2ProveDevicePayload20: %w", err)
	}
	return &payload, nil
}

// HelloDeviceProbeMsg is TO2.HelloDeviceProbe (Type 80)
// From Device to Owner - initiates TO2 and can negotiate version
type HelloDeviceProbeMsg struct {
	CapabilityFlags
	GUID                 protocol.GUID
	MaxDeviceMessageSize uint16
	HashTypes            []protocol.HashAlg // Supported hash types
	Sugar                [16]byte           // Random entropy for hash binding
}

// HelloDeviceAck20Msg is TO2.HelloDeviceAck20 (Type 81)
// From Owner to Device - acknowledges probe and prepares for device attestation
type HelloDeviceAck20Msg struct {
	CapabilityFlags
	GUID                protocol.GUID
	MaxOwnerMessageSize uint16
	KexSuites           []kex.Suite         // Supported key exchange suites
	CipherSuites        []kex.CipherSuiteID // Supported cipher suites
	NonceTO2ProveDVPrep protocol.Nonce      // Nonce for ProveDevice20
	HashPrev            protocol.Hash       // Hash of HelloDeviceProbe
}

// ProveDevice20Payload is TO2ProveDevicePayload20, carried in the EAT-FDO
// claim of the TO2.ProveDevice20 (Type 82) EAT. The EAT nonce claim carries
// NonceTO2ProveDv (from TO2.HelloDeviceAck20).
// From Device to Owner - Device proves itself FIRST (key 2.0 change)
type ProveDevice20Payload struct {
	KexSuiteName        kex.Suite         // Selected key exchange suite
	CipherSuiteName     kex.CipherSuiteID // Selected cipher suite
	XAKeyExchange       []byte            // Key exchange parameter A
	NonceTO2ProveOVPrep protocol.Nonce    // Device-generated nonce, returned in ProveOVHdr20
	HashPrev2           protocol.Hash     // Hash of the received HelloDeviceAck20 message
}

// ProveOVHdr20Payload is the COSE payload for TO2.ProveOVHdr20 (Type 83)
// From Owner to Device - Owner proves ownership AFTER device verified
type ProveOVHdr20Payload struct {
	OVHeader            cbor.Bstr[VoucherHeader] // Ownership Voucher header
	NumOVEntries        uint8                    // Number of voucher entries
	HMac                protocol.Hmac            // HMAC of header
	NonceTO2ProveOV     protocol.Nonce           // Nonce from ProveDevice20
	XBKeyExchange       []byte                   // Key exchange parameter B
	MaxOwnerMessageSize uint16
	OwnerPubKey         protocol.PublicKey       // Owner key, as convenience to Device
	DelegateChain       *[]*cbor.X509Certificate // CertChainOrNull: Delegate chain, if any
}

// GetOVNextEntry20Msg is TO2.GetOVNextEntry20 (Type 84)
// From Device to Owner - requests next voucher entry
type GetOVNextEntry20Msg struct {
	OVEntryNum uint8
}

// OVNextEntry20Msg is TO2.OVNextEntry20 (Type 85)
// From Owner to Device - provides voucher entry
type OVNextEntry20Msg struct {
	OVEntryNum uint8
	OVEntry    []byte // COSE_Sign1 encoded voucher entry
}

// DeviceSvcInfoRdy20Msg is TO2.DeviceServiceInfoRdy20 (Type 86)
// From Device to Owner - signals ready for service info exchange
// Note: This is ENCRYPTED in 2.0
type DeviceSvcInfoRdy20Msg struct {
	ReplacementHMac       *protocol.Hmac // Not used (FDO 2.0 Errata 1): always nil, ignored
	MaxOwnerServiceInfoSz *uint16        // nil for default
	NonceTO2SetupDVPrep   protocol.Nonce // Device-generated, returned in SetupDevice20 and DoneAck20
}

// SetupDevice20 DispositionCode values.
const (
	DispResale    uint8 = 1 // Use new credentials in ReplacementCred
	DispCredReuse uint8 = 2 // Credential reuse protocol
	DispDisable   uint8 = 3 // Disable FDO after use
)

// ReplacementCred20 is the ReplacementCred of TO2.SetupDevice20, present
// only for DispResale.
type ReplacementCred20 struct {
	RvInfo          [][]protocol.RvInstruction // RendezvousInfo replacement
	GUID            protocol.GUID              // GUID replacement
	NonceTO2SetupDv protocol.Nonce             // From DeviceSvcInfoRdy20; proves freshness
	Owner2PubKey    protocol.PublicKey         // Replacement for Owner key
}

// SetupDevice20Payload is the COSE payload of TO2.SetupDevice20 (Type 87).
// For DispResale it is signed by the Owner2 key; otherwise by the key that
// signed TO2.ProveOVHdr20 (FDO 2.0 Errata 1).
// From Owner to Device - Note: This is ENCRYPTED in 2.0
type SetupDevice20Payload struct {
	DispositionCode        uint8
	ReplacementCred        *ReplacementCred20 // nil unless DispResale
	MaxDeviceServiceInfoSz *uint16            // nil for default
}

// DeviceSvcInfo20Msg is TO2.DeviceSvcInfo20 (Type 88)
// From Device to Owner - device service info
// Note: This is ENCRYPTED
type DeviceSvcInfo20Msg struct {
	ReplacementHMacOrNull *protocol.Hmac // Not used (FDO 2.0 Errata 1): always nil, ignored
	IsMoreServiceInfo     bool
	ServiceInfo           []*serviceinfo.KV
}

// OwnerSvcInfo20Msg is TO2.OwnerSvcInfo20 (Type 89)
// From Owner to Device - owner service info
// Note: This is ENCRYPTED
type OwnerSvcInfo20Msg struct {
	IsMoreServiceInfo bool
	IsDone            bool
	ServiceInfo       []*serviceinfo.KV
}

// Done20Msg is TO2.Done20 (Type 90)
// From Device to Owner - device signals completion
// Note: This is ENCRYPTED
// Note: the only message carrying the ReplacementHMac (FDO 2.0 Errata 1), so
// the Device can compute it after receiving the new credentials in SetupDevice20
type Done20Msg struct {
	NonceTO2ProveDv protocol.Nonce // Echo of the Owner's nonce from HelloDeviceAck20
	ReplacementHMAC *protocol.Hmac // nil unless DispResale (or Device declines resale)
}

// DoneAck20Msg is TO2.DoneAck20 (Type 91)
// From Owner to Device - owner acknowledges completion
// Note: This is ENCRYPTED
type DoneAck20Msg struct {
	NonceTO2SetupDv protocol.Nonce // Echo of the Device's nonce from DeviceSvcInfoRdy20
}
