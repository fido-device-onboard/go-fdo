// SPDX-FileCopyrightText: (C) 2024 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
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

// HelloDeviceProbeMsg is TO2.HelloDeviceProbe (Type 80)
// From Device to Owner - initiates TO2 and can negotiate version
type HelloDeviceProbeMsg struct {
	CapabilityFlags      CapabilityFlags
	GUID                 protocol.GUID
	MaxDeviceMessageSize uint16
	HashTypes            []protocol.HashAlg // Supported hash types
	Sugar                [16]byte           // Random entropy for hash binding
}

// HelloDeviceAck20Msg is TO2.HelloDeviceAck20 (Type 81)
// From Owner to Device - acknowledges probe and prepares for device attestation
type HelloDeviceAck20Msg struct {
	CapabilityFlags      CapabilityFlags
	GUID                 protocol.GUID
	MaxOwnerMessageSize  uint16
	KexSuites            []kex.Suite         // Supported key exchange suites
	CipherSuites         []kex.CipherSuiteID // Supported cipher suites
	NonceTO2ProveDV_Prep protocol.Nonce      // Nonce for ProveDevice20
	HashPrev             protocol.Hash       // Hash of HelloDeviceProbe
}

// ProveDevice20Payload is the EAT payload for TO2.ProveDevice20 (Type 82)
// From Device to Owner - Device proves itself FIRST (key 2.0 change)
type ProveDevice20Payload struct {
	KexSuiteName         kex.Suite         // Selected key exchange suite
	CipherSuiteName      kex.CipherSuiteID // Selected cipher suite
	XAKeyExchange        []byte            // Key exchange parameter A
	NonceTO2ProveOV_Prep protocol.Nonce    // Nonce for ProveOVHdr20
	HashPrev2            protocol.Hash     // Hash of HelloDeviceAck20
}

// ProveOVHdr20Payload is the COSE payload for TO2.ProveOVHdr20 (Type 83)
// From Owner to Device - Owner proves ownership AFTER device verified
// Note: OwnerPubKey and DelegateChain are passed in COSE header unprotected map (like 1.01)
type ProveOVHdr20Payload struct {
	OVHeader            cbor.Bstr[VoucherHeader] // Ownership Voucher header
	NumOVEntries        uint8                    // Number of voucher entries
	HMac                protocol.Hmac            // HMAC of header
	NonceTO2ProveOV     protocol.Nonce           // Nonce from ProveDevice20
	XBKeyExchange       []byte                   // Key exchange parameter B
	MaxOwnerMessageSize uint16
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
// Note: ReplacementHMAC moved to Done20 so client can compute it after receiving GUID/RvInfo
type DeviceSvcInfoRdy20Msg struct {
	MaxOwnerServiceInfoSz *uint16 // nil for default
}

// SetupDevice20Msg is TO2.SetupDevice20 (Type 87)
// From Owner to Device - provides replacement credentials
// Note: This is ENCRYPTED in 2.0
type SetupDevice20Msg struct {
	NonceTO2SetupDV        protocol.Nonce
	ReplacementGUID        *protocol.GUID              // nil for credential reuse
	ReplacementRvInfo      *[][]protocol.RvInstruction // nil for credential reuse
	MaxDeviceServiceInfoSz uint16
}

// DeviceSvcInfo20Msg is TO2.DeviceSvcInfo20 (Type 88)
// From Device to Owner - device service info
// Note: This is ENCRYPTED
type DeviceSvcInfo20Msg struct {
	IsMoreServiceInfo bool
	ServiceInfo       []*serviceinfo.KV
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
// Note: ReplacementHMAC is here (not in DeviceSvcInfoRdy20) so client can compute
// it after receiving GUID/RvInfo from SetupDevice20
type Done20Msg struct {
	NonceTO2SetupDV protocol.Nonce // Echo back nonce from SetupDevice20
	ReplacementHMAC *protocol.Hmac // nil for credential reuse
}

// DoneAck20Msg is TO2.DoneAck20 (Type 91)
// From Owner to Device - owner acknowledges completion
// Note: This is ENCRYPTED
type DoneAck20Msg struct {
	NonceTO2ProveOV protocol.Nonce // Echo back nonce from ProveDevice20
}
