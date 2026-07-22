// SPDX-FileCopyrightText: (C) 2024 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// FDO 2.0 TO2 message flow (device proves first, anti-DoS):
//
//	HelloDeviceProbe(80) -> HelloDeviceAck20(81) ->
//	ProveDevice20(82) -> ProveOVHdr20(83) ->
//	GetOVNextEntry20(84) -> OVNextEntry20(85) ->
//	DeviceSvcInfoRdy20(86) -> SetupDevice20(87) ->
//	DeviceSvcInfo20(88) -> OwnerSvcInfo20(89) ->
//	Done20(90) -> DoneAck20(91)

// HelloDeviceProbeMsg is sent by the device to initiate FDO 2.0 TO2 (type 80).
// It includes capability flags for version and feature negotiation.
type HelloDeviceProbeMsg struct {
	CapabilityFlags CapabilityFlags
	GUID            protocol.GUID
	MaxDeviceMsgSz  uint16
	HashTypes       []protocol.HashAlg `cbor:",omitempty"`
	Sugar           []byte             `cbor:",omitempty"`
}

// HelloDeviceAck20Msg is the server's response to HelloDeviceProbe (type 81).
// It includes the server's capability flags and the crypto suites it supports.
type HelloDeviceAck20Msg struct {
	CapabilityFlags     CapabilityFlags
	GUID                protocol.GUID
	MaxOwnerMsgSz       uint16
	KexSuites           []kex.Suite
	CipherSuites        []kex.CipherSuiteID
	NonceTO2ProveDVPrep protocol.Nonce
	HashPrev            protocol.Hash
}

// ProveDevice20Payload is the payload of the device's EAT in ProveDevice20
// (type 82). In FDO 2.0, the device proves itself FIRST.
type ProveDevice20Payload struct {
	KexSuiteName        kex.Suite
	CipherSuiteName     kex.CipherSuiteID
	XAKeyExchange       []byte
	NonceTO2ProveOVPrep protocol.Nonce
	HashPrev2           protocol.Hash
}

// ProveOVHdr20Payload is the payload of the owner's COSE Sign1 in
// ProveOVHdr20 (type 83). After the device has proven itself, the owner
// proves ownership. Owner pub key and delegate chain are in COSE
// unprotected headers.
type ProveOVHdr20Payload struct {
	OVH             cbor.Bstr[VoucherHeader]
	NumOVEntries    uint8
	OVHHmac         protocol.Hmac
	NonceTO2ProveOV protocol.Nonce
	XBKeyExchange   []byte
	MaxOwnerMsgSz   uint16
}

// GetOVNextEntry20Msg requests a voucher entry by index (type 84).
type GetOVNextEntry20Msg struct {
	OVEntryNum int
}

// OVNextEntry20Msg provides a voucher entry (type 85).
type OVNextEntry20Msg struct {
	OVEntryNum int
	OVEntry    cose.Sign1Tag[VoucherEntryPayload, []byte]
}

// DeviceSvcInfoRdy20Msg signals device readiness for service info (type 86).
// In FDO 2.0, the replacement HMAC is moved to Done20.
type DeviceSvcInfoRdy20Msg struct {
	MaxOwnerSvcInfoSz *uint16 `cbor:",omitempty"`
}

// SetupDevice20Msg provides replacement credentials (type 87).
// Encrypted. GUID and RvInfo pointers are nil for credential reuse.
type SetupDevice20Msg struct {
	NonceTO2SetupDV    protocol.Nonce
	ReplacementGUID    *protocol.GUID              `cbor:",omitempty"`
	ReplacementRvInfo  *[][]protocol.RvInstruction `cbor:",omitempty"`
	MaxDeviceSvcInfoSz uint16
}

// DeviceSvcInfo20Msg carries device service info (type 88). Encrypted.
type DeviceSvcInfo20Msg struct {
	IsMoreServiceInfo bool
	ServiceInfo       []*serviceinfo.KV
}

// OwnerSvcInfo20Msg carries owner service info (type 89). Encrypted.
type OwnerSvcInfo20Msg struct {
	IsMoreServiceInfo bool
	IsDone            bool
	ServiceInfo       []*serviceinfo.KV
}

// Done20Msg signals TO2 completion from the device (type 90). Encrypted.
// In FDO 2.0, the replacement HMAC is included here (moved from
// DeviceSvcInfoRdy).
type Done20Msg struct {
	NonceTO2SetupDV protocol.Nonce
	ReplacementHmac *protocol.Hmac `cbor:",omitempty"`
}

// DoneAck20Msg is the server's acknowledgment of TO2 completion (type 91).
// Encrypted.
type DoneAck20Msg struct {
	NonceTO2ProveOV protocol.Nonce
}
