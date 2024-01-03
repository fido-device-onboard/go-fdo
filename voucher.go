// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"crypto/x509"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

// Rendezvous Variables
const (
	RVDevOnly    uint64 = 0
	RVOwnerOnly  uint64 = 1
	RVIPAddress  uint64 = 2
	RVDevPort    uint64 = 3
	RVOwnerPort  uint64 = 4
	RVDns        uint64 = 5
	RVSvCertHash uint64 = 6
	RVClCertHash uint64 = 7
	RVUserInput  uint64 = 8
	RVWifiSsid   uint64 = 9
	RVWifiPw     uint64 = 10
	RVMedium     uint64 = 11
	RVProtocol   uint64 = 12
	RVDelaysec   uint64 = 13
	RVBypass     uint64 = 14
	RVExtRV      uint64 = 15
)

// Rendezvous Protocols
const (
	RVProtRest    uint64 = 0
	RVProtHttp    uint64 = 1
	RVProtHttps   uint64 = 2
	RVProtTcp     uint64 = 3
	RVProtTls     uint64 = 4
	RVProtCoapTcp uint64 = 5
	RVProtCoapUdp uint64 = 6
)

// Rendezvous Media
const (
	RVMedEth0    uint64 = 0
	RVMedEth1    uint64 = 1
	RVMedEth2    uint64 = 2
	RVMedEth3    uint64 = 3
	RVMedEth4    uint64 = 4
	RVMedEth5    uint64 = 5
	RVMedEth6    uint64 = 6
	RVMedEth7    uint64 = 7
	RVMedEth8    uint64 = 8
	RVMedEth9    uint64 = 9
	RVMedEthAll  uint64 = 20
	RVMedWifi0   uint64 = 10
	RVMedWifi1   uint64 = 11
	RVMedWifi2   uint64 = 12
	RVMedWifi3   uint64 = 13
	RVMedWifi4   uint64 = 14
	RVMedWifi5   uint64 = 15
	RVMedWifi6   uint64 = 16
	RVMedWifi7   uint64 = 17
	RVMedWifi8   uint64 = 18
	RVMedWifi9   uint64 = 19
	RVMedWifiAll uint64 = 21
)

// Voucher is the top level structure.
//
//	OwnershipVoucher = [
//	    OVProtVer:      protver,           ;; protocol version
//	    OVHeaderTag:    bstr .cbor OVHeader,
//	    OVHeaderHMac:   HMac,              ;; hmac[DCHmacSecret, OVHeader]
//	    OVDevCertChain: OVDevCertChainOrNull,
//	    OVEntryArray:   OVEntries
//	]
//
//	;; Device certificate chain
//	;; use null for Intel® EPID.
//	OVDevCertChainOrNull     = X5CHAIN / null  ;; CBOR null for Intel® EPID device key
//
//	;; Ownership voucher entries array
//	OVEntries = [ * OVEntry ]
type Voucher struct {
	Version   uint16
	Header    cbor.Bstr[VoucherHeader]
	Hmac      Hmac
	CertChain *[]*x509.Certificate
	Entries   []cbor.Tag[cose.Sign1[VoucherEntryPayload]]
}

// VoucherHeader is the Ownership Voucher header, also used in TO1 protocol.
//
//	OVHeader = [
//	    OVHProtVer:        protver,        ;; protocol version
//	    OVGuid:            Guid,           ;; guid
//	    OVRVInfo:          RendezvousInfo, ;; rendezvous instructions
//	    OVDeviceInfo:      tstr,           ;; DeviceInfo
//	    OVPubKey:          PublicKey,      ;; mfg public key
//	    OVDevCertChainHash:OVDevCertChainHashOrNull
//	]
//
//	;; Hash of Device certificate chain
//	;; use null for Intel® EPID
//	OVDevCertChainHashOrNull = Hash / null     ;; CBOR null for Intel® EPID device key
type VoucherHeader struct {
	Version       uint64
	Guid          []byte
	RvInfo        []RvInstruction
	DeviceInfo    string
	PublicKey     PublicKey
	CertChainHash *Hash
}

// VoucherEntryPayload is an entry in a voucher's list of recorded transfers.
//
// ;; ...each entry is a COSE Sign1 object with a payload
// OVEntry = CoseSignature
// $COSEProtectedHeaders //= (
//
//	1: OVSignType
//
// )
// $COSEPayloads /= (
//
//	OVEntryPayload
//
// )
// ;; ... each payload contains the hash of the previous entry
// ;; and the signature of the public key to verify the next signature
// ;; (or the Owner, in the last entry).
// OVEntryPayload = [
//
//	OVEHashPrevEntry: Hash,
//	OVEHashHdrInfo:   Hash,  ;; hash[GUID||DeviceInfo] in header
//	OVEExtra:         null / bstr .cbor OVEExtraInfo
//	OVEPubKey:        PublicKey
//
// ]
//
// OVEExtraInfo = { * OVEExtraInfoType: bstr }
// OVEExtraInfoType = int
//
// ;;OVSignType = Supporting COSE signature types
type VoucherEntryPayload struct {
	PreviousHash Hash
	HeaderHash   Hash
	Extra        *cbor.Bstr[ExtraInfo]
	PublicKey    PublicKey
}

type ExtraInfo map[int][]byte

type RvInstruction struct {
	Variables []RvVariable
}

type RvVariable struct {
	Variable uint64
	Value    []byte
}
