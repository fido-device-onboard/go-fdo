// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"crypto/x509"
	"errors"
	"fmt"

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

// Certificate is a newtype for x509.Certificate implementing proper CBOR
// encoding.
type Certificate x509.Certificate

// X509 is a helper function for conversion.
func (c *Certificate) X509() *x509.Certificate { return (*x509.Certificate)(c) }

func (c *Certificate) MarshalCBOR() ([]byte, error) {
	if c == nil {
		return cbor.Marshal(nil)
	}
	return cbor.Marshal(c.Raw)
}

func (c *Certificate) UnmarshalCBOR(data []byte) error {
	if c == nil {
		return errors.New("cannot unmarshal to a nil pointer")
	}
	var der []byte
	if err := cbor.Unmarshal(data, &der); err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("error parsing x509 certificate DER-encoded bytes: %w", err)
	}
	*c = Certificate(*cert)
	return nil
}

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
	CertChain *[]*Certificate
	Entries   []cose.Sign1Tag[VoucherEntryPayload]
}

// VerifyHeader checks that the OVHeader was not modified by comparing the HMAC
// generated using the secret from the device credentials.
func (v *Voucher) VerifyHeader(deviceCredential Signer) error {
	return deviceCredential.HmacVerify(v.Hmac, v.Header.Val)
}

// VerifyCertChain using trusted roots. If roots is nil then the last
// certificate in the chain will be implicitly trusted.
func (v *Voucher) VerifyCertChain(roots *x509.CertPool) error {
	if v.CertChain == nil || len(*v.CertChain) == 0 {
		return errors.New("empty cert chain")
	}
	chain := *v.CertChain

	// All all intermediates (if any) to a pool
	intermediates := x509.NewCertPool()
	if len(chain) > 2 {
		for _, cert := range chain[1 : len(chain)-1] {
			intermediates.AddCert(cert.X509())
		}
	}

	// Trust last certificate in chain if roots is nil
	if roots == nil {
		roots = x509.NewCertPool()
		roots.AddCert(chain[len(chain)-1].X509())
	}

	// Return the result of (*x509.Certificate).Verify
	if _, err := chain[0].X509().Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}); err != nil {
		return err
	}

	// TODO: Check that cert chain hash matches value in OVHeader
	return nil
}

// VerifyEntries checks the COSE signature of every voucher entry payload using
// the manufacturer public key from the header.
func (v *Voucher) VerifyEntries() error {
	key := v.Header.Val.ManufacturerKey.Public
	for i, entry := range v.Entries {
		if ok, err := entry.Untag().Verify(key, nil); err != nil {
			return fmt.Errorf("COSE signature for entry %d could not be verified: %w", i, err)
		} else if !ok {
			return fmt.Errorf("COSE signature for entry %d did not match manufacturer key", i)
		}
	}
	return nil
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
	Version         uint16
	Guid            Guid
	RvInfo          [][]RvVariable
	DeviceInfo      string
	ManufacturerKey PublicKey
	CertChainHash   *Hash
}

type RvVariable struct {
	Variable uint64
	Value    []byte
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
