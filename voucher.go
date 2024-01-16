// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"

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

// ErrCryptoVerifyFailed indicates that the wrapping error originated from a
// case of cryptographic verification failing rather than a broken invariant.
var ErrCryptoVerifyFailed = errors.New("cryptographic verification failed")

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

func (v *Voucher) shallowClone() *Voucher {
	return &Voucher{
		Version: v.Version,
		Header: cbor.NewBstr(VoucherHeader{
			Version:         v.Header.Val.Version,
			Guid:            v.Header.Val.Guid,
			RvInfo:          v.Header.Val.RvInfo,
			DeviceInfo:      v.Header.Val.DeviceInfo,
			ManufacturerKey: v.Header.Val.ManufacturerKey.clone(),
			CertChainHash:   v.Header.Val.CertChainHash,
		}),
		Hmac:      v.Hmac,
		CertChain: v.CertChain,
		Entries:   v.Entries,
	}
}

// VerifyHeader checks that the OVHeader was not modified by comparing the HMAC
// generated using the secret from the device credentials.
func (v *Voucher) VerifyHeader(deviceCredential Signer) error {
	return deviceCredential.HmacVerify(v.Hmac, &v.Header.Val)
}

// VerifyCertChain using trusted roots. If roots is nil then the last
// certificate in the chain will be implicitly trusted.
func (v *Voucher) VerifyCertChain(roots *x509.CertPool) error {
	if v.CertChain == nil {
		return nil
	}
	if len(*v.CertChain) == 0 {
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
		return fmt.Errorf("%w: %w", ErrCryptoVerifyFailed, err)
	}

	return nil
}

// VerifyCertChainHash uses the hash in the voucher header to verify that the
// certificate chain of the voucher has not been tampered with. This method
// should therefore not be called before VerifyHeader.
func (v *Voucher) VerifyCertChainHash() error {
	switch {
	case v.CertChain == nil && v.Header.Val.CertChainHash == nil:
		return nil
	case v.CertChain == nil || v.Header.Val.CertChainHash == nil:
		return errors.New("device cert chain and hash must both be present or both be absent")
	}

	cchash := v.Header.Val.CertChainHash

	var digest hash.Hash
	switch cchash.Algorithm {
	case Sha256Hash:
		digest = sha256.New()
	case Sha384Hash:
		digest = sha512.New384()
	default:
		return fmt.Errorf("unsupported hash algorithm: %s", cchash.Algorithm)
	}

	for _, cert := range *v.CertChain {
		if _, err := digest.Write(cert.Raw); err != nil {
			return fmt.Errorf("error computing hash: %w", err)
		}
	}

	if !hmac.Equal(digest.Sum(nil), cchash.Value) {
		return fmt.Errorf("%w: certificate chain hash did not match", ErrCryptoVerifyFailed)
	}
	return nil
}

// VerifyManufacturerKey by using a public key hash (generally stored as part
// of the device credential).
func (v *Voucher) VerifyManufacturerKey(keyHash Hash) error {
	var digest hash.Hash
	switch keyHash.Algorithm {
	case Sha256Hash:
		digest = sha256.New()
	case Sha384Hash:
		digest = sha512.New384()
	default:
		return fmt.Errorf("unsupported hash algorithm for hashing manufacturer public key: %s", keyHash.Algorithm)
	}
	if err := cbor.NewEncoder(digest).Encode(&v.Header.Val.ManufacturerKey); err != nil {
		return fmt.Errorf("error computing hash of manufacturer public key: %w", err)
	}
	if !hmac.Equal(digest.Sum(nil), keyHash.Value) {
		return fmt.Errorf("%w: manufacturer public key hash did not match", ErrCryptoVerifyFailed)
	}
	return nil
}

// VerifyEntries checks the chain of signatures on each voucher entry payload.
func (v *Voucher) VerifyEntries() error {
	// Parse the public key from the voucher header
	mfgKey, err := v.Header.Val.ManufacturerKey.Public()
	if err != nil {
		return fmt.Errorf("error parsing manufacturer public key: %w", err)
	}

	// Voucher may have never been extended since manufacturing
	if len(v.Entries) == 0 {
		return nil
	}

	// For entry 0, the previous hash is computed on OVHeader||OVHeaderHMac
	var initialHash hash.Hash
	switch alg := v.Entries[0].Payload.Val.PreviousHash.Algorithm; alg {
	case Sha256Hash:
		initialHash = sha256.New()
	case Sha384Hash:
		initialHash = sha512.New384()
	default:
		return fmt.Errorf("unsupported hash algorithm for hashing initial previous hash of entry list: %s", alg)
	}
	if err := cbor.NewEncoder(initialHash).Encode(&v.Header.Val); err != nil {
		return fmt.Errorf("error computing initial entry hash, writing encoded header: %w", err)
	}
	if err := cbor.NewEncoder(initialHash).Encode(v.Hmac); err != nil {
		return fmt.Errorf("error computing initial entry hash, writing encoded header hmac: %w", err)
	}

	// Precompute SHA256/SHA384 checksum for header info
	headerInfo := append(v.Header.Val.Guid[:], []byte(v.Header.Val.DeviceInfo)...)
	headerInfo256Sum := sha256.Sum256(headerInfo)
	headerInfo384Sum := sha512.Sum384(headerInfo)
	headerInfoSums := map[HashAlg][]byte{
		Sha256Hash: headerInfo256Sum[:],
		Sha384Hash: headerInfo384Sum[:],
	}

	// Validate all entries
	return validateNextEntry(mfgKey, initialHash, headerInfoSums, 0, v.Entries)
}

// Validate each entry recursively
func validateNextEntry(prevOwnerKey crypto.PublicKey, prevHash hash.Hash, headerInfo map[HashAlg][]byte, i int, entries []cose.Sign1Tag[VoucherEntryPayload]) error {
	entry := entries[0].Untag()

	// Check payload has a valid COSE signature from the previous owner key
	if ok, err := entry.Verify(prevOwnerKey, nil); err != nil {
		return fmt.Errorf("COSE signature for entry %d could not be verified: %w", i, err)
	} else if !ok {
		return fmt.Errorf("%w: COSE signature for entry %d did not match previous owner key", ErrCryptoVerifyFailed, i)
	}

	// Check payload's HeaderHash matches voucher header as hash[GUID||DeviceInfo]
	headerHash := entry.Payload.Val.HeaderHash
	if !hmac.Equal(headerHash.Value, headerInfo[headerHash.Algorithm]) {
		return fmt.Errorf("%w: voucher entry payload %d header hash did not match", ErrCryptoVerifyFailed, i-1)
	}

	// Check payload's PreviousHash matches the previous entry
	if !hmac.Equal(prevHash.Sum(nil), entry.Payload.Val.PreviousHash.Value) {
		return fmt.Errorf("%w: voucher entry payload %d previous hash did not match", ErrCryptoVerifyFailed, i-1)
	}

	// Succeed if no more entries
	if len(entries[1:]) == 0 {
		return nil
	}

	// Parse owner key for next iteration
	ownerKey, err := entry.Payload.Val.PublicKey.Public()
	if err != nil {
		return fmt.Errorf("error parsing public key of entry %d: %w", i-1, err)
	}

	// Hash payload for next iteration
	var payloadHash hash.Hash
	switch alg := entries[1].Payload.Val.PreviousHash.Algorithm; alg {
	case Sha256Hash:
		payloadHash = sha256.New()
	case Sha384Hash:
		payloadHash = sha512.New384()
	default:
		return fmt.Errorf("unsupported hash algorithm for hashing voucher entry payload: %s", alg)
	}
	if err := cbor.NewEncoder(payloadHash).Encode(&entry.Payload.Val); err != nil {
		return fmt.Errorf("error computing hash of voucher entry payload: %w", err)
	}

	// Validate the next entry recursively
	return validateNextEntry(ownerKey, payloadHash, headerInfo, i+1, entries[1:])
}

// DevicePublicKey extracts the device's public key from from the certificate
// chain. Before calling this method, the voucher must be fully verified. For
// certain key types, such as Intel EPID, the public key will be nil.
func (v *Voucher) DevicePublicKey() (crypto.PublicKey, error) {
	if v.CertChain == nil {
		return nil, nil
	}
	if len(*v.CertChain) == 0 {
		return nil, errors.New("empty cert chain")
	}
	return (*v.CertChain)[len(*v.CertChain)-1].PublicKey, nil
}

// OwnerPublicKey extracts the voucher owner's public key from either the
// header or the entries list.
func (v *Voucher) OwnerPublicKey() (crypto.PublicKey, error) {
	if len(v.Entries) == 0 {
		return v.Header.Val.ManufacturerKey.Public()
	}
	return v.Entries[len(v.Entries)-1].Payload.Val.PublicKey.Public()
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

// ExtraInfo may be used to pass additional supply-chain information along with
// the Ownership Voucher. The Device implicitly verifies the plaintext of
// OVEExtra along with the verification of the Ownership Voucher. An Owner
// which trusts the Device' verification of the Ownership Voucher may also
// choose to trust OVEExtra.
type ExtraInfo map[int][]byte

// ExtendVoucher adds a new signed voucher entry to the list and returns the
// new extended vouchers. Vouchers should be treated as immutable structures.
func ExtendVoucher[T PublicKeyOrChain](v *Voucher, owner crypto.PrivateKey, nextOwner T, extra ExtraInfo) (*Voucher, error) {
	// This performs a shallow clone, which allows arrays, maps, and pointers
	// to have their contents modified and both the original and copied voucher
	// will see the modification. However, this function does not perform a
	// deep copy/clone of the voucher, because vouchers are generally not used
	// as mutable entities. Every reference type in a voucher - keys, device
	// certificate chain, etc. - is protected by some other signature or hash,
	// so it doesn't make sense to modify.
	xv := v.shallowClone()

	// Each key in the Ownership Voucher must copy the public key type from the
	// manufacturer’s key in OVHeader.OVPubKey, hash, and encoding (e.g., all
	// RSA2048RESTR, all RSAPKCS 3072, all ECDSA secp256r1 or all ECDSA
	// secp384r1). This restriction permits a Device with limited crypto
	// capabilities to verify all the signatures.
	ownerPub := owner.(interface{ Public() crypto.PublicKey }).Public()
	switch ownerPub := ownerPub.(type) {
	case *ecdsa.PublicKey:
		if mfgKey, err := v.Header.Val.ManufacturerKey.Public(); err != nil {
			return nil, fmt.Errorf("error parsing manufacturer key from header: %w", err)
		} else if mfgPubKey, ok := mfgKey.(*ecdsa.PublicKey); !ok {
			return nil, fmt.Errorf("owner key for voucher extension did not match the type of the manufacturer key")
		} else if mfgPubKey.Curve != ownerPub.Curve {
			return nil, fmt.Errorf("owner key for voucher extension did not match the type and size/curve of the manufacturer key")
		}
	case *rsa.PublicKey:
		if mfgKey, err := v.Header.Val.ManufacturerKey.Public(); err != nil {
			return nil, fmt.Errorf("error parsing manufacturer key from header: %w", err)
		} else if mfgPubKey, ok := mfgKey.(*rsa.PublicKey); !ok {
			return nil, fmt.Errorf("owner key for voucher extension did not match the type of the manufacturer key")
		} else if mfgPubKey.Size() != ownerPub.Size() {
			return nil, fmt.Errorf("owner key for voucher extension did not match the type and size/curve of the manufacturer key")
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %T", ownerPub)
	}

	// Create the next owner PublicKey structure
	nextOwnerPublicKey := PublicKey{Type: v.Header.Val.ManufacturerKey.Type}
	switch nextOwner := any(nextOwner).(type) {
	case []*x509.Certificate:
		chain := make([]*Certificate, len(nextOwner))
		for i, cert := range nextOwner {
			cert := cert
			chain[i] = (*Certificate)(cert)
		}
		body, err := cbor.Marshal(chain)
		if err != nil {
			return nil, fmt.Errorf("error marshaling next owner public key with X5Chain encoding: %w", err)
		}

		nextOwnerPublicKey.Encoding = X5ChainKeyEnc
		nextOwnerPublicKey.Body = body
	case *ecdsa.PublicKey, *rsa.PublicKey:
		body, err := x509.MarshalPKIXPublicKey(nextOwner)
		if err != nil {
			return nil, fmt.Errorf("error marshaling next owner public key with X509 encoding: %w", err)
		}

		nextOwnerPublicKey.Encoding = X509KeyEnc
		nextOwnerPublicKey.Body = body

	default:
		return nil, fmt.Errorf("unsupported next owner public key: must be *ecdsa.PublicKey, *rsa.PublicKey, or []*x509.Certificate")
	}

	// Calculate the hash of the voucher header info
	headerInfo := sha512.Sum384(append(v.Header.Val.Guid[:], []byte(v.Header.Val.DeviceInfo)...))
	headerHash := Hash{Algorithm: Sha384Hash, Value: headerInfo[:]}

	// Calculate the hash of the previous entry
	digest := sha512.New384()
	if len(v.Entries) == 0 {
		// For entry 0, the previous hash is computed on OVHeader||OVHeaderHMac
		if err := cbor.NewEncoder(digest).Encode(&v.Header.Val); err != nil {
			return nil, fmt.Errorf("error computing initial entry hash, writing encoded header: %w", err)
		}
		if err := cbor.NewEncoder(digest).Encode(v.Hmac); err != nil {
			return nil, fmt.Errorf("error computing initial entry hash, writing encoded header hmac: %w", err)
		}
	} else {
		if err := cbor.NewEncoder(digest).Encode(&v.Entries[len(v.Entries)-1].Payload.Val); err != nil {
			return nil, fmt.Errorf("error computing hash of voucher entry payload: %w", err)
		}
	}
	prevHash := Hash{Algorithm: Sha384Hash, Value: digest.Sum(nil)}

	// Create and sign next entry
	entry := cose.Sign1Tag[VoucherEntryPayload]{
		Header: cose.Header{},
		Payload: cbor.NewBstrPtr(VoucherEntryPayload{
			PreviousHash: prevHash,
			HeaderHash:   headerHash,
			Extra:        cbor.NewBstrPtr(extra),
			PublicKey:    nextOwnerPublicKey.clone(),
		}),
	}
	var signOpts crypto.SignerOpts
	if v.Header.Val.ManufacturerKey.Type == RsaPssKeyType {
		signOpts = &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA384,
		}
	}
	if err := entry.Sign(owner, nil, signOpts); err != nil {
		return nil, fmt.Errorf("error signing voucher entry payload: %w", err)
	}

	xv.Entries = append(xv.Entries, entry)
	return xv, nil
}
