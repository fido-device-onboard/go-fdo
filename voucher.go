// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"reflect"
	"slices"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// ErrCryptoVerifyFailed indicates that the wrapping error originated from a
// case of cryptographic verification failing rather than a broken invariant.
var ErrCryptoVerifyFailed = errors.New("cryptographic verification failed")

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
	Hmac      protocol.Hmac
	CertChain *[]*cbor.X509Certificate
	Entries   []cose.Sign1Tag[VoucherEntryPayload, []byte]
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
	GUID            protocol.GUID
	RvInfo          [][]protocol.RvInstruction
	DeviceInfo      string
	ManufacturerKey protocol.PublicKey
	CertChainHash   *protocol.Hash
}

// Equal compares two ownership voucher headers for equality.
//
//nolint:gocyclo
func (ovh *VoucherHeader) Equal(otherOVH *VoucherHeader) bool {
	if ovh.Version != otherOVH.Version {
		return false
	}
	if !bytes.Equal(ovh.GUID[:], otherOVH.GUID[:]) {
		return false
	}
	if !slices.EqualFunc(ovh.RvInfo, otherOVH.RvInfo, func(directivesA, directivesB []protocol.RvInstruction) bool {
		return slices.EqualFunc(directivesA, directivesB, func(instA, instB protocol.RvInstruction) bool {
			return instA.Variable == instB.Variable && bytes.Equal(instA.Value, instB.Value)
		})
	}) {
		return false
	}
	if ovh.DeviceInfo != otherOVH.DeviceInfo {
		return false
	}
	if ovh.ManufacturerKey.Type != otherOVH.ManufacturerKey.Type {
		return false
	}
	if ovh.ManufacturerKey.Encoding != otherOVH.ManufacturerKey.Encoding {
		return false
	}
	if !bytes.Equal(ovh.ManufacturerKey.Body, otherOVH.ManufacturerKey.Body) {
		return false
	}
	if (ovh.CertChainHash == nil && otherOVH.CertChainHash != nil) || (ovh.CertChainHash != nil && otherOVH.CertChainHash == nil) {
		return false
	}
	if ovh.CertChainHash != nil {
		if ovh.CertChainHash.Algorithm != otherOVH.CertChainHash.Algorithm {
			return false
		}
		if !bytes.Equal(ovh.CertChainHash.Value, otherOVH.CertChainHash.Value) {
			return false
		}
	}
	return true
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
	PreviousHash protocol.Hash
	HeaderHash   protocol.Hash
	Extra        *cbor.Bstr[map[int][]byte]
	PublicKey    protocol.PublicKey
}

func (v *Voucher) shallowClone() *Voucher {
	return &Voucher{
		Version: v.Version,
		Header: *cbor.NewBstr(VoucherHeader{
			Version:         v.Header.Val.Version,
			GUID:            v.Header.Val.GUID,
			RvInfo:          v.Header.Val.RvInfo,
			DeviceInfo:      v.Header.Val.DeviceInfo,
			ManufacturerKey: v.Header.Val.ManufacturerKey,
			CertChainHash:   v.Header.Val.CertChainHash,
		}),
		Hmac:      v.Hmac,
		CertChain: v.CertChain,
		Entries:   v.Entries,
	}
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
	return (*v.CertChain)[0].PublicKey, nil
}

// OwnerPublicKey extracts the voucher owner's public key from either the
// header or the entries list.
func (v *Voucher) OwnerPublicKey() (crypto.PublicKey, error) {
	if len(v.Entries) == 0 {
		return v.Header.Val.ManufacturerKey.Public()
	}
	return v.Entries[len(v.Entries)-1].Payload.Val.PublicKey.Public()
}

// VerifyCrypto checks that a voucher is valid cryptographically in its header
// and extensions.
//
// A verified voucher is not inherently trustworthy to an owner service, which
// should verify that it trusts the manufacturer (signer of first extension)
// and the root CA of the device certificate chain.
func (v *Voucher) VerifyCrypto(o VerifyOptions) error {
	// Verify ownership voucher header
	if err := v.VerifyHeader(o.HmacSha256, o.HmacSha384); err != nil {
		return fmt.Errorf("bad ownership voucher header from TO2.ProveOVHdr: %w", err)
	}

	// Verify that the owner service corresponds to the most recent device
	// initialization performed by checking that the voucher header has a GUID
	// and/or manufacturer key corresponding to the stored device credentials.
	if err := v.VerifyManufacturerKey(o.MfgPubKeyHash); err != nil {
		return fmt.Errorf("bad ownership voucher header from TO2.ProveOVHdr: manufacturer key: %w", err)
	}

	// Verify each entry in the voucher's list by performing iterative
	// signature and hash (header and GUID/devInfo) checks.
	if err := v.VerifyEntries(); err != nil {
		return fmt.Errorf("bad ownership voucher entries from TO2.ProveOVHdr: %w", err)
	}

	// Ensure that the voucher entry chain ends with given owner key.
	//
	// Note that this check is REQUIRED in this case, because the the owner public
	// key from the ProveOVHdr message's unprotected headers is used to
	// validate its COSE signature. If the public key were not to match the
	// last entry of the voucher, then it would not be known that ProveOVHdr
	// was signed by the intended owner service.
	ownerPub := v.Header.Val.ManufacturerKey
	if len(v.Entries) > 0 {
		ownerPub = v.Entries[len(v.Entries)-1].Payload.Val.PublicKey
	}
	expectedOwnerPub, err := ownerPub.Public()
	if err != nil {
		return fmt.Errorf("error parsing last public key of ownership voucher: %w", err)
	}
	if !o.OwnerPubToValidate.(interface{ Equal(crypto.PublicKey) bool }).Equal(expectedOwnerPub) {
		return fmt.Errorf("owner public key did not match last entry in ownership voucher")
	}

	// If no to1d blob was given, then immmediately return. This will be the
	// case when RV bypass was used.
	if o.To1d == nil {
		return nil
	}

	// If the TO1.RVRedirect signature does not verify, the Device must assume
	// that a man in the middle is monitoring its traffic, and fail TO2
	// immediately with an error code message.
	//
	// When a delegate is used, the TO1d is signed by the delegate key, not the
	// owner key. Check if a delegate chain is present in the TO1d unprotected
	// header and verify against the delegate key if so.
	verifyKey := expectedOwnerPub
	var delegatePubKey protocol.PublicKey
	if found, err := o.To1d.Unprotected.Parse(cose.Label{Int64: 258}, &delegatePubKey); found && err == nil {
		// Delegate chain present - verify against delegate key
		delegateKey, err := delegatePubKey.Public()
		if err != nil {
			return fmt.Errorf("error parsing delegate key from TO1d: %w", err)
		}
		verifyKey = delegateKey
	}

	if ok, err := o.To1d.Verify(verifyKey, nil, nil); err != nil {
		return fmt.Errorf("error verifying to1d signature: %w", err)
	} else if !ok {
		return fmt.Errorf("%w: to1d signature verification failed", ErrCryptoVerifyFailed)
	}

	return nil
}

// VerifyOptions are used to verify the cryptographic signing of a voucher and
// its extensions.
type VerifyOptions struct {
	// HMACs for verifying the voucher header
	HmacSha256, HmacSha384 hash.Hash

	// The expected hash of the first entry in the chain
	MfgPubKeyHash protocol.Hash

	// The public key presented in message 61 which was already used for
	// signature verification but needs to match the end of the entry chain
	OwnerPubToValidate crypto.PublicKey

	// FUTURE: Optional delegate certificate chain

	// May be nil in the case of RV bypass
	To1d *cose.Sign1[protocol.To1d, []byte]
}

// VerifyHeader checks that the OVHeader was not modified by comparing the HMAC
// generated using the secret from the device credentials.
func (v *Voucher) VerifyHeader(hmacSha256, hmacSha384 hash.Hash) error {
	return hmacVerify(hmacSha256, hmacSha384, v.Hmac, &v.Header.Val)
}

// VerifyDeviceCertChain using trusted roots. If roots is nil then the last
// certificate in the chain will be implicitly trusted.
func (v *Voucher) VerifyDeviceCertChain(roots *x509.CertPool) error {
	if v.CertChain == nil {
		return nil
	}
	if len(*v.CertChain) == 0 {
		return errors.New("empty cert chain")
	}
	chain := make([]*x509.Certificate, len(*v.CertChain))
	for i, cert := range *v.CertChain {
		chain[i] = (*x509.Certificate)(cert)
	}
	return verifyCertChain(chain, roots)
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
	digest := cchash.Algorithm.HashFunc().New()
	for _, cert := range *v.CertChain {
		if _, err := digest.Write(cert.Raw); err != nil {
			return fmt.Errorf("error computing hash: %w", err)
		}
	}
	if !hmac.Equal(digest.Sum(nil), cchash.Value) {
		// Find the first certificate to include in error
		var cert *x509.Certificate
		if len(*v.CertChain) > 0 {
			cert = (*x509.Certificate)((*v.CertChain)[0])
		}
		return NewCertificateValidationError(
			CertValidationErrorChainHashMismatch,
			cert,
			"voucher certificate chain hash",
			"certificate chain hash did not match voucher header",
		)
	}
	return nil
}

// VerifyManufacturerKey by using a public key hash (generally stored as part
// of the device credential).
func (v *Voucher) VerifyManufacturerKey(keyHash protocol.Hash) error {
	var digest hash.Hash
	switch keyHash.Algorithm {
	case protocol.Sha256Hash:
		digest = sha256.New()
	case protocol.Sha384Hash:
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

// VerifyManufacturerCertChain using trusted roots. If roots is nil then the
// last certificate in the chain will be implicitly trusted.
//
// If the manufacturer public key is X509 encoded rather than X5Chain, then
// this method will fail if a non-nil root certificate pool is given.
func (v *Voucher) VerifyManufacturerCertChain(roots *x509.CertPool) error {
	chain, err := v.Header.Val.ManufacturerKey.Chain()
	if err != nil {
		return fmt.Errorf("error parsing manufacturer public key: %w", err)
	}
	if chain == nil {
		if roots == nil {
			return nil
		}
		return fmt.Errorf("manufacturer public key could not be verified against given roots, because it was not an X5Chain")
	}
	return verifyCertChain(chain, roots)
}

// VerifyEntries checks the chain of signatures on each voucher entry payload.
func (v *Voucher) VerifyEntries() error {
	// Parse the public key from the voucher header
	mfgPubKey, err := v.Header.Val.ManufacturerKey.Public()
	if err != nil {
		return fmt.Errorf("error parsing manufacturer public key: %w", err)
	}

	// Voucher may have never been extended since manufacturing
	if len(v.Entries) == 0 {
		return nil
	}

	// Header info is the concatenation of GUID and DeviceInfo
	headerInfo := append(v.Header.Val.GUID[:], []byte(v.Header.Val.DeviceInfo)...)

	// The algorithm used for hashing entries should always match the one used
	// during the very first extension
	alg := v.Entries[0].Payload.Val.PreviousHash.Algorithm

	var initialHash hash.Hash
	var headerInfoHash []byte
	switch alg {
	case protocol.Sha256Hash:
		initialHash = sha256.New()
		sum := sha256.Sum256(headerInfo)
		headerInfoHash = sum[:]
	case protocol.Sha384Hash:
		initialHash = sha512.New384()
		sum := sha512.Sum384(headerInfo)
		headerInfoHash = sum[:]
	default:
		return fmt.Errorf("unsupported hash algorithm for hashing initial previous hash of entry list: %s", alg)
	}

	// For entry 0, the previous hash is computed on OVHeader||OVHeaderHMac
	if err := cbor.NewEncoder(initialHash).Encode(&v.Header.Val); err != nil {
		return fmt.Errorf("error computing initial entry hash, writing encoded header: %w", err)
	}
	if err := cbor.NewEncoder(initialHash).Encode(v.Hmac); err != nil {
		return fmt.Errorf("error computing initial entry hash, writing encoded header hmac: %w", err)
	}

	// Validate all entries
	return validateNextEntry(mfgPubKey, alg, initialHash, headerInfoHash, 0, v.Entries)
}

// Validate each entry recursively
func validateNextEntry(prevOwnerKey crypto.PublicKey, alg protocol.HashAlg, prevHash hash.Hash, headerInfoHash []byte, i int, entries []cose.Sign1Tag[VoucherEntryPayload, []byte]) error {
	entry := entries[0].Untag()

	// Check payload has a valid COSE signature from the previous owner key
	if ok, err := entry.Verify(prevOwnerKey, nil, nil); err != nil {
		return fmt.Errorf("COSE signature for entry %d could not be verified: %w", i, err)
	} else if !ok {
		return fmt.Errorf("%w: COSE signature for entry %d did not match previous owner key", ErrCryptoVerifyFailed, i)
	}

	// Check payload's HeaderHash matches voucher header as hash[GUID||DeviceInfo]
	headerHash := entry.Payload.Val.HeaderHash
	if headerHash.Algorithm != alg {
		return fmt.Errorf("%w: voucher entry payload %d header hash was computed with %s instead of %s",
			ErrCryptoVerifyFailed, i-1, headerHash.Algorithm, alg)
	}
	if !hmac.Equal(headerHash.Value, headerInfoHash) {
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
	prevHash.Reset()
	if err := cbor.NewEncoder(prevHash).Encode(entry.Tag()); err != nil {
		return fmt.Errorf("error computing hash of voucher entry payload: %w", err)
	}

	// Validate the next entry recursively
	return validateNextEntry(ownerKey, alg, prevHash, headerInfoHash, i+1, entries[1:])
}

// VerifyOwnerCertChain validates the certificate chain of the owner public key
// using trusted roots. If roots is nil then the last certificate in the chain
// will be implicitly trusted. If the public key is X509 encoded rather than
// X5Chain, then this method will fail if a non-nil root certificate pool is
// given.
func (e *VoucherEntryPayload) VerifyOwnerCertChain(roots *x509.CertPool) error {
	chain, err := e.PublicKey.Chain()
	if err != nil {
		return fmt.Errorf("error parsing voucher entry's owner public key: %w", err)
	}
	if chain == nil {
		if roots == nil {
			return nil
		}
		return fmt.Errorf("voucher entry's owner public key could not be verified against given roots, because it was not an X5Chain")
	}
	return verifyCertChain(chain, roots)
}

func verifyCertChain(chain []*x509.Certificate, roots *x509.CertPool) error {
	// Check certificate expiration for all certificates in chain
	now := time.Now()
	for i, cert := range chain {
		if now.Before(cert.NotBefore) {
			return NewCertificateValidationError(
				CertValidationErrorNotYetValid,
				cert,
				"certificate chain",
				fmt.Sprintf("certificate %d not yet valid (NotBefore: %v)", i, cert.NotBefore),
			)
		}
		if now.After(cert.NotAfter) {
			return NewCertificateValidationError(
				CertValidationErrorExpired,
				cert,
				"certificate chain",
				fmt.Sprintf("certificate %d expired (NotAfter: %v)", i, cert.NotAfter),
			)
		}

		// Call custom certificate checker if configured
		if certificateChecker != nil {
			var certErr *CertificateValidationError

			// Try to use enhanced checker by checking for the specific method signature
			// We use interface{} to avoid the conflicting method signature issue
			if checkerVal := reflect.ValueOf(certificateChecker); checkerVal.IsValid() {
				method := checkerVal.MethodByName("CheckCertificate")
				if method.IsValid() {
					methodType := method.Type()
					// Check if the method returns *CertificateValidationError
					if methodType.NumOut() == 1 && methodType.Out(0) == reflect.TypeOf((*CertificateValidationError)(nil)).Elem() {
						// This is an enhanced checker
						result := method.Call([]reflect.Value{reflect.ValueOf(cert)})
						if len(result) == 1 && !result[0].IsNil() {
							certErr = result[0].Interface().(*CertificateValidationError)
						}
					} else {
						// This is a legacy checker
						result := method.Call([]reflect.Value{reflect.ValueOf(cert)})
						if len(result) == 1 && !result[0].IsNil() {
							if err, ok := result[0].Interface().(error); ok {
								// Wrap legacy error
								if isRevocationError(err) {
									certErr = NewCertificateValidationError(
										CertValidationErrorRevoked,
										cert,
										"certificate chain",
										err.Error(),
									)
								} else {
									certErr = NewCertificateValidationError(
										CertValidationErrorCustomCheck,
										cert,
										"certificate chain",
										err.Error(),
									)
								}
							}
						}
					}
				}
			}

			if certErr != nil {
				certErr.Context = "certificate chain"
				return certErr
			}
		}
	}

	// All all intermediates (if any) to a pool
	intermediates := x509.NewCertPool()
	if len(chain) > 2 {
		for _, cert := range chain[1 : len(chain)-1] {
			intermediates.AddCert(cert)
		}
	}

	// Trust last certificate in chain if roots is nil
	if roots == nil {
		roots = x509.NewCertPool()
		roots.AddCert(chain[len(chain)-1])
	}

	// Return the result of (*x509.Certificate).Verify
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}); err != nil {
		return NewCertificateValidationError(
			CertValidationErrorSignature,
			chain[0],
			"certificate chain",
			fmt.Sprintf("signature verification failed: %v", err),
		)
	}

	return nil
}

// ExtendVoucher adds a new signed voucher entry to the list and returns the
// new extended voucher. Vouchers should be treated as immutable structures.
//
// ExtraInfo may be used to pass additional supply-chain information along with
// the Ownership Voucher. The Device implicitly verifies the plaintext of
// OVEExtra along with the verification of the Ownership Voucher. An Owner
// which trusts the Device' verification of the Ownership Voucher may also
// choose to trust OVEExtra.
func ExtendVoucher[T protocol.PublicKeyOrChain](v *Voucher, owner crypto.Signer, nextOwner T, extra map[int][]byte) (*Voucher, error) { //nolint:gocyclo
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
	ownerPubKey := owner.Public()
	switch ownerPub := ownerPubKey.(type) {
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

	// Owner key must match the last signature
	expectedOwnerPubKey, err := v.OwnerPublicKey()
	if err != nil {
		return nil, fmt.Errorf("error getting owner public key of voucher to extend: %w", err)
	}
	if !ownerPubKey.(interface {
		Equal(x crypto.PublicKey) bool
	}).Equal(expectedOwnerPubKey) {
		return nil, fmt.Errorf("owner key for signing does not match the last signature of the voucher to be extended")
	}

	// Create the next owner PublicKey structure
	asCOSE := v.Header.Val.ManufacturerKey.Encoding == protocol.CoseKeyEnc
	if _, ok := any(nextOwner).([]*x509.Certificate); ok {
		asCOSE = false
	}
	nextOwnerPublicKey, err := protocol.NewPublicKey(v.Header.Val.ManufacturerKey.Type, nextOwner, asCOSE)
	if err != nil {
		return nil, fmt.Errorf("error marshaling next owner public key: %w", err)
	}

	// Select the appropriate hash algorithm
	devicePubKey := (*v.CertChain)[0].PublicKey
	alg, err := hashAlgFor(devicePubKey, ownerPubKey)
	if err != nil {
		return nil, fmt.Errorf("error selecting the appropriate hash algorithm: %w", err)
	}

	// Calculate the hash of the voucher header info
	headerInfo := append(v.Header.Val.GUID[:], []byte(v.Header.Val.DeviceInfo)...)
	digest := alg.HashFunc().New()
	_, _ = digest.Write(headerInfo)
	headerHash := protocol.Hash{Algorithm: alg, Value: digest.Sum(nil)}

	// Calculate the hash of the previous entry
	digest.Reset()
	if len(v.Entries) == 0 {
		// For entry 0, the previous hash is computed on OVHeader||OVHeaderHMac
		if err := cbor.NewEncoder(digest).Encode(&v.Header.Val); err != nil {
			return nil, fmt.Errorf("error computing initial entry hash, writing encoded header: %w", err)
		}
		if err := cbor.NewEncoder(digest).Encode(v.Hmac); err != nil {
			return nil, fmt.Errorf("error computing initial entry hash, writing encoded header hmac: %w", err)
		}
	} else {
		if err := cbor.NewEncoder(digest).Encode(v.Entries[len(v.Entries)-1].Tag()); err != nil {
			return nil, fmt.Errorf("error computing hash of voucher entry payload: %w", err)
		}
	}
	prevHash := protocol.Hash{Algorithm: alg, Value: digest.Sum(nil)}

	// Create and sign next entry
	usePSS := v.Header.Val.ManufacturerKey.Type == protocol.RsaPssKeyType
	entry, err := newSignedEntry(owner, usePSS, VoucherEntryPayload{
		PreviousHash: prevHash,
		HeaderHash:   headerHash,
		Extra:        cbor.NewBstr(extra),
		PublicKey:    *nextOwnerPublicKey,
	})
	if err != nil {
		return nil, err
	}
	xv.Entries = append(xv.Entries, *entry)
	return xv, nil
}

// hashAlgFor determines the appropriate hash algorithm to use based on device
// and owner attestation key types. Recommended configurations (see section
// 3.3.2) have matching strengths between device and owner attestation keys and
// therefore the RSA key size should match the device public key or should be
// 2048 for secp256r1 and 3072 for secp384r1.
func hashAlgFor(devicePubKey, ownerPubKey crypto.PublicKey) (protocol.HashAlg, error) {
	deviceSize, err := hashSizeForPubKey(devicePubKey)
	if err != nil {
		return 0, fmt.Errorf("device attestation key: %w", err)
	}
	ownerSize, err := hashSizeForPubKey(ownerPubKey)
	if err != nil {
		return 0, fmt.Errorf("owner attestation key: %w", err)
	}
	switch min(deviceSize, ownerSize) {
	case 256:
		return protocol.Sha256Hash, nil
	case 384:
		return protocol.Sha384Hash, nil
	default:
		panic("only hash sizes of 256 and 384 are included in FDO")
	}
}

func hashSizeForPubKey(pubKey crypto.PublicKey) (int, error) {
	switch key := pubKey.(type) {
	case *ecdsa.PublicKey:
		switch curve := key.Curve; curve {
		case elliptic.P256():
			return 256, nil
		case elliptic.P384():
			return 384, nil
		default:
			return 0, fmt.Errorf("unsupported elliptic curve: %s", curve.Params().Name)
		}

	case *rsa.PublicKey:
		return key.Size(), nil

	default:
		return 0, fmt.Errorf("unsupported key type: %T", key)
	}
}

func newSignedEntry(owner crypto.Signer, usePSS bool, payload VoucherEntryPayload) (*cose.Sign1Tag[VoucherEntryPayload, []byte], error) {
	var entry cose.Sign1Tag[VoucherEntryPayload, []byte]
	entry.Payload = cbor.NewByteWrap(payload)

	signOpts, err := signOptsFor(owner, usePSS)
	if err != nil {
		return nil, err
	}

	if err := entry.Sign(owner, nil, nil, signOpts); err != nil {
		return nil, fmt.Errorf("error signing voucher entry payload: %w", err)
	}

	return &entry, nil
}
