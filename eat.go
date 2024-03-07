// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"github.com/fido-device-onboard/go-fdo/cose"
)

// Entity Attestation Tokens (EAT)
// https://datatracker.ietf.org/doc/draft-ietf-rats-eat/

// EAT UEID types
//
//	+======+======+=====================================================+
//	| Type | Type | Specification                                       |
//	| Byte | Name |                                                     |
//	+======+======+=====================================================+
//	| 0x01 | RAND | This is a 128, 192 or 256-bit random number         |
//	|      |      | generated once and stored in the entity.  This      |
//	|      |      | may be constructed by concatenating enough          |
//	|      |      | identifiers to make up an equivalent number of      |
//	|      |      | random bits and then feeding the concatenation      |
//	|      |      | through a cryptographic hash function.  It may      |
//	|      |      | also be a cryptographic quality random number       |
//	|      |      | generated once at the beginning of the life of      |
//	|      |      | the entity and stored.  It MUST NOT be smaller      |
//	|      |      | than 128 bits.  See the length analysis in          |
//	|      |      | Appendix B.                                         |
//	+------+------+-----------------------------------------------------+
//	| 0x02 | IEEE | This makes use of the device identification         |
//	|      | EUI  | scheme operated by the IEEE.  An EUI is either      |
//	|      |      | an EUI-48, EUI-60 or EUI-64 and made up of an       |
//	|      |      | OUI, OUI-36 or a CID, different registered          |
//	|      |      | company identifiers, and some unique per-entity     |
//	|      |      | identifier.  EUIs are often the same as or          |
//	|      |      | similar to MAC addresses.  This type includes       |
//	|      |      | MAC-48, an obsolete name for EUI-48.  (Note that    |
//	|      |      | while entities with multiple network interfaces     |
//	|      |      | may have multiple MAC addresses, there is only      |
//	|      |      | one UEID for an entity; changeable MAC addresses    |
//	|      |      | that don't meet the permanence requirements in      |
//	|      |      | this document MUST NOT be used for the UEID or      |
//	|      |      | SUEID) [IEEE.802-2001], [OUI.Guide].                |
//	+------+------+-----------------------------------------------------+
//	| 0x03 | IMEI | This makes use of the International Mobile          |
//	|      |      | Equipment Identity (IMEI) scheme operated by the    |
//	|      |      | GSMA.  This is a 14-digit identifier consisting     |
//	|      |      | of an 8-digit Type Allocation Code (TAC) and a      |
//	|      |      | 6-digit serial number allocated by the              |
//	|      |      | manufacturer, which SHALL be encoded as byte        |
//	|      |      | string of length 14 with each byte as the           |
//	|      |      | digit's value (not the ASCII encoding of the        |
//	|      |      | digit; the digit 3 encodes as 0x03, not 0x33).      |
//	|      |      | The IMEI value encoded SHALL NOT include Luhn       |
//	|      |      | checksum or SVN information.  See                   |
//	|      |      | [ThreeGPP.IMEI].                                    |
//	+------+------+-----------------------------------------------------+
const (
	eatRandUeid byte = 0x01
)

// EAT claim tags
var (
	// EAT encrypt-then-MAC AES IV claim unprotected header
	eatAesIvClaim = cose.Label{Int64: 5} //nolint:unused
	// An EAT nonce
	eatNonceClaim = cose.Label{Int64: 10}
	// EatRand (0x01) followed by FDO GUID (128-bit)
	eatUeidClaim = cose.Label{Int64: 256}
)

// FDO claim tags
var (
	// MAY be present to contain other claims specified for the specific FIDO Device Onboard message.
	eatFdoClaim = cose.Label{Int64: -257}
	// If needed for a given ROE, is an unprotected header item (not payload)
	eatMaroePrefixClaim = cose.Label{Int64: -258} //nolint:unused
	// An unprotected header item
	eatUnprotectedNonceClaim = cose.Label{Int64: -259}
)

// eatoken is used for the Device attestation. Entity Attestation Tokens in
// FIDO Device Onboard require the COSE_Sign1 prefix. The EAT token follows the
// EAT specification for all claims except as follows:
//
//   - The UEID claim MUST have EAT-RAND in the first byte and contain the FIDO
//     Device Onboard Guid for the attesting Device in subsequent bytes
//   - The EAT NONCE claim MUST contain the specified FIDO Device Onboard Nonce
//     for the specific FIDO Device Onboard message in question (see below)
//   - An additional claim, EAT-FDO, may be present to contain other claims
//     specified for the specific FIDO Device Onboard message.
//   - The MAROEPrefix, if needed for a given ROE, is an unprotected header
//     item.
//
// EATOtherClaims indicates all other valid EAT claims, as defined in the EAT
// specification [EAT].
//
// As a documentation convention, the affected FIDO Device Onboard messages are
// defined to be the EAT token, with the following:
//
//   - Guid appears as above
//   - `EAT-NONCE` is added to `$$EATPayloadBase` to indicate which Nonce to use
//   - If needed, `$EATPayloads` contains the definition for the contents of
//     the `EAT-FDO` tag.
//   - `$$EATUnprotectedHeaders` gives unprotected headers to use for that
//     message.
//   - `$$EATProtectedHeaders` gives protected headers to use for that message.
//
// Relevant CDDL:
//
//	EATPayloadBaseMap = { EATPayloadBase }
//	$$EATPayloadBase //= (
//	    EAT-FDO => $EATPayloads,
//	    EAT-NONCE => Nonce,
//	    EAT-UEID  => EAT-GUID,
//	    EATOtherClaims
//	)
//	$EATPayloads /= ()
type eatoken map[cose.Label]any

// NewEAToken creates an eatoken with the expected required and additional
// claims.
func newEAT(guid GUID, nonce Nonce, fdo any, other map[cose.Label]any) eatoken {
	if other == nil {
		other = make(map[cose.Label]any)
	}
	if fdo != nil {
		other[eatFdoClaim] = fdo
	}
	other[eatNonceClaim] = nonce
	other[eatUeidClaim] = append([]byte{eatRandUeid}, guid[:]...)
	return other
}
