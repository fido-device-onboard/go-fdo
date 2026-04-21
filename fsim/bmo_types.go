// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"github.com/fido-device-onboard/go-fdo/cbor"
)

// DeliveryMode constants for BMO image delivery per fdo.bmo.md
const (
	DeliveryModeInline  uint = 0 // Traditional chunked transfer over FDO channel (default)
	DeliveryModeURL     uint = 1 // Device fetches image from URL
	DeliveryModeMetaURL uint = 2 // Device fetches meta-payload from URL, which defines actual image
)

// BMO error codes per fdo.bmo.md
const (
	BMOErrorUnknownImageType           = 1  // Firmware does not support the image type
	BMOErrorInvalidFormat              = 2  // Image format is invalid or corrupted
	BMOErrorSizeExceeded               = 3  // Image exceeds available memory/storage
	BMOErrorBootFailed                 = 4  // Chainload/boot attempt failed
	BMOErrorTransferError              = 5  // Error during data transfer
	BMOErrorSecureBootViolation        = 6  // Image fails Secure Boot verification
	BMOErrorDBModificationNotSupported = 7  // Firmware cannot modify Secure Boot DB/DBX
	BMOErrorDBModificationFailed       = 8  // DB/DBX enrollment failed
	BMOErrorURLFetchFailed             = 9  // Could not download from URL
	BMOErrorTLSValidationFailed        = 10 // TLS certificate validation failed
	BMOErrorHashMismatch               = 11 // Downloaded image hash doesn't match expected
	BMOErrorMetaSignatureInvalid       = 12 // COSE Sign1 signature verification failed
	BMOErrorMetaParseError             = 13 // Meta-payload CBOR is malformed
	BMOErrorDeliveryModeNotSupported   = 14 // Firmware does not support the delivery mode
)

// MetaPayload represents the CBOR structure for meta-payload indirection (Mode 2)
// per fdo.bmo.md specification.
type MetaPayload struct {
	MIMEType     string `cbor:"0,keyasint"`           // Required: MIME type of actual image
	URL          string `cbor:"1,keyasint"`           // Required: URL to fetch actual image
	TLSCA        []byte `cbor:"2,keyasint,omitempty"` // Optional: CA cert for image URL (DER)
	HashAlg      string `cbor:"3,keyasint,omitempty"` // Optional: hash algorithm
	ExpectedHash []byte `cbor:"4,keyasint,omitempty"` // Optional: hash of actual image
	BootArgs     string `cbor:"5,keyasint,omitempty"` // Optional: kernel arguments
	Name         string `cbor:"6,keyasint,omitempty"` // Optional: image name
	Version      string `cbor:"7,keyasint,omitempty"` // Optional: image version
	Description  string `cbor:"8,keyasint,omitempty"` // Optional: image description
}

// MarshalCBOR encodes MetaPayload to CBOR map format with integer keys.
func (m *MetaPayload) MarshalCBOR() ([]byte, error) {
	mp := make(map[int]any)
	mp[0] = m.MIMEType
	mp[1] = m.URL
	if len(m.TLSCA) > 0 {
		mp[2] = m.TLSCA
	}
	if m.HashAlg != "" {
		mp[3] = m.HashAlg
	}
	if len(m.ExpectedHash) > 0 {
		mp[4] = m.ExpectedHash
	}
	if m.BootArgs != "" {
		mp[5] = m.BootArgs
	}
	if m.Name != "" {
		mp[6] = m.Name
	}
	if m.Version != "" {
		mp[7] = m.Version
	}
	if m.Description != "" {
		mp[8] = m.Description
	}
	return cbor.Marshal(mp)
}

// UnmarshalCBOR decodes MetaPayload from CBOR map format.
func (m *MetaPayload) UnmarshalCBOR(data []byte) error {
	var mp map[int]any
	if err := cbor.Unmarshal(data, &mp); err != nil {
		// Try with any key type (CBOR may decode as int64)
		var mpAny map[any]any
		if err2 := cbor.Unmarshal(data, &mpAny); err2 != nil {
			return err
		}
		mp = make(map[int]any)
		for k, v := range mpAny {
			switch ki := k.(type) {
			case int:
				mp[ki] = v
			case int64:
				if ki >= 0 && ki <= 127 {
					mp[int(ki)] = v //#nosec G115 -- bounds checked above
				}
			case uint64:
				if ki <= 127 {
					mp[int(ki)] = v //#nosec G115 -- bounds checked above
				}
			}
		}
	}

	if v, ok := mp[0].(string); ok {
		m.MIMEType = v
	}
	if v, ok := mp[1].(string); ok {
		m.URL = v
	}
	if v, ok := mp[2].([]byte); ok {
		m.TLSCA = v
	}
	if v, ok := mp[3].(string); ok {
		m.HashAlg = v
	}
	if v, ok := mp[4].([]byte); ok {
		m.ExpectedHash = v
	}
	if v, ok := mp[5].(string); ok {
		m.BootArgs = v
	}
	if v, ok := mp[6].(string); ok {
		m.Name = v
	}
	if v, ok := mp[7].(string); ok {
		m.Version = v
	}
	if v, ok := mp[8].(string); ok {
		m.Description = v
	}

	return nil
}

// URLFetcher is an interface for fetching content from URLs.
// This abstraction allows for mocking in unit tests.
type URLFetcher interface {
	// Fetch downloads content from the given URL.
	// If tlsCA is non-nil, it should be used as the trust anchor for TLS validation.
	// Returns the downloaded content or an error.
	Fetch(url string, tlsCA []byte) ([]byte, error)
}

// MetaPayloadVerifier is an interface for verifying signed meta-payloads.
// This abstraction allows for mocking in unit tests.
type MetaPayloadVerifier interface {
	// Verify checks the COSE Sign1 signature on a meta-payload.
	// signerKey is the COSE_Key used for verification.
	// Returns the inner payload (MetaPayload CBOR) if signature is valid,
	// or an error if verification fails.
	Verify(signedPayload []byte, signerKey []byte) ([]byte, error)
}
