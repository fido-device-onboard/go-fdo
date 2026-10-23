// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"github.com/fido-device-onboard/go-fdo/fsim/chunking"
)

// DeliveryMode constants for BMO image delivery. Delivery modes are generic
// (chunking-strategy.md "Delivery Modes"); these alias the chunking constants.
const (
	DeliveryModeInline  = chunking.DeliveryModeInline  // Chunked transfer over the FDO channel (default)
	DeliveryModeURL     = chunking.DeliveryModeURL     // Device fetches image from URL
	DeliveryModeMetaURL = chunking.DeliveryModeMetaURL // Device fetches meta-payload naming the image
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
	BMOErrorScopeMismatch              = 16 // Artifact scope guid does not match this device
	BMOErrorValidityFailed             = 17 // Artifact outside validity window / no trusted clock
	BMOErrorSuperseded                 = 18 // Artifact generation superseded / not evaluable
	BMOErrorUnauthenticatedSource      = 19 // Fetched object authenticated by no hash, signature, or validated TLS
)

// MetaPayload is the meta-payload for meta-URL delivery. It is defined by the
// generic chunking layer (chunking-strategy.md "Meta-Payload"); key 5 is
// fdo.bmo's boot_args.
type MetaPayload = chunking.MetaPayload

// URLFetcher fetches content from URLs (see chunking.URLFetcher). Implement
// chunking.ValidatingFetcher as well to let validated TLS count as evidence.
type URLFetcher = chunking.URLFetcher
