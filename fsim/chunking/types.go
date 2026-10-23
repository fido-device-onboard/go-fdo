// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

// Package chunking provides generic chunking support for FDO Service Info Modules (FSIMs)
// following the pattern defined in chunking-strategy.md.
//
// This package implements the common begin/data/end/result message flow that allows
// FSIMs to transmit large payloads without being constrained by MTU limits.
package chunking

import (
	"bytes"
	"fmt"
	"math"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// Begin message keys defined by chunking-strategy.md ("Begin Message Fields").
const (
	BeginKeyTotalSize         = 0
	BeginKeyHashAlg           = 1
	BeginKeyMetadata          = 2
	BeginKeyRequireAck        = 3
	BeginKeyEstimatedDuration = 4
	BeginKeyDeliveryMode      = 5
	BeginKeyURL               = 6
	BeginKeyTLSCA             = 7
	BeginKeyExpectedHash      = 8
	BeginKeyMetaSigner        = 9
)

// LegacyBeginKeyAliases maps the former fdo.bmo-local negative keys to the
// generic delivery keys that replaced them. Receivers accept the aliases;
// senders never emit them (chunking-strategy.md, Reserved Key Policy).
var LegacyBeginKeyAliases = map[int]int{
	-6:  BeginKeyDeliveryMode,
	-7:  BeginKeyURL,
	-8:  BeginKeyTLSCA,
	-9:  BeginKeyExpectedHash,
	-10: BeginKeyMetaSigner,
}

// Delivery modes (chunking-strategy.md "Delivery Modes").
const (
	DeliveryModeInline  uint = 0 // chunked transfer over the FDO channel (default)
	DeliveryModeURL     uint = 1 // receiver fetches the content from URL
	DeliveryModeMetaURL uint = 2 // receiver fetches a meta-payload naming the content
)

// BeginMessage represents the *-begin message structure from chunking-strategy.md.
// It contains generic fields (non-negative keys) and FSIM-specific fields (negative keys).
type BeginMessage struct {
	// Generic fields (keys 0-127 reserved by chunking spec)
	TotalSize         uint64         // Key 0: Total bytes that will be transmitted (optional)
	HashAlg           string         // Key 1: Hash algorithm identifier (e.g., "sha256", "sha384")
	Metadata          map[string]any // Key 2: Optional FSIM-specific metadata
	RequireAck        bool           // Key 3: If true, sender waits for *-ack before sending data
	EstimatedDuration uint64         // Key 4: Advisory estimate of total transfer+apply time in seconds (0 = unset)

	// Delivery fields (keys 5-9). Receivers also accept the legacy fdo.bmo
	// aliases -6..-10 (see LegacyBeginKeyAliases); senders emit only 5-9.
	DeliveryMode uint   // Key 5: 0=inline, 1=url, 2=meta-url
	URL          string // Key 6: content URL (mode 1) or meta-payload URL (mode 2)
	TLSCA        []byte // Key 7: DER CA certificate used as TLS trust anchor for URL
	ExpectedHash []byte // Key 8: hash of the final content (algorithm in HashAlg)
	MetaSigner   []byte // Key 9: COSE_Key of a third-party meta-payload publisher

	// FSIM-specific fields use negative integer keys to avoid collisions
	// Example: -1 for network_id, -2 for ssid, etc.
	FSIMFields map[int]any
}

// MarshalCBOR encodes BeginMessage to CBOR map format.
func (b *BeginMessage) MarshalCBOR() ([]byte, error) {
	m := make(map[any]any)

	// Add generic fields if present
	if b.TotalSize > 0 {
		m[BeginKeyTotalSize] = b.TotalSize
	}
	if b.HashAlg != "" {
		m[BeginKeyHashAlg] = b.HashAlg
	}
	if len(b.Metadata) > 0 {
		m[BeginKeyMetadata] = b.Metadata
	}
	if b.RequireAck {
		m[BeginKeyRequireAck] = true
	}
	if b.EstimatedDuration > 0 {
		m[BeginKeyEstimatedDuration] = b.EstimatedDuration
	}
	if b.DeliveryMode != DeliveryModeInline {
		m[BeginKeyDeliveryMode] = b.DeliveryMode
	}
	if b.URL != "" {
		m[BeginKeyURL] = b.URL
	}
	if len(b.TLSCA) > 0 {
		m[BeginKeyTLSCA] = b.TLSCA
	}
	if len(b.ExpectedHash) > 0 {
		m[BeginKeyExpectedHash] = b.ExpectedHash
	}
	if len(b.MetaSigner) > 0 {
		m[BeginKeyMetaSigner] = b.MetaSigner
	}

	// Add FSIM-specific fields (negative keys). A legacy delivery alias set
	// by older code is translated to its generic key, never emitted as-is;
	// if the generic field is also set to a different value, that is an error.
	for key, val := range b.FSIMFields {
		if key >= 0 {
			continue // Skip non-negative keys to avoid conflicts
		}
		if generic, legacy := LegacyBeginKeyAliases[key]; legacy {
			if existing, set := m[generic]; set {
				if !sameValue(existing, val) {
					return nil, fmt.Errorf("begin message sets key %d and legacy alias %d to different values", generic, key)
				}
				continue
			}
			m[generic] = val
			continue
		}
		m[key] = val
	}

	return cbor.Marshal(m)
}

// UnmarshalCBOR decodes BeginMessage from CBOR map format.
//
// Legacy fdo.bmo aliases (-6..-10) are folded into the generic delivery
// fields. A message carrying both a generic key and its alias with different
// values is rejected, as chunking-strategy.md requires.
func (b *BeginMessage) UnmarshalCBOR(data []byte) error {
	var m map[any]any
	if err := cbor.Unmarshal(data, &m); err != nil {
		return err
	}

	b.FSIMFields = make(map[int]any)
	fields := make(map[int]any, len(m))
	for key, val := range m {
		k, ok := intKey(key)
		if !ok {
			continue
		}
		fields[k] = val
	}

	// Resolve legacy aliases into their generic keys.
	for alias, generic := range LegacyBeginKeyAliases {
		av, hasAlias := fields[alias]
		if !hasAlias {
			continue
		}
		if gv, hasGeneric := fields[generic]; hasGeneric && !sameValue(gv, av) {
			return fmt.Errorf("begin message carries key %d and its legacy alias %d with different values", generic, alias)
		}
		fields[generic] = av
	}

	for k, val := range fields {
		switch k {
		case BeginKeyTotalSize:
			switch v := val.(type) {
			case int64:
				if v < 0 {
					return fmt.Errorf("total size cannot be negative")
				}
			case int:
				if v < 0 {
					return fmt.Errorf("total size cannot be negative")
				}
			}
			b.TotalSize = parseUint64(val)
		case BeginKeyHashAlg:
			b.HashAlg, _ = val.(string)
		case BeginKeyMetadata:
			if v, ok := val.(map[any]any); ok {
				b.Metadata = convertToStringMap(v)
			}
		case BeginKeyRequireAck:
			b.RequireAck, _ = val.(bool)
		case BeginKeyEstimatedDuration:
			b.EstimatedDuration = parseUint64(val)
		case BeginKeyDeliveryMode:
			mode := parseUint64(val)
			if mode > uint64(DeliveryModeMetaURL) {
				// Unknown modes are kept as-is so the receiver can reject
				// them with "delivery mode not supported".
				mode = uint64(DeliveryModeMetaURL) + 1
			}
			b.DeliveryMode = uint(mode) //#nosec G115 -- clamped above
		case BeginKeyURL:
			b.URL, _ = val.(string)
		case BeginKeyTLSCA:
			b.TLSCA, _ = val.([]byte)
		case BeginKeyExpectedHash:
			b.ExpectedHash, _ = val.([]byte)
		case BeginKeyMetaSigner:
			b.MetaSigner, _ = val.([]byte)
		default:
			// Negative keys are FSIM-specific (legacy aliases are kept here
			// too, for FSIM code that still reads them).
			if k < 0 {
				b.FSIMFields[k] = val
			}
		}
	}

	return nil
}

// intKey normalizes a CBOR-decoded map key to int.
func intKey(key any) (int, bool) {
	switch k := key.(type) {
	case int:
		return k, true
	case int64:
		if k < math.MinInt32 || k > math.MaxInt32 {
			return 0, false
		}
		return int(k), true
	case uint64:
		if k > math.MaxInt32 {
			return 0, false
		}
		return int(k), true //#nosec G115 -- bounds checked above
	}
	return 0, false
}

// sameValue compares two CBOR-decoded scalar values.
func sameValue(a, b any) bool {
	if ab, ok := a.([]byte); ok {
		bb, ok := b.([]byte)
		return ok && bytes.Equal(ab, bb)
	}
	if as, ok := a.(string); ok {
		bs, ok := b.(string)
		return ok && as == bs
	}
	return parseUint64(a) == parseUint64(b) && fmt.Sprint(a) == fmt.Sprint(b)
}

// EndMessage represents the *-end message structure from chunking-strategy.md.
type EndMessage struct {
	// Generic fields (keys 0-127 reserved by chunking spec)
	Status    int    // Key 0: FSIM-specific status code (e.g., 0 = success)
	HashValue []byte // Key 1: Hash of the full payload
	Message   string // Key 2: Optional human-readable note or error string

	// StatusSet distinguishes an explicit status of 0 from an absent key 0.
	// When true, key 0 is always encoded; decoding sets it if key 0 is present.
	StatusSet bool

	// FSIM-specific fields use negative integer keys
	FSIMFields map[int]any
}

// MarshalCBOR encodes EndMessage to CBOR map format.
func (e *EndMessage) MarshalCBOR() ([]byte, error) {
	m := make(map[any]any)

	// Add generic fields if present
	if e.Status != 0 || e.StatusSet {
		m[0] = e.Status
	}
	if len(e.HashValue) > 0 {
		m[1] = e.HashValue
	}
	if e.Message != "" {
		m[2] = e.Message
	}

	// Add FSIM-specific fields (negative keys)
	for key, val := range e.FSIMFields {
		if key >= 0 {
			continue
		}
		m[key] = val
	}

	return cbor.Marshal(m)
}

// UnmarshalCBOR decodes EndMessage from CBOR map format.
func (e *EndMessage) UnmarshalCBOR(data []byte) error {
	var m map[any]any
	if err := cbor.Unmarshal(data, &m); err != nil {
		return err
	}

	e.FSIMFields = make(map[int]any)

	for key, val := range m {
		switch k := key.(type) {
		case int64: // CBOR always returns int64 for integer keys
			switch k {
			case 0:
				if v, ok := val.(int64); ok {
					e.Status, e.StatusSet = int(v), true
				}
			case 1:
				if v, ok := val.([]byte); ok {
					e.HashValue = v
				}
			case 2:
				if v, ok := val.(string); ok {
					e.Message = v
				}
			}
		default:
			if intKey, ok := key.(int); ok && intKey < 0 {
				e.FSIMFields[intKey] = val
			} else if int64Key, ok := key.(int64); ok && int64Key < 0 {
				e.FSIMFields[int(int64Key)] = val
			}
		}
	}

	return nil
}

// ResultMessage represents the *-result message structure from chunking-strategy.md.
// This is sent by the receiver to acknowledge completion of the transfer.
type ResultMessage struct {
	StatusCode int    // 0=success, 1=warning, 2=error (FSIMs may define additional values)
	Message    string // Optional human-readable description or error detail
}

// MarshalCBOR encodes ResultMessage to CBOR array format: [status_code, ?message]
func (r *ResultMessage) MarshalCBOR() ([]byte, error) {
	if r.Message == "" {
		return cbor.Marshal([]any{r.StatusCode})
	}
	return cbor.Marshal([]any{r.StatusCode, r.Message})
}

// UnmarshalCBOR decodes ResultMessage from CBOR array format.
func (r *ResultMessage) UnmarshalCBOR(data []byte) error {
	var arr []any
	if err := cbor.Unmarshal(data, &arr); err != nil {
		return err
	}

	if len(arr) > 0 {
		switch v := arr[0].(type) {
		case int:
			r.StatusCode = int(v)
		case int64:
			r.StatusCode = int(v)
		case uint64:
			if v <= math.MaxInt {
				r.StatusCode = int(v)
			}
		case float64:
			r.StatusCode = int(v)
		default:
			// Try to handle other numeric types
			if num, ok := v.(interface{ Int() int64 }); ok {
				r.StatusCode = int(num.Int())
			}
		}
	}

	if len(arr) > 1 {
		if v, ok := arr[1].(string); ok {
			r.Message = v
		}
	}

	return nil
}

// AckMessage represents the *-ack message structure from chunking-strategy.md.
// This is sent by the receiver in response to *-begin when RequireAck is true.
// It allows the receiver to accept or reject the transfer before data is sent.
type AckMessage struct {
	Accepted   bool   // Whether the transfer is accepted
	ReasonCode int    // Optional reason code if rejected (FSIM-specific)
	Message    string // Optional human-readable message
}

// Standard reason codes for rejection (FSIMs may define additional codes)
const (
	AckReasonUnsupportedType = 1 // MIME type or format not supported
	AckReasonSizeExceeded    = 2 // Payload too large
	AckReasonNotApplicable   = 3 // Payload not applicable to current state
	AckReasonPolicyViolation = 4 // Rejected by policy

	// AckReasonDiagnosticsNotRequested rejects a reverse-direction diagnostic
	// log transfer (see chunking-strategy.md "Diagnostic Payloads").
	AckReasonDiagnosticsNotRequested = 5

	// AckReasonBusy rejects a standalone diagnostic log offered while another
	// transfer of the same FSIM is in progress; the device may offer it again
	// once that transfer completes (chunking-strategy.md "Standalone
	// Diagnostic Transfers").
	AckReasonBusy = 6
)

// MarshalCBOR encodes AckMessage to CBOR array format: [accepted, ?reason_code, ?message]
func (a *AckMessage) MarshalCBOR() ([]byte, error) {
	if a.Accepted {
		// Accepted: just [true]
		return cbor.Marshal([]any{true})
	}
	// Rejected: include reason code and optional message
	if a.Message == "" {
		return cbor.Marshal([]any{false, a.ReasonCode})
	}
	return cbor.Marshal([]any{false, a.ReasonCode, a.Message})
}

// UnmarshalCBOR decodes AckMessage from CBOR array format.
func (a *AckMessage) UnmarshalCBOR(data []byte) error {
	var arr []any
	if err := cbor.Unmarshal(data, &arr); err != nil {
		return err
	}

	if len(arr) > 0 {
		if v, ok := arr[0].(bool); ok {
			a.Accepted = v
		}
	}

	if len(arr) > 1 {
		if v, ok := arr[1].(int); ok {
			a.ReasonCode = int(v)
		} else if v, ok := arr[1].(uint64); ok {
			if v <= math.MaxInt {
				a.ReasonCode = int(v)
			}
		} else if v, ok := arr[1].(int64); ok {
			a.ReasonCode = int(v)
		}
	}

	if len(arr) > 2 {
		if v, ok := arr[2].(string); ok {
			a.Message = v
		}
	}

	return nil
}

// parseUint64 extracts a uint64 from a CBOR-decoded value that may be int, int64, or uint64.
func parseUint64(val any) uint64 {
	switch v := val.(type) {
	case uint64:
		return v
	case int:
		if v >= 0 {
			return uint64(v)
		}
	case int64:
		if v >= 0 {
			return uint64(v)
		}
	}
	return 0
}

// convertToStringMap converts a map[any]any to map[string]any for metadata.
func convertToStringMap(m map[any]any) map[string]any {
	result := make(map[string]any)
	for k, v := range m {
		if str, ok := k.(string); ok {
			result[str] = v
		}
	}
	return result
}
