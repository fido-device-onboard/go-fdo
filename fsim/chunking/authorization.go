// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package chunking

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	fdo "github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
)

// Transfer error codes (chunking-strategy.md "Transfer Error Codes"). FSIMs
// that use delivery modes 1-2 or authorization-gated messages reserve these
// codes, with these meanings.
const (
	CodeURLFetchFailed           = 9
	CodeTLSValidationFailed      = 10
	CodeHashMismatch             = 11
	CodeMetaSignatureInvalid     = 12
	CodeMetaParseError           = 13
	CodeDeliveryModeNotSupported = 14
	CodeNotAuthorized            = 15
	CodeScopeMismatch            = 16
	CodeValidityFailed           = 17
	CodeSuperseded               = 18
	CodeUnauthenticatedSource    = 19
)

// TransferError is an error carrying one of the transfer error codes.
type TransferError struct {
	Code int
	Msg  string
}

func (e *TransferError) Error() string { return e.Msg }

func transferErr(code int, format string, args ...any) error {
	return &TransferError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// ErrorCode extracts the transfer error code from err, or returns fallback.
func ErrorCode(err error, fallback int) int {
	var te *TransferError
	if errors.As(err, &te) {
		return te.Code
	}
	return fallback
}

// COSE header labels used by authorized messages.
var (
	labelContentType = cose.Label{Int64: 3}
	labelX5Chain     = cose.Label{Int64: 33} // RFC 9360
	// ScopeLabel is the protected header label carrying scope constraints.
	ScopeLabel = cose.Label{Str: "fdo.scope"}
	// LegacyBmoScopeLabel is the former fdo.bmo-specific scope label,
	// accepted for backward compatibility.
	LegacyBmoScopeLabel = cose.Label{Str: "fdo.bmo.scope"}
)

// coseSign1TagByte is the first byte of a CBOR tag-18 (COSE_Sign1) item.
const coseSign1TagByte byte = 0xD2

// IsSigned reports whether raw is a tagged COSE_Sign1 (artifact authority).
func IsSigned(raw []byte) bool { return len(raw) > 0 && raw[0] == coseSign1TagByte }

// ScopeContext supplies what the receiver needs to evaluate scope
// constraints (chunking-strategy.md "Scope Constraints").
type ScopeContext struct {
	// DeviceGUID is the GUID from the Ownership Voucher proven in TO2. If
	// nil, a "guid" constraint cannot be evaluated and is rejected.
	DeviceGUID []byte
	// Now returns the current trusted time. If nil, time constraints cannot
	// be evaluated and are rejected (error 17).
	Now func() time.Time
	// Generation, if non-nil, checks and records a "generation" value in
	// rollback-protected storage. If nil, "generation" cannot be evaluated
	// and is rejected (error 18) — a receiver MUST NOT claim support it
	// cannot back with rollback-protected storage.
	Generation func(gen uint64) error
}

// VerifyArtifact verifies a tagged COSE_Sign1 authorization artifact per
// chunking-strategy.md "Verification Algorithm" and returns its inner payload.
//
//   - contentType must equal the protected content_type (label 3).
//   - Without x5chain the signer is the Owner: verified against ownerKey.
//   - With x5chain the chain must validate to ownerKey and grant
//     fdo-ekt-permit-provision (PERM.7) in every certificate; the leaf key verifies.
//   - aad is the FSIM's registered external_aad (CBOR-encoded [tag]).
//   - Scope is evaluated after the signature; any unevaluable constraint rejects.
//
// Errors are *TransferError with code 15/16/17/18. There is no fallback to
// channel authority on any failure (no downgrade).
func VerifyArtifact(signed []byte, ownerKey crypto.PublicKey, contentType string, aad []byte, sc ScopeContext) ([]byte, error) {
	if ownerKey == nil {
		return nil, transferErr(CodeNotAuthorized, "no TO2-proven Owner key available to verify artifact")
	}
	var s1 cose.Sign1Tag[[]byte, []byte]
	if err := cbor.Unmarshal(signed, &s1); err != nil {
		return nil, transferErr(CodeNotAuthorized, "failed to parse COSE_Sign1: %v", err)
	}

	var ct string
	if ok, err := s1.Protected.Parse(labelContentType, &ct); err != nil || !ok {
		return nil, transferErr(CodeNotAuthorized, "missing or invalid content_type in protected header")
	}
	if ct != contentType {
		return nil, transferErr(CodeNotAuthorized, "content_type mismatch: expected %q, got %q", contentType, ct)
	}

	verifyKey, err := signerKey(s1.Unprotected, ownerKey)
	if err != nil {
		return nil, err
	}
	valid, err := s1.Verify(verifyKey, nil, aad)
	if err != nil || !valid {
		return nil, transferErr(CodeNotAuthorized, "artifact signature verification failed")
	}
	if s1.Payload == nil {
		return nil, transferErr(CodeNotAuthorized, "COSE_Sign1 has no payload")
	}

	if err := evaluateScope(s1.Protected, sc); err != nil {
		return nil, err
	}
	return s1.Payload.Val, nil
}

// signerKey returns the key that must have produced a provisioning
// signature: the Owner key when no x5chain is present, otherwise the leaf of
// an x5chain that validates to the Owner key and grants PERM.7.
func signerKey(unprotected cose.HeaderMap, ownerKey crypto.PublicKey) (crypto.PublicKey, error) {
	if unprotected == nil || unprotected[labelX5Chain] == nil {
		return ownerKey, nil
	}
	chain, err := parseX5Chain(unprotected[labelX5Chain])
	if err != nil {
		return nil, transferErr(CodeNotAuthorized, "invalid x5chain: %v", err)
	}
	if err := fdo.VerifyDelegateChain(chain, &ownerKey, &fdo.OIDPermitProvision); err != nil {
		return nil, transferErr(CodeNotAuthorized, "x5chain does not validate to the Owner key with fdo-ekt-permit-provision: %v", err)
	}
	return chain[0].PublicKey, nil
}

// parseX5Chain decodes an x5chain header value (a single bstr or an array of
// bstr, leaf first) into certificates.
func parseX5Chain(raw any) ([]*x509.Certificate, error) {
	var ders [][]byte
	switch v := raw.(type) {
	case []byte:
		ders = [][]byte{v}
	case [][]byte:
		ders = v
	case []any:
		for _, item := range v {
			b, ok := item.([]byte)
			if !ok {
				return nil, fmt.Errorf("x5chain entry is not a byte string")
			}
			ders = append(ders, b)
		}
	default:
		return nil, fmt.Errorf("x5chain has unexpected type %T", raw)
	}
	if len(ders) == 0 {
		return nil, fmt.Errorf("x5chain is empty")
	}
	chain := make([]*x509.Certificate, len(ders))
	for i, der := range ders {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", i, err)
		}
		chain[i] = c
	}
	return chain, nil
}

// evaluateScope evaluates the protected scope header. An artifact carrying
// both the generic and the legacy label is rejected.
func evaluateScope(protected cose.HeaderMap, sc ScopeContext) error {
	_, hasNew := protected[ScopeLabel]
	_, hasLegacy := protected[LegacyBmoScopeLabel]
	if hasNew && hasLegacy {
		return transferErr(CodeNotAuthorized, "artifact carries both %q and %q", ScopeLabel.Str, LegacyBmoScopeLabel.Str)
	}
	label := ScopeLabel
	if hasLegacy {
		label = LegacyBmoScopeLabel
	}
	var scope map[string]any
	ok, err := protected.Parse(label, &scope)
	if err != nil {
		return transferErr(CodeNotAuthorized, "malformed scope header: %v", err)
	}
	if !ok {
		return nil
	}
	return EvaluateScope(scope, sc)
}

// EvaluateScope applies decoded scope constraints. Every present field must
// be satisfied; a field that is unknown or cannot be evaluated rejects.
func EvaluateScope(scope map[string]any, sc ScopeContext) error {
	for field, val := range scope {
		switch field {
		case "guid":
			if sc.DeviceGUID == nil {
				return transferErr(CodeNotAuthorized, "scope guid present but device GUID unavailable")
			}
			if !guidMatches(val, sc.DeviceGUID) {
				return transferErr(CodeScopeMismatch, "scope guid does not match the voucher GUID")
			}
		case "not_before", "not_after":
			bound, ok := scopeUint(val)
			if !ok {
				return transferErr(CodeNotAuthorized, "scope %s is not an unsigned integer", field)
			}
			if sc.Now == nil {
				return transferErr(CodeValidityFailed, "scope %s present but no trustworthy clock", field)
			}
			now := uint64(sc.Now().Unix()) //#nosec G115 -- post-1970 trusted time
			if (field == "not_before" && now < bound) || (field == "not_after" && now > bound) {
				return transferErr(CodeValidityFailed, "artifact outside its validity window (%s=%d, now=%d)", field, bound, now)
			}
		case "generation":
			gen, ok := scopeUint(val)
			if !ok {
				return transferErr(CodeNotAuthorized, "scope generation is not an unsigned integer")
			}
			if sc.Generation == nil {
				return transferErr(CodeSuperseded, "scope generation present but no rollback-protected storage")
			}
			if err := sc.Generation(gen); err != nil {
				return transferErr(CodeSuperseded, "generation %d rejected: %v", gen, err)
			}
		default:
			return transferErr(CodeNotAuthorized, "unrecognized scope field %q", field)
		}
	}
	return nil
}

func guidMatches(val any, guid []byte) bool {
	switch v := val.(type) {
	case []byte:
		return bytes.Equal(v, guid)
	case []any:
		for _, item := range v {
			if b, ok := item.([]byte); ok && bytes.Equal(b, guid) {
				return true
			}
		}
	}
	return false
}

func scopeUint(val any) (uint64, bool) {
	switch v := val.(type) {
	case uint64:
		return v, true
	case int64:
		if v >= 0 {
			return uint64(v), true
		}
	case int:
		if v >= 0 {
			return uint64(v), true
		}
	}
	return 0, false
}
