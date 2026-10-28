// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// SysConfig implements the fdo.sysconfig FSIM for system parameter configuration on the device side.
// See fdo.sysconfig.md specification.
//
// This module is purely callback-based and performs NO OS-specific operations.
// All parameter setting must be provided by the application via callbacks.
type SysConfig struct {
	// SetParameter is called when the owner sends a system parameter to set.
	// The parameter name and value are passed as opaque strings.
	// The implementation is responsible for all OS-specific operations:
	// - Validating parameter names and values
	// - Applying parameters to the system (hostname, timezone, NTP, etc.)
	// - Persisting configuration changes
	// - Restarting services if needed
	// This callback is REQUIRED.
	SetParameter func(parameter, value string) error

	// Internal state
	pendingError *uint
}

// SystemParam represents a system parameter to be configured.
type SystemParam struct {
	Parameter string `cbor:"parameter"`
	Value     string `cbor:"value"`
}

var _ serviceinfo.DeviceModule = (*SysConfig)(nil)

// Transition implements serviceinfo.DeviceModule.
func (s *SysConfig) Transition(active bool) error {
	if !active {
		s.reset()
	}
	return nil
}

// Receive implements serviceinfo.DeviceModule.
func (s *SysConfig) Receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	if err := s.receive(ctx, messageName, messageBody, respond); err != nil {
		s.reset()
		return err
	}
	return nil
}

func (s *SysConfig) receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer) error {
	switch messageName {
	case "set":
		return s.receiveSet(messageBody, respond)

	default:
		// Silently ignore unknown messages to maintain protocol compatibility
		return nil
	}
}

// Yield implements serviceinfo.DeviceModule.
func (s *SysConfig) Yield(ctx context.Context, respond func(string) io.Writer, yield func()) error {
	// Check for pending error
	if s.pendingError != nil {
		return fmt.Errorf("system parameter operation failed with error code %d", *s.pendingError)
	}

	// Nothing to send
	return nil
}

func (s *SysConfig) receiveSet(messageBody io.Reader, respond func(string) io.Writer) error {
	var param SystemParam
	if err := cbor.NewDecoder(messageBody).Decode(&param); err != nil {
		return fmt.Errorf("error decoding set message: %w", err)
	}

	// If no callback is provided, just log and continue
	if s.SetParameter == nil {
		if debugEnabled() {
			slog.Debug("fdo.sysconfig: no SetParameter callback provided, parameter will be ignored", "parameter", param.Parameter)
		}
		return nil
	}

	// Set parameter via callback - both parameter and value are treated as opaque strings
	if err := s.SetParameter(param.Parameter, param.Value); err != nil {
		if debugEnabled() {
			slog.Debug("fdo.sysconfig: parameter set failed", "parameter", param.Parameter, "error", err)
		}

		// Map error to error code
		errCode := mapErrorToCode(err)
		s.pendingError = &errCode

		return nil // Don't fail the protocol, just report error
	}

	if debugEnabled() {
		slog.Debug("fdo.sysconfig: parameter set", "parameter", param.Parameter, "value", param.Value)
	}

	return nil
}

func (s *SysConfig) reset() {
	s.pendingError = nil
}

// mapErrorToCode maps an error to a system parameter error code.
// This is a best-effort mapping - applications can return custom errors
// that will be mapped to generic codes.
func mapErrorToCode(err error) uint {
	errStr := err.Error()

	// Try to match common error patterns
	switch {
	case contains(errStr, "unknown") || contains(errStr, "not recognized"):
		return 1 // Unknown parameter
	case contains(errStr, "invalid") || contains(errStr, "malformed"):
		return 2 // Invalid value
	case contains(errStr, "permission") || contains(errStr, "denied"):
		return 3 // Permission denied
	case contains(errStr, "not supported") || contains(errStr, "unsupported"):
		return 5 // Not supported
	default:
		return 4 // Operation failed (generic)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			len(s) > len(substr)+1 && findSubstr(s, substr)))
}

func findSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func sysconfigErrorString(code uint) string {
	switch code {
	case 1:
		return "Unknown parameter"
	case 2:
		return "Invalid value"
	case 3:
		return "Permission denied"
	case 4:
		return "Operation failed"
	case 5:
		return "Not supported"
	default:
		return fmt.Sprintf("Unknown error code %d", code)
	}
}
