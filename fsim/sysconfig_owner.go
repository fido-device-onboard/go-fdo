// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// SysConfigOwner implements the fdo.sysconfig FSIM for system parameter configuration on the owner side.
//
// This module is purely callback-based and performs NO parameter validation.
// All parameter names and values are treated as opaque strings.
type SysConfigOwner struct {
	// Parameters is a list of system parameters to set on the device.
	// Each entry specifies a parameter name and value as opaque strings.
	Parameters []SystemParam

	// Internal state
	paramIndex      int
	sentActive      bool
	pendingResponse *pendingSystemResponse
}

type pendingSystemResponse struct {
	messageType string
	data        []byte
	errorCode   *uint
}

var _ serviceinfo.OwnerModule = (*SysConfigOwner)(nil)

// HandleInfo implements serviceinfo.OwnerModule.
func (s *SysConfigOwner) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
	switch messageName {
	case "active":
		var deviceActive bool
		if err := cbor.NewDecoder(messageBody).Decode(&deviceActive); err != nil {
			return fmt.Errorf("error decoding active message: %w", err)
		}
		if !deviceActive {
			return fmt.Errorf("device system module is not active")
		}
		return nil

	case "error":
		var errCode uint
		if err := cbor.NewDecoder(messageBody).Decode(&errCode); err != nil {
			return fmt.Errorf("error decoding error code: %w", err)
		}
		return fmt.Errorf("device reported system error %d: %s", errCode, sysconfigErrorString(errCode))

	default:
		// Silently ignore unknown messages for protocol compatibility
		if debugEnabled() {
			slog.Debug("fdo.sysconfig: ignoring unknown message", "messageName", messageName)
		}
		return nil
	}
}

// ProduceInfo implements serviceinfo.OwnerModule.
func (s *SysConfigOwner) ProduceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	// Send active message first if we have parameters to send
	if !s.sentActive && len(s.Parameters) > 0 {
		if err := producer.WriteChunk("active", []byte{0xf5}); err != nil { // 0xf5 is CBOR true
			return false, false, fmt.Errorf("error sending active message: %w", err)
		}
		s.sentActive = true
	}

	// Send pending response if any
	if s.pendingResponse != nil {
		if s.pendingResponse.errorCode != nil {
			var buf bytes.Buffer
			if err := cbor.NewEncoder(&buf).Encode(*s.pendingResponse.errorCode); err != nil {
				return false, false, fmt.Errorf("error encoding error response: %w", err)
			}
			if err := producer.WriteChunk("error", buf.Bytes()); err != nil {
				return false, false, fmt.Errorf("error sending error response: %w", err)
			}
			s.pendingResponse = nil
			return false, true, nil
		}

		var buf bytes.Buffer
		if err := cbor.NewEncoder(&buf).Encode(s.pendingResponse.data); err != nil {
			return false, false, fmt.Errorf("error encoding %s: %w", s.pendingResponse.messageType, err)
		}
		if err := producer.WriteChunk(s.pendingResponse.messageType, buf.Bytes()); err != nil {
			return false, false, fmt.Errorf("error sending %s: %w", s.pendingResponse.messageType, err)
		}

		if debugEnabled() {
			slog.Debug("fdo.sysconfig: sent response", "type", s.pendingResponse.messageType)
		}

		s.pendingResponse = nil
		return false, false, nil
	}

	// Send system parameters
	if s.paramIndex < len(s.Parameters) {
		param := s.Parameters[s.paramIndex]
		s.paramIndex++

		// Parameters are treated as opaque strings - no validation
		var buf bytes.Buffer
		if err := cbor.NewEncoder(&buf).Encode(param); err != nil {
			return false, false, fmt.Errorf("error encoding set: %w", err)
		}

		if err := producer.WriteChunk("set", buf.Bytes()); err != nil {
			return false, false, fmt.Errorf("error sending set: %w", err)
		}

		if debugEnabled() {
			slog.Debug("fdo.sysconfig: sent parameter", "parameter", param.Parameter, "value", param.Value)
		}

		return false, false, nil
	}

	// All parameters sent, module is done
	return false, true, nil
}

// AddParameter adds a system parameter to be set on the device.
// Both parameter name and value are treated as opaque strings - no validation is performed.
func (s *SysConfigOwner) AddParameter(parameter, value string) {
	s.Parameters = append(s.Parameters, SystemParam{
		Parameter: parameter,
		Value:     value,
	})
}

// Reset resets the module state for reuse.
func (s *SysConfigOwner) Reset() {
	s.paramIndex = 0
	s.pendingResponse = nil
}
