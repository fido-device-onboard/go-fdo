// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/fsim/chunking"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// PayloadOwner implements the fdo.payload FSIM for owner-side payload delivery.
// It follows the specification in fdo.payload.md and uses the generic chunking strategy.
type PayloadOwner struct {
	// Payloads to send to the device
	payloads []PayloadToSend

	// Internal state
	currentSender *chunking.ChunkSender
	currentIndex  int
	sendState     payloadSendState
	sentActive    bool
	lastResult    *PayloadResult
	lastError     *PayloadErrorInfo
}

type payloadSendState int

const (
	stateIdle payloadSendState = iota
	stateSendingBegin
	stateWaitingAck
	stateSendingChunks
	stateSendingEnd
	stateWaitingResult
)

// PayloadToSend represents a payload to be sent to the device per fdo.payload.md.
type PayloadToSend struct {
	MimeType   string         // Required: MIME type (field -1)
	Name       string         // Optional: Payload name (field -2)
	Data       []byte         // Payload data
	Metadata   map[string]any // Optional: Metadata map (field -3)
	HashAlg    string         // Optional: Hash algorithm (e.g., "sha256")
	RequireAck bool           // Optional: Request ack before sending data (default: false)
}

// PayloadResult represents the result received from the device.
type PayloadResult struct {
	StatusCode int    // 0=success, 1=warning, 2=error
	Message    string // Optional message
}

// PayloadErrorInfo contains error information from the device per fdo.payload.md.
type PayloadErrorInfo struct {
	Code    int    // Error code (see fdo.payload.md)
	Message string // Human-readable error message
	Details string // Optional additional details
}

var _ serviceinfo.OwnerModule = (*PayloadOwner)(nil)

// HandleInfo implements serviceinfo.OwnerModule.
func (p *PayloadOwner) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
	// Delegate to receive method
	return p.receive(ctx, messageName, messageBody, nil)
}

// ProduceInfo implements serviceinfo.OwnerModule.
func (p *PayloadOwner) ProduceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	return p.produceInfo(ctx, producer)
}

// AddPayload adds a payload to be sent to the device.
func (p *PayloadOwner) AddPayload(mimeType, name string, data []byte, metadata map[string]any) {
	p.payloads = append(p.payloads, PayloadToSend{
		MimeType: mimeType,
		Name:     name,
		Data:     data,
		Metadata: metadata,
		HashAlg:  "sha256", // Default hash algorithm
	})
}

// AddPayloadWithAck adds a payload that requires acknowledgment before data transfer.
// This allows the device to reject the payload based on MIME type before receiving data.
func (p *PayloadOwner) AddPayloadWithAck(mimeType, name string, data []byte, metadata map[string]any) {
	p.payloads = append(p.payloads, PayloadToSend{
		MimeType:   mimeType,
		Name:       name,
		Data:       data,
		Metadata:   metadata,
		HashAlg:    "sha256",
		RequireAck: true,
	})
}

// Transition implements serviceinfo.OwnerModule.
func (p *PayloadOwner) Transition(active bool) error {
	if !active {
		p.reset()
	}
	return nil
}

// reset clears the internal state.
func (p *PayloadOwner) reset() {
	p.currentSender = nil
	p.currentIndex = 0
	p.sendState = stateIdle
	p.lastResult = nil
	p.lastError = nil
}

// produceInfo generates messages to send to the device using the chunking library.
func (p *PayloadOwner) produceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	// Send active message first if we have payloads to send
	if !p.sentActive && len(p.payloads) > 0 {
		if err := producer.WriteChunk("active", []byte{0xf5}); err != nil { // 0xf5 is CBOR true
			return false, false, fmt.Errorf("error sending active message: %w", err)
		}
		p.sentActive = true
		return false, false, nil
	}

	// Check if we're done with all payloads
	if p.currentIndex >= len(p.payloads) && p.sendState == stateIdle {
		return false, true, nil
	}

	// Initialize sender for next payload if needed
	if p.currentSender == nil && p.currentIndex < len(p.payloads) {
		payload := &p.payloads[p.currentIndex]
		p.currentSender = chunking.NewChunkSender("payload", payload.Data)

		// Set hash algorithm if provided
		if payload.HashAlg != "" {
			p.currentSender.BeginFields.HashAlg = payload.HashAlg
		}

		// Set FSIM-specific fields per fdo.payload.md
		p.currentSender.BeginFields.FSIMFields[-1] = payload.MimeType // Required
		if payload.Name != "" {
			p.currentSender.BeginFields.FSIMFields[-2] = payload.Name
		}
		if payload.Metadata != nil {
			p.currentSender.BeginFields.FSIMFields[-3] = payload.Metadata
		}

		// Set RequireAck if requested
		if payload.RequireAck {
			p.currentSender.BeginFields.RequireAck = true
		}

		p.sendState = stateSendingBegin
	}

	// State machine for sending - send begin, all chunks, and end in one call
	switch p.sendState {
	case stateSendingBegin:
		fmt.Printf("[PayloadOwner] Sending begin message\n")
		if err := p.currentSender.SendBegin(producer); err != nil {
			return false, false, fmt.Errorf("failed to send begin: %w", err)
		}
		slog.Debug("fdo.payload sent begin",
			"mime_type", p.currentSender.BeginFields.FSIMFields[-1],
			"size", len(p.currentSender.Data),
			"require_ack", p.currentSender.BeginFields.RequireAck)

		// If RequireAck, wait for payload-ack before sending chunks
		if p.currentSender.IsWaitingForAck() {
			fmt.Printf("[PayloadOwner] RequireAck set, waiting for payload-ack\n")
			p.sendState = stateWaitingAck
			return false, false, nil
		}

		p.sendState = stateSendingChunks
		fmt.Printf("[PayloadOwner] Sent begin, continuing to send chunks\n")
		// Fall through to send chunks in same call
		fallthrough

	case stateWaitingAck:
		// Waiting for device to send payload-ack
		// This state is entered when RequireAck=true and we're waiting for ack
		// We transition out when we receive payload-ack in HandleInfo
		if p.currentSender.IsWaitingForAck() {
			// Still waiting
			return false, false, nil
		}
		// Check if rejected
		if p.currentSender.IsRejected() {
			reason, msg := p.currentSender.GetRejectReason()
			slog.Warn("fdo.payload rejected by device",
				"mime_type", p.currentSender.BeginFields.FSIMFields[-1],
				"reason_code", reason,
				"message", msg)
			// Move to next payload
			p.currentSender = nil
			p.currentIndex++
			p.sendState = stateIdle
			return false, false, nil
		}
		// Ack received, proceed to send chunks
		fmt.Printf("[PayloadOwner] payload-ack received, proceeding to send chunks\n")
		p.sendState = stateSendingChunks
		fallthrough

	case stateSendingChunks:
		// Send chunks one at a time, respecting MTU limits
		// Check if we have space for the next chunk
		chunkIndex := p.currentSender.GetBytesSent() / int64(p.currentSender.ChunkSize)
		chunkKey := fmt.Sprintf("payload-data-%d", chunkIndex)

		// Estimate the size needed for the next chunk (chunk size + CBOR overhead)
		// Add some buffer for CBOR encoding overhead
		estimatedSize := p.currentSender.ChunkSize + 50
		if producer.Available(chunkKey) < estimatedSize {
			// Not enough space, block and continue in next round
			fmt.Printf("[PayloadOwner] Not enough MTU space for next chunk, blocking\n")
			return true, false, nil
		}

		fmt.Printf("[PayloadOwner] Sending chunk %d, totalSize=%d\n", chunkIndex, len(p.currentSender.Data))
		done, err := p.currentSender.SendNextChunk(producer)
		if err != nil {
			return false, false, fmt.Errorf("failed to send chunk: %w", err)
		}
		if done {
			fmt.Printf("[PayloadOwner] All chunks sent, transitioning to send end\n")
			p.sendState = stateSendingEnd
			// Don't send end in same round - let it happen in next ProduceInfo call
			// This ensures we don't exceed MTU
			return true, false, nil
		}
		fmt.Printf("[PayloadOwner] Chunk sent, will continue in next round\n")
		// Block to continue sending more chunks in next round
		return true, false, nil

	case stateSendingEnd:
		fmt.Printf("[PayloadOwner] Sending end message\n")
		if err := p.currentSender.SendEnd(producer); err != nil {
			return false, false, fmt.Errorf("failed to send end: %w", err)
		}
		slog.Debug("fdo.payload sent end")
		fmt.Printf("[PayloadOwner] Sent end, waiting for result\n")
		p.sendState = stateWaitingResult
		// Don't block - the device will send payload-result in the same round
		// We'll receive it via HandleInfo before the next ProduceInfo call
		return false, false, nil

	case stateWaitingResult:
		// Waiting for device to send payload-result
		// This will be unblocked when we receive the result in HandleInfo
		// Don't block or send anything - just wait for HandleInfo to be called
		return false, false, nil
	}

	return false, false, nil
}

// receive processes incoming messages from the device.
func (p *PayloadOwner) receive(ctx context.Context, key string, messageBody io.Reader, respond func(string) io.Writer) error {
	slog.Debug("fdo.payload owner received message", "key", key)

	switch key {
	case "active":
		// Device responds with active status
		var deviceActive bool
		if err := cbor.NewDecoder(messageBody).Decode(&deviceActive); err != nil {
			return fmt.Errorf("error decoding active message: %w", err)
		}
		if !deviceActive {
			return fmt.Errorf("device payload module is not active")
		}
		slog.Debug("fdo.payload device active status received")
		return nil

	case "payload-ack":
		// Device responds to RequireAck with accept/reject
		if p.currentSender == nil {
			return fmt.Errorf("received ack without active transfer")
		}
		if !p.currentSender.IsWaitingForAck() {
			return fmt.Errorf("received unexpected ack")
		}

		if err := p.currentSender.HandleAck(messageBody); err != nil {
			// HandleAck returns error if rejected, but that's not a protocol error
			slog.Debug("fdo.payload ack received", "error", err)
		}

		// State machine will handle the transition in ProduceInfo
		return nil

	case "payload-result":
		// Device reports final result per fdo.payload.md
		if p.currentSender == nil {
			return fmt.Errorf("received result without active transfer")
		}

		result, err := p.currentSender.HandleResult(messageBody)
		if err != nil {
			return fmt.Errorf("failed to decode result: %w", err)
		}

		p.lastResult = &PayloadResult{
			StatusCode: result.StatusCode,
			Message:    result.Message,
		}

		if result.StatusCode == 0 {
			slog.Info("fdo.payload applied successfully",
				"mime_type", p.currentSender.BeginFields.FSIMFields[-1],
				"message", result.Message)
		} else {
			slog.Warn("fdo.payload application failed",
				"mime_type", p.currentSender.BeginFields.FSIMFields[-1],
				"status", result.StatusCode,
				"message", result.Message)
		}

		// Move to next payload
		p.currentSender = nil
		p.currentIndex++
		p.sendState = stateIdle

	case "error":
		// Device reports an error per fdo.payload.md error format
		var errorMap map[any]any
		data, err := io.ReadAll(messageBody)
		if err != nil {
			return fmt.Errorf("failed to read error: %w", err)
		}
		if err := cbor.Unmarshal(data, &errorMap); err != nil {
			return fmt.Errorf("failed to decode error: %w", err)
		}

		// Extract error fields (keys 0, 1, 2)
		code, _ := errorMap[0].(int)
		message, _ := errorMap[1].(string)
		details, _ := errorMap[2].(string)

		p.lastError = &PayloadErrorInfo{
			Code:    code,
			Message: message,
			Details: details,
		}

		slog.Error("fdo.payload device error",
			"code", code,
			"message", message,
			"details", details)

		// Reset current payload
		p.currentSender = nil
		p.sendState = stateIdle

		return fmt.Errorf("payload error %d: %s", code, message)

	default:
		// Silently ignore unknown messages for protocol compatibility
		if debugEnabled() {
			slog.Debug("fdo.payload: ignoring unknown message", "messageName", key)
		}
		return nil
	}

	return nil
}

// GetLastError returns the last error reported by the device.
func (p *PayloadOwner) GetLastError() *PayloadErrorInfo {
	return p.lastError
}

// GetLastResult returns the last result reported by the device.
func (p *PayloadOwner) GetLastResult() *PayloadResult {
	return p.lastResult
}

// SetChunkSize sets the chunk size for data transfer (default 1014 bytes per spec).
func (p *PayloadOwner) SetChunkSize(size int) {
	if p.currentSender != nil {
		p.currentSender.ChunkSize = size
	}
}
