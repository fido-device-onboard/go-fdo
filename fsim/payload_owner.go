// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/fsim/chunking"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

const (
	// maxPayloadChunkSize caps payload-data chunks when the device advertises
	// a large MaxOwnerServiceInfoSz. 60000 is chosen to stay below the 65535
	// uint16 ceiling while leaving room for protocol framing.
	maxPayloadChunkSize = 60000

	// payloadChunkOverhead reserves room inside the MTU for the
	// "fdo.payload:payload-data-<n>" key plus the CBOR framing the producer
	// wraps around each chunk.
	payloadChunkOverhead = 100
)

// PayloadOwner implements the fdo.payload FSIM for owner-side payload delivery.
// It follows the specification in fdo.payload.md and uses the generic chunking strategy.
type PayloadOwner struct {
	// Payloads to send to the device
	payloads []PayloadToSend

	// chunkSize overrides the payload-data chunk size. When zero, the chunk
	// size is derived from the negotiated MTU (capped at maxPayloadChunkSize).
	chunkSize int

	// LogHandler receives diagnostic logs uploaded by the device. If nil, the
	// owner declines every offered log with AckReasonDiagnosticsNotRequested.
	LogHandler PayloadLogHandler

	// Internal state
	currentSender *chunking.ChunkSender
	currentIndex  int
	sendState     payloadSendState
	sentActive    bool
	lastResult    *PayloadResult
	lastError     *PayloadErrorInfo
	logReceiver   *chunking.ChunkReceiver
	logAck        *chunking.AckMessage
	lastLog       *PayloadLogInfo

	// Decision recorded by onLogBeginAck for ProduceInfo to put on the wire.
	logAckReasonCode int
	logAckMessage    string
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
	MimeType          string         // Required: MIME type (field -1)
	Name              string         // Optional: Payload name (field -2)
	Data              []byte         // Payload data
	Metadata          map[string]any // Optional: Metadata map (field -3)
	HashAlg           string         // Optional: Hash algorithm (e.g., "sha256")
	RequireAck        bool           // Optional: Request ack before sending data (default: false)
	EstimatedDuration uint64         // Optional: Advisory transfer+apply time in seconds (0 = auto-compute from size)
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

// PayloadLogInfo is a diagnostic log uploaded by the device via the
// payload-log-* messages described in fdo.payload.md.
type PayloadLogInfo struct {
	Data        []byte // Assembled log content
	ContentType string // MIME type, defaults to "text/plain"
	Truncated   bool   // Device clipped the output to a local size cap
	Source      string // Origin, e.g. "installer", "stderr"
}

// PayloadLogHandler receives diagnostic logs uploaded by the device after a
// payload has been applied.
//
// Logs are supplementary. Declining one, or failing to store it, never
// changes the outcome reported in payload-result.
type PayloadLogHandler interface {
	// AcceptLog decides whether to receive a log the device has offered.
	// Returning false sends payload-log-ack [false, reasonCode, message] and
	// the device proceeds directly to payload-result. A reasonCode of 0 is
	// replaced with AckReasonDiagnosticsNotRequested.
	AcceptLog(mimeType, name string, size uint64, contentType string) (accepted bool, reasonCode int, message string)

	// HandleLog is called with the fully assembled log. An error is logged
	// but does not fail the session.
	HandleLog(ctx context.Context, mimeType, name string, log *PayloadLogInfo) error
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

// SetLastEstimatedDuration sets the estimated_duration (advisory, in seconds) on the
// most recently added payload. A value of 0 means "do not send the field". This is
// an advisory hint to the device for how long the transfer and application may take,
// allowing it to adjust internal watchdogs.
func (p *PayloadOwner) SetLastEstimatedDuration(seconds uint64) {
	if len(p.payloads) > 0 {
		p.payloads[len(p.payloads)-1].EstimatedDuration = seconds
	}
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
	p.logReceiver = nil
	p.logAck = nil
	p.lastLog = nil
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

	// Answer a pending payload-log-begin before anything else. The device is
	// blocked waiting on this ack and will not send payload-result until it
	// has been answered.
	if p.logAck != nil {
		ack := p.logAck
		p.logAck = nil
		data, err := ack.MarshalCBOR()
		if err != nil {
			return false, false, fmt.Errorf("failed to encode payload-log-ack: %w", err)
		}
		if err := producer.WriteChunk("payload-log-ack", data); err != nil {
			return false, false, fmt.Errorf("failed to send payload-log-ack: %w", err)
		}
		slog.Debug("fdo.payload sent log ack", "accepted", ack.Accepted, "reason", ack.ReasonCode)
		return false, false, nil
	}

	// Main payload processing loop - handle multiple payloads in single call
	for {
		// Check if we're done with all payloads
		if p.currentIndex >= len(p.payloads) && p.sendState == stateIdle {
			return false, true, nil
		}

		// Initialize sender for next payload if needed
		if p.currentSender == nil && p.currentIndex < len(p.payloads) {
			payload := &p.payloads[p.currentIndex]
			fmt.Printf("[PayloadOwner] Starting payload %d/%d: MIME type=%s, Name=%s, RequireAck=%v\n",
				p.currentIndex+1, len(p.payloads), payload.MimeType, payload.Name, payload.RequireAck)
			p.currentSender = chunking.NewChunkSender("payload", payload.Data)

			// Fill the negotiated MTU rather than the 1014-byte default.
			// Reserve headroom for the "fdo.payload:payload-data-<n>" key and
			// the CBOR array framing the producer adds around the chunk.
			want := p.chunkSize
			if want == 0 {
				want = maxPayloadChunkSize
			}
			if mtu := producer.MTU(); mtu > payloadChunkOverhead && want > mtu-payloadChunkOverhead {
				want = mtu - payloadChunkOverhead
			}
			p.currentSender.ChunkSize = want
			fmt.Printf("[PayloadOwner] Negotiated chunk size: %d (MTU=%d, requested=%d)\n",
				want, producer.MTU(), p.chunkSize)

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

			// Set estimated duration (advisory) per chunking-strategy.md
			if payload.EstimatedDuration > 0 {
				p.currentSender.BeginFields.EstimatedDuration = payload.EstimatedDuration
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
				return true, false, nil // Block peer while waiting for ack
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
				fmt.Printf("[PayloadOwner] Payload was rejected, moving to next payload. Reason: %d, Message: %s\n", reason, msg)
				slog.Warn("fdo.payload rejected by device",
					"mime_type", p.currentSender.BeginFields.FSIMFields[-1],
					"reason_code", reason,
					"message", msg)
				// Move to next payload and continue in loop
				p.currentSender = nil
				p.currentIndex++
				p.sendState = stateIdle
				continue // Continue to next payload
			}
			// Ack received, proceed to send chunks
			fmt.Printf("[PayloadOwner] payload-ack received, proceeding to send chunks\n")
			p.sendState = stateSendingChunks
			fallthrough

		case stateSendingChunks:
			// Send chunks one at a time, respecting MTU limits
			chunkIndex := p.currentSender.GetBytesSent() / int64(p.currentSender.ChunkSize)
			chunkKey := fmt.Sprintf("payload-data-%d", chunkIndex)

			// Check if there's space for the chunk. Available() already accounts
			// for CBOR array and key name overhead, so we only need to compare
			// against the chunk data size plus its CBOR bstr header (~5 bytes).
			estimatedSize := p.currentSender.ChunkSize + 5
			if producer.Available(chunkKey) < estimatedSize {
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
	}
}

// receive processes incoming messages from the device.
func (p *PayloadOwner) receive(ctx context.Context, key string, messageBody io.Reader, respond func(string) io.Writer) error {
	slog.Debug("fdo.payload owner received message", "key", key)

	// Diagnostic log upload (device -> owner). Checked before the switch so
	// payload-log-* is not confused with the outbound payload transfer.
	if strings.HasPrefix(key, "payload-log-") {
		return p.receiveLog(ctx, key, messageBody)
	}

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

		fmt.Printf("[PayloadOwner] Received payload-ack for MIME type: %s\n", p.currentSender.BeginFields.FSIMFields[-1])
		if err := p.currentSender.HandleAck(messageBody); err != nil {
			// HandleAck returns error if rejected, but that's not a protocol error
			fmt.Printf("[PayloadOwner] Payload rejected: %v\n", err)
			slog.Debug("fdo.payload ack received", "error", err)
		} else {
			fmt.Printf("[PayloadOwner] Payload accepted\n")
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

// receiveLog handles the payload-log-* reverse-direction chunked transfer
// described in fdo.payload.md. Failures here are logged and swallowed:
// diagnostics are supplementary and must never fail a session that would
// otherwise have succeeded.
func (p *PayloadOwner) receiveLog(ctx context.Context, key string, messageBody io.Reader) error {
	messageName := strings.TrimPrefix(key, "payload-")
	isBegin := strings.HasSuffix(messageName, "-begin")

	if isBegin {
		p.logReceiver = &chunking.ChunkReceiver{
			PayloadName:    "payload-log",
			OnBeginAck:     p.onLogBeginAck,
			DiscardPayload: p.LogHandler == nil,
		}
		p.logReceiver.OnEnd = p.onLogEnd(ctx)
	}

	if p.logReceiver == nil {
		slog.Warn("fdo.payload: log message outside of a transfer", "key", key)
		_, _ = io.Copy(io.Discard, messageBody)
		return nil
	}

	if err := p.logReceiver.HandleMessage(messageName, messageBody); err != nil {
		slog.Warn("fdo.payload: discarding malformed diagnostic log", "key", key, "error", err)
		p.logReceiver = nil
		return nil
	}

	// The chunking receiver records the accept/reject decision; hand it to
	// ProduceInfo, which owns the wire. Only consider this immediately after
	// the begin message: the receiver's own ack-pending flag is cleared by
	// its SendAck, which is not used here because the owner replies through
	// ProduceInfo rather than a respond writer. Without the isBegin guard
	// every subsequent chunk would queue a duplicate ack.
	if isBegin && p.logReceiver.IsAckPending() {
		p.logAck = &chunking.AckMessage{
			Accepted:   p.logReceiver.IsAckAccepted(),
			ReasonCode: p.logAckReasonCode,
			Message:    p.logAckMessage,
		}
		if !p.logReceiver.IsAckAccepted() {
			p.logReceiver = nil
		}
	}

	if strings.HasSuffix(messageName, "-end") {
		p.logReceiver = nil
	}

	return nil
}

// onLogBeginAck applies the LogHandler's accept/reject policy.
func (p *PayloadOwner) onLogBeginAck(begin chunking.BeginMessage) (accepted bool, reasonCode int, message string) {
	contentType, _ := begin.Metadata["content_type"].(string)
	if contentType == "" {
		contentType = "text/plain"
	}
	if p.LogHandler == nil {
		p.logAckReasonCode = chunking.AckReasonDiagnosticsNotRequested
		p.logAckMessage = "Diagnostics not collected"
		return false, p.logAckReasonCode, p.logAckMessage
	}

	var mimeType, name string
	if p.currentSender != nil {
		mimeType, _ = p.currentSender.BeginFields.FSIMFields[-1].(string)
		name, _ = p.currentSender.BeginFields.FSIMFields[-2].(string)
	}

	accepted, reasonCode, message = p.LogHandler.AcceptLog(mimeType, name, begin.TotalSize, contentType)
	if !accepted && reasonCode == 0 {
		reasonCode = chunking.AckReasonDiagnosticsNotRequested
	}
	p.logAckReasonCode, p.logAckMessage = reasonCode, message
	return accepted, reasonCode, message
}

// onLogEnd assembles the log and hands it to the LogHandler.
func (p *PayloadOwner) onLogEnd(ctx context.Context) func(chunking.EndMessage) error {
	return func(chunking.EndMessage) error {
		if p.LogHandler == nil || p.logReceiver == nil {
			return nil
		}
		begin := p.logReceiver.GetBeginMessage()

		contentType, _ := begin.Metadata["content_type"].(string)
		if contentType == "" {
			contentType = "text/plain"
		}
		truncated, _ := begin.Metadata["truncated"].(bool)
		source, _ := begin.Metadata["source"].(string)

		// Copy: the receiver resets its buffer once this callback returns.
		data := append([]byte(nil), p.logReceiver.GetBuffer()...)
		log := &PayloadLogInfo{
			Data:        data,
			ContentType: contentType,
			Truncated:   truncated,
			Source:      source,
		}
		p.lastLog = log

		var mimeType, name string
		if p.currentSender != nil {
			mimeType, _ = p.currentSender.BeginFields.FSIMFields[-1].(string)
			name, _ = p.currentSender.BeginFields.FSIMFields[-2].(string)
		}

		slog.Info("fdo.payload received device diagnostics",
			"bytes", len(data), "content_type", contentType, "truncated", truncated, "source", source)

		if err := p.LogHandler.HandleLog(ctx, mimeType, name, log); err != nil {
			slog.Warn("fdo.payload: log handler failed", "error", err)
		}
		return nil
	}
}

// GetLastLog returns the last diagnostic log uploaded by the device.
func (p *PayloadOwner) GetLastLog() *PayloadLogInfo { return p.lastLog }

// GetLastError returns the last error reported by the device.
func (p *PayloadOwner) GetLastError() *PayloadErrorInfo {
	return p.lastError
}

// GetLastResult returns the last result reported by the device.
func (p *PayloadOwner) GetLastResult() *PayloadResult {
	return p.lastResult
}

// SetChunkSize overrides the payload-data chunk size. When zero (default),
// the chunk size is derived from the negotiated MTU (capped at
// maxPayloadChunkSize). A non-zero value requests that specific size but
// will still be clamped down to the negotiated MTU if necessary.
func (p *PayloadOwner) SetChunkSize(size int) {
	p.chunkSize = size
}
