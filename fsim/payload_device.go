// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/fsim/chunking"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// UnifiedPayloadHandler receives complete payloads at once.
// The framework handles all chunking transparently - the application just processes the complete payload.
// This is the recommended approach for most applications and is similar to how SysConfig works.
type UnifiedPayloadHandler interface {
	// HandlePayload receives a complete payload after all chunks have been assembled.
	// mimeType: MIME type from field -1 (required)
	// name: Optional payload name from field -2
	// size: Total size in bytes (0 if not provided)
	// metadata: Optional metadata map from field -3
	// payload: Complete payload data (all chunks assembled)
	// Returns status code (0=success, 1=warning, 2=error) and optional message.
	HandlePayload(ctx context.Context, mimeType, name string, size uint64, metadata map[string]any, payload []byte) (statusCode int, message string, err error)
}

// ChunkedPayloadHandler receives payloads chunk-by-chunk.
// Use this for memory-constrained scenarios where buffering the entire payload is not feasible.
type ChunkedPayloadHandler interface {
	// SupportsMimeType checks if the device supports the given MIME type.
	// This is called when payload-begin is received to validate the mime_type field.
	SupportsMimeType(mimeType string) bool

	// BeginPayload prepares to receive a payload.
	// mimeType: MIME type from field -1 (required)
	// name: Optional payload name from field -2
	// size: Total size in bytes (0 if not provided)
	// metadata: Optional metadata map from field -3
	// Returns error if MIME type is unsupported or preparation fails.
	BeginPayload(mimeType, name string, size uint64, metadata map[string]any) error

	// ReceiveChunk processes a data chunk.
	// Returns error if chunk cannot be processed.
	ReceiveChunk(data []byte) error

	// EndPayload finalizes and applies the payload.
	// Returns status code (0=success, 1=warning, 2=error) and optional message.
	EndPayload() (statusCode int, message string, err error)

	// CancelPayload aborts the current transfer.
	CancelPayload() error
}

// PayloadAckHandler is called when the owner sends a payload-begin with RequireAck=true.
// It allows the application to accept or reject the payload before data transfer.
type PayloadAckHandler interface {
	// AcceptPayload decides whether to accept or reject a payload based on metadata.
	// mimeType: MIME type from field -1
	// name: Optional payload name from field -2
	// size: Total size in bytes (0 if not provided)
	// metadata: Optional metadata map from field -3
	// Returns: (accepted, reasonCode, message)
	// If accepted is false, reasonCode should be one of:
	//   1 = Unsupported MIME Type
	//   2 = Size Exceeded
	//   3 = Not Applicable
	//   4 = Policy Violation
	AcceptPayload(mimeType, name string, size uint64, metadata map[string]any) (accepted bool, reasonCode int, message string)
}

// PayloadLog is diagnostic output produced while applying a payload, returned
// by a LogProvider and transferred to the owner via the payload-log-* messages
// described in fdo.payload.md.
type PayloadLog struct {
	// Data is the raw diagnostic output. Empty data suppresses the transfer.
	Data []byte

	// ContentType is the MIME type of Data. Defaults to "text/plain".
	ContentType string

	// Truncated indicates the provider already clipped the output.
	Truncated bool

	// Source describes where the output came from, e.g. "installer", "stderr".
	Source string
}

// LogProvider supplies diagnostic output after a payload has been applied.
//
// payload-result carries only a single-line summary, bounded by the negotiated
// ServiceInfo MTU. A LogProvider lets a device return substantial diagnostics -
// installer logs, tracebacks, validation reports - using a reverse-direction
// chunked transfer.
//
// The log is supplementary: it never affects the status reported in
// payload-result, and the owner may decline to receive it.
type LogProvider interface {
	// PayloadLog returns diagnostic output for the payload just processed.
	// Returning a nil PayloadLog, or one with empty Data, suppresses the
	// transfer. statusCode is the value about to be sent in payload-result.
	PayloadLog(ctx context.Context, mimeType, name string, statusCode int) (*PayloadLog, error)
}

// defaultMaxLogSize bounds diagnostic output a device will upload. Logs are a
// convenience, not a reason to blow up an onboarding session, and the FDO 2.0
// client path buffers a module's responses in memory before sending them.
const defaultMaxLogSize = 64 * 1024

// logChunkOverhead reserves room inside the MTU for the
// "fdo.payload:payload-log-data-<n>" key and the CBOR framing around a chunk.
const logChunkOverhead = 100

// Payload implements the fdo.payload FSIM for device-side payload delivery.
// It follows the specification in fdo.payload.md and uses the generic chunking strategy.
// Applications can use either UnifiedPayloadHandler (simple, buffered) or ChunkedPayloadHandler (streaming).
type Payload struct {
	// Option 1: Simple unified handler (framework buffers chunks)
	// Recommended for most applications - chunking is transparent.
	UnifiedHandler UnifiedPayloadHandler

	// Option 2: Chunked handler (app handles chunks individually)
	// Use for memory-constrained scenarios or streaming processing.
	ChunkedHandler ChunkedPayloadHandler

	// Optional: Handler for accept/reject decision when RequireAck=true
	// If nil and RequireAck=true, payloads are automatically accepted.
	AckHandler PayloadAckHandler

	// Optional: Supplies diagnostic output to return to the owner after a
	// payload is applied. If nil, no payload-log-* transfer is attempted.
	LogProvider LogProvider

	// MaxLogSize caps diagnostic output in bytes. Zero selects
	// defaultMaxLogSize. Output beyond the cap is truncated and flagged.
	MaxLogSize int

	// Active indicates if the module is active
	Active bool

	// Internal state
	receiver     *chunking.ChunkReceiver
	buffer       *bytes.Buffer
	begin        chunking.BeginMessage
	resultStatus int
	resultMsg    string
	logSender    *chunking.ChunkSender
}

var _ serviceinfo.DeviceModule = (*Payload)(nil)

// Transition implements serviceinfo.DeviceModule.
func (p *Payload) Transition(active bool) error {
	if !active {
		p.reset()
	}
	return nil
}

// Receive implements serviceinfo.DeviceModule.
func (p *Payload) Receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	// The owner's response to our payload-log-begin. Checked before the
	// generic "payload-" prefix so it is not mistaken for a chunking message
	// belonging to the inbound payload transfer.
	if messageName == "payload-log-ack" {
		return p.handleLogAck(messageBody, respond)
	}

	// Handle chunked payload messages
	if strings.HasPrefix(messageName, "payload-") {
		return p.handleChunkedMessage(ctx, messageName, messageBody, respond)
	}

	// Silently ignore unknown messages for protocol compatibility
	return nil
}

// Yield implements serviceinfo.DeviceModule.
func (p *Payload) Yield(ctx context.Context, respond func(string) io.Writer, yield func()) error {
	return nil
}

// reset clears the internal state.
func (p *Payload) reset() {
	if p.receiver != nil && p.receiver.IsReceiving() && p.ChunkedHandler != nil {
		_ = p.ChunkedHandler.CancelPayload()
	}
	p.receiver = nil
	p.buffer = nil
	p.logSender = nil
}

// handleChunkedMessage processes payload-begin, payload-data-<n>, and payload-end messages.
func (p *Payload) handleChunkedMessage(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer) error {
	if p.UnifiedHandler == nil && p.ChunkedHandler == nil {
		return p.sendError(respond, 4, "No payload handler configured", "")
	}

	// Initialize receiver on first chunked message
	if p.receiver == nil {
		p.receiver = &chunking.ChunkReceiver{
			PayloadName:    "payload",
			DiscardPayload: p.UnifiedHandler == nil,
		}

		// Set up ack callback if handler provided
		if p.AckHandler != nil {
			p.receiver.OnBeginAck = p.onBeginAck
		}

		// Set up callbacks based on handler mode
		if p.UnifiedHandler != nil {
			// Unified mode: buffer everything
			p.buffer = &bytes.Buffer{}
			p.receiver.OnBegin = p.onBeginUnified
			p.receiver.OnChunk = p.onChunkUnified
			p.receiver.OnEnd = p.onEndUnified(ctx)
		} else {
			// Chunked mode: delegate to handler
			p.receiver.OnBegin = p.onBeginChunked
			p.receiver.OnChunk = p.onChunkChunked
			p.receiver.OnEnd = p.onEndChunked
		}
	}

	// Handle the message using the chunking receiver
	if err := p.receiver.HandleMessage(messageName, messageBody); err != nil {
		// On error, send error response and reset
		if sendErr := p.sendError(respond, 6, "Transfer error", err.Error()); sendErr != nil {
			return sendErr
		}
		p.receiver = nil
		if p.ChunkedHandler != nil {
			_ = p.ChunkedHandler.CancelPayload()
		}
		// Return nil to allow protocol to continue after sending error
		return nil
	}

	// After begin message with RequireAck, send payload-ack
	if strings.HasSuffix(messageName, "-begin") && p.receiver.IsAckPending() {
		if err := p.receiver.SendAck(respond); err != nil {
			return fmt.Errorf("failed to send ack: %w", err)
		}
		// If rejected, we're done with this payload
		if !p.receiver.IsAckAccepted() {
			p.receiver = nil
			return nil
		}
	}

	// After successful end message, offer diagnostics and then send the
	// result. payload-result is terminal per chunking-strategy.md, so the
	// log transfer must precede it.
	if strings.HasSuffix(messageName, "-end") && !p.receiver.IsReceiving() {
		p.receiver = nil

		started, err := p.startLogTransfer(ctx, respond)
		if err != nil {
			return err
		}
		if started {
			// Result is deferred until the owner accepts or declines the log.
			return nil
		}

		return p.sendResult(respond)
	}

	return nil
}

// sendResult sends the terminal payload-result message.
func (p *Payload) sendResult(respond func(string) io.Writer) error {
	result := chunking.ResultMessage{
		StatusCode: p.resultStatus,
		Message:    p.resultMsg,
	}
	resultData, err := result.MarshalCBOR()
	if err != nil {
		return fmt.Errorf("failed to encode result: %w", err)
	}

	w := respond("payload-result")
	if _, err := w.Write(resultData); err != nil {
		return fmt.Errorf("failed to send result: %w", err)
	}
	return nil
}

// startLogTransfer asks the LogProvider for diagnostics and, if any are
// available, sends payload-log-begin with require_ack set. It reports whether
// a transfer was started; when false the caller should send payload-result
// immediately.
func (p *Payload) startLogTransfer(ctx context.Context, respond func(string) io.Writer) (bool, error) {
	if p.LogProvider == nil {
		return false, nil
	}

	mimeType, _ := p.begin.FSIMFields[-1].(string)
	name, _ := p.begin.FSIMFields[-2].(string)

	log, err := p.LogProvider.PayloadLog(ctx, mimeType, name, p.resultStatus)
	if err != nil {
		// Diagnostics are supplementary: failing to collect them must not
		// fail onboarding or suppress the result.
		slog.Warn("fdo.payload: log provider failed", "error", err)
		return false, nil
	}
	if log == nil || len(log.Data) == 0 {
		return false, nil
	}

	maxSize := p.MaxLogSize
	if maxSize <= 0 {
		maxSize = defaultMaxLogSize
	}
	data, truncated := log.Data, log.Truncated
	if len(data) > maxSize {
		data, truncated = data[:maxSize], true
	}

	contentType := log.ContentType
	if contentType == "" {
		contentType = "text/plain"
	}
	metadata := map[string]any{"content_type": contentType}
	if truncated {
		metadata["truncated"] = true
	}
	if log.Source != "" {
		metadata["source"] = log.Source
	}

	sender := chunking.NewChunkSender("payload-log", data)
	sender.BeginFields.HashAlg = "sha256"
	sender.BeginFields.RequireAck = true
	sender.BeginFields.Metadata = metadata
	if mtu, ok := ctx.Value(serviceinfo.MTUKey{}).(uint16); ok && int(mtu) > logChunkOverhead {
		sender.ChunkSize = int(mtu) - logChunkOverhead
	}

	if err := sender.SendBeginToWriter(respond); err != nil {
		return false, fmt.Errorf("failed to send payload-log-begin: %w", err)
	}
	p.logSender = sender

	slog.Debug("fdo.payload sent log begin",
		"size", len(data), "truncated", truncated, "content_type", contentType)

	return true, nil
}

// handleLogAck processes the owner's payload-log-ack. On acceptance the log
// chunks and payload-log-end are sent, followed by the terminal
// payload-result. On rejection the result is sent immediately.
func (p *Payload) handleLogAck(messageBody io.Reader, respond func(string) io.Writer) error {
	sender := p.logSender
	p.logSender = nil
	if sender == nil {
		slog.Warn("fdo.payload: received payload-log-ack with no log transfer in progress")
		return nil
	}

	data, err := io.ReadAll(messageBody)
	if err != nil {
		return fmt.Errorf("failed to read payload-log-ack: %w", err)
	}
	var ack chunking.AckMessage
	if err := ack.UnmarshalCBOR(data); err != nil {
		return fmt.Errorf("failed to decode payload-log-ack: %w", err)
	}

	if !ack.Accepted {
		slog.Debug("fdo.payload: owner declined log",
			"reason_code", ack.ReasonCode, "message", ack.Message)
		return p.sendResult(respond)
	}

	for {
		done, err := sender.SendNextChunkToWriter(respond)
		if err != nil {
			return fmt.Errorf("failed to send payload-log chunk: %w", err)
		}
		if done {
			break
		}
	}
	if err := sender.SendEndToWriter(respond); err != nil {
		return fmt.Errorf("failed to send payload-log-end: %w", err)
	}

	slog.Debug("fdo.payload sent log", "bytes", sender.GetBytesSent())

	return p.sendResult(respond)
}

// onBeginAck is called when payload-begin with RequireAck=true is received.
// It delegates to the AckHandler to decide whether to accept or reject.
func (p *Payload) onBeginAck(begin chunking.BeginMessage) (accepted bool, reasonCode int, message string) {
	if p.AckHandler == nil {
		// No handler, accept by default
		return true, 0, ""
	}

	// Extract MIME type from field -1 (required per fdo.payload.md)
	mimeType, _ := begin.FSIMFields[-1].(string)

	// Extract optional name from field -2
	name, _ := begin.FSIMFields[-2].(string)

	// Extract optional metadata from field -3
	var metadata map[string]any
	if m, ok := begin.FSIMFields[-3].(map[string]any); ok {
		metadata = m
	} else if m, ok := begin.FSIMFields[-3].(map[any]any); ok {
		metadata = make(map[string]any)
		for k, v := range m {
			if ks, ok := k.(string); ok {
				metadata[ks] = v
			}
		}
	}

	return p.AckHandler.AcceptPayload(mimeType, name, begin.TotalSize, metadata)
}

// Unified mode callbacks - buffer all chunks and call handler once

// onBeginUnified is called when payload-begin is received in unified mode.
func (p *Payload) onBeginUnified(begin chunking.BeginMessage) error {
	if begin.EstimatedDuration > 0 {
		slog.Info("fdo.payload: server estimates transfer+apply time",
			"estimated_duration_sec", begin.EstimatedDuration,
			"total_size", begin.TotalSize)
	}
	// Store begin message for later use in onEndUnified
	p.begin = begin
	return nil
}

// onChunkUnified is called for each payload-data-<n> chunk in unified mode.
func (p *Payload) onChunkUnified(data []byte) error {
	// Just buffer the chunk - handler will be called in onEnd
	p.buffer.Write(data)
	return nil
}

// onEndUnified returns a callback for when payload-end is received in unified mode.
func (p *Payload) onEndUnified(ctx context.Context) func(chunking.EndMessage) error {
	return func(end chunking.EndMessage) error {
		// Check if payload was rejected during ACK phase
		if p.receiver != nil && p.receiver.IsAckPending() && !p.receiver.IsAckAccepted() {
			// Payload was rejected, don't process it
			return nil
		}
		// Extract MIME type from field -1 (required per fdo.payload.md)
		mimeType, ok := p.begin.FSIMFields[-1].(string)
		if !ok || mimeType == "" {
			return fmt.Errorf("missing required mime_type field (-1)")
		}

		// Extract optional name from field -2
		name, _ := p.begin.FSIMFields[-2].(string)

		// Extract optional metadata from field -3
		var metadata map[string]any
		if m, ok := p.begin.FSIMFields[-3].(map[string]any); ok {
			metadata = m
		} else if m, ok := p.begin.FSIMFields[-3].(map[any]any); ok {
			// Convert map[any]any to map[string]any
			metadata = make(map[string]any)
			for k, v := range m {
				if ks, ok := k.(string); ok {
					metadata[ks] = v
				}
			}
		}

		slog.Debug("fdo.payload unified",
			"mime_type", mimeType,
			"name", name,
			"size", p.begin.TotalSize,
			"received", p.buffer.Len())

		// Call unified handler with complete payload
		statusCode, message, err := p.UnifiedHandler.HandlePayload(ctx, mimeType, name, p.begin.TotalSize, metadata, p.buffer.Bytes())
		if err != nil {
			return err
		}

		// Store result for sending after HandleMessage completes
		p.resultStatus = statusCode
		p.resultMsg = message

		slog.Debug("fdo.payload unified end", "status", statusCode, "message", message)
		return nil
	}
}

// Chunked mode callbacks - delegate to handler for each chunk

// onBeginChunked is called when payload-begin is received in chunked mode.
func (p *Payload) onBeginChunked(begin chunking.BeginMessage) error {
	// Extract MIME type from field -1 (required per fdo.payload.md)
	mimeType, ok := begin.FSIMFields[-1].(string)
	if !ok || mimeType == "" {
		return fmt.Errorf("missing required mime_type field (-1)")
	}

	// Check if MIME type is supported
	if !p.ChunkedHandler.SupportsMimeType(mimeType) {
		return fmt.Errorf("MIME type '%s' not supported", mimeType)
	}

	// Extract optional name from field -2
	name, _ := begin.FSIMFields[-2].(string)

	// Extract optional metadata from field -3
	var metadata map[string]any
	if m, ok := begin.FSIMFields[-3].(map[string]any); ok {
		metadata = m
	} else if m, ok := begin.FSIMFields[-3].(map[any]any); ok {
		// Convert map[any]any to map[string]any
		metadata = make(map[string]any)
		for k, v := range m {
			if ks, ok := k.(string); ok {
				metadata[ks] = v
			}
		}
	}

	slog.Debug("fdo.payload chunked begin",
		"mime_type", mimeType,
		"name", name,
		"size", begin.TotalSize)

	if begin.EstimatedDuration > 0 {
		slog.Info("fdo.payload: server estimates transfer+apply time",
			"estimated_duration_sec", begin.EstimatedDuration,
			"mime_type", mimeType,
			"total_size", begin.TotalSize)
	}

	// Call application handler
	return p.ChunkedHandler.BeginPayload(mimeType, name, begin.TotalSize, metadata)
}

// onChunkChunked is called for each payload-data-<n> chunk in chunked mode.
func (p *Payload) onChunkChunked(data []byte) error {
	return p.ChunkedHandler.ReceiveChunk(data)
}

// onEndChunked is called when payload-end is received in chunked mode.
func (p *Payload) onEndChunked(end chunking.EndMessage) error {
	// Finalize and apply the payload
	statusCode, message, err := p.ChunkedHandler.EndPayload()
	if err != nil {
		return err
	}

	// Store result for sending after HandleMessage completes
	p.resultStatus = statusCode
	p.resultMsg = message

	slog.Debug("fdo.payload chunked end", "status", statusCode, "message", message)
	return nil
}

// sendError sends an error message to the owner per fdo.payload.md error format.
func (p *Payload) sendError(respond func(string) io.Writer, code int, message, details string) error {
	// Error format: map with keys 0=code, 1=message, 2=details
	errorMsg := make(map[any]any)
	errorMsg[0] = code
	errorMsg[1] = message
	if details != "" {
		errorMsg[2] = details
	}

	w := respond("error")
	if err := cbor.NewEncoder(w).Encode(errorMsg); err != nil {
		return fmt.Errorf("failed to encode error: %w", err)
	}

	// Return nil after successfully sending error message
	// The error has been communicated to the owner via the error message
	return nil
}
