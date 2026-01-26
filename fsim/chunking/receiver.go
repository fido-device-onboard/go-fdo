// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package chunking

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// ChunkReceiver handles receiving chunked payloads on the device side.
// It implements the generic chunking strategy from chunking-strategy.md.
type ChunkReceiver struct {
	// PayloadName is the logical name of the payload (e.g., "payload", "cert", "csr")
	PayloadName string

	// Callbacks for FSIM-specific handling
	OnBegin func(begin BeginMessage) error // Called when *-begin is received
	OnChunk func(data []byte) error        // Called for each *-data-<n> chunk
	OnEnd   func(end EndMessage) error     // Called when *-end is received

	// OnBeginAck is called when *-begin with RequireAck=true is received.
	// Returns (accepted, reasonCode, message). If accepted is false, the transfer is rejected.
	// If this callback is nil and RequireAck is true, the transfer is automatically accepted.
	OnBeginAck func(begin BeginMessage) (accepted bool, reasonCode int, message string)

	// Internal state
	buffer       bytes.Buffer
	totalBytes   int64
	expectedSize uint64
	hashAlg      string
	receiving    bool
	nextChunk    int          // Expected next chunk index
	ackPending   bool         // Whether *-ack needs to be sent
	ackAccepted  bool         // Whether the pending ack is an accept or reject
	ackReason    int          // Reason code for rejection
	ackMessage   string       // Message for rejection
	beginMsg     BeginMessage // Stored begin message for ack handling
}

// HandleMessage processes incoming chunking messages.
// The messageName should be the part after "module:" (e.g., "payload-begin", "payload-data-0").
func (r *ChunkReceiver) HandleMessage(messageName string, messageBody io.Reader) error {
	// Parse message type
	if strings.HasSuffix(messageName, "-begin") {
		return r.handleBegin(messageBody)
	} else if strings.HasSuffix(messageName, "-end") {
		return r.handleEnd(messageBody)
	} else if strings.Contains(messageName, "-data-") {
		return r.handleData(messageName, messageBody)
	}

	return fmt.Errorf("unknown chunking message: %s", messageName)
}

// handleBegin processes the *-begin message.
func (r *ChunkReceiver) handleBegin(messageBody io.Reader) error {
	if r.receiving {
		return fmt.Errorf("already receiving a payload")
	}

	// Decode begin message
	var begin BeginMessage
	data, err := io.ReadAll(messageBody)
	if err != nil {
		return fmt.Errorf("failed to read begin message: %w", err)
	}

	if err := begin.UnmarshalCBOR(data); err != nil {
		return fmt.Errorf("failed to decode begin message: %w", err)
	}

	// Store state
	r.expectedSize = begin.TotalSize
	r.hashAlg = begin.HashAlg
	r.totalBytes = 0
	r.nextChunk = 0
	r.buffer.Reset()
	r.beginMsg = begin

	// Handle RequireAck - check with callback if provided
	if begin.RequireAck {
		r.ackPending = true
		if r.OnBeginAck != nil {
			r.ackAccepted, r.ackReason, r.ackMessage = r.OnBeginAck(begin)
		} else {
			// Default: accept if no callback provided
			r.ackAccepted = true
		}
		// If rejected, don't set receiving=true
		if !r.ackAccepted {
			return nil
		}
	}

	r.receiving = true

	// Call FSIM-specific handler
	if r.OnBegin != nil {
		if err := r.OnBegin(begin); err != nil {
			r.reset()
			return fmt.Errorf("begin handler failed: %w", err)
		}
	}

	return nil
}

// handleData processes *-data-<n> messages.
func (r *ChunkReceiver) handleData(messageName string, messageBody io.Reader) error {
	if !r.receiving {
		return fmt.Errorf("not ready to receive data (call *-begin first)")
	}

	// Extract chunk index from message name (e.g., "payload-data-5" -> 5)
	parts := strings.Split(messageName, "-")
	if len(parts) < 3 {
		return fmt.Errorf("invalid data message name: %s", messageName)
	}
	chunkIndex, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return fmt.Errorf("invalid chunk index in %s: %w", messageName, err)
	}

	// Verify chunk ordering
	if chunkIndex != r.nextChunk {
		return fmt.Errorf("chunk out of order: expected %d, got %d", r.nextChunk, chunkIndex)
	}

	// Decode chunk data (must be CBOR bstr)
	var chunkData []byte
	if err := cbor.NewDecoder(messageBody).Decode(&chunkData); err != nil {
		return fmt.Errorf("failed to decode chunk data: %w", err)
	}

	// Check if we would exceed expected size
	if r.expectedSize > 0 && r.totalBytes+int64(len(chunkData)) > int64(r.expectedSize) {
		r.reset()
		return fmt.Errorf("chunk would exceed expected size: %d + %d > %d",
			r.totalBytes, len(chunkData), r.expectedSize)
	}

	// Buffer the chunk
	r.buffer.Write(chunkData)
	r.totalBytes += int64(len(chunkData))
	r.nextChunk++

	// Call FSIM-specific handler if provided
	if r.OnChunk != nil {
		if err := r.OnChunk(chunkData); err != nil {
			r.reset()
			return fmt.Errorf("chunk handler failed: %w", err)
		}
	}

	return nil
}

// handleEnd processes the *-end message.
func (r *ChunkReceiver) handleEnd(messageBody io.Reader) error {
	if !r.receiving {
		return fmt.Errorf("no active transfer to end")
	}

	// Decode end message
	var end EndMessage
	data, err := io.ReadAll(messageBody)
	if err != nil {
		return fmt.Errorf("failed to read end message: %w", err)
	}

	if err := end.UnmarshalCBOR(data); err != nil {
		return fmt.Errorf("failed to decode end message: %w", err)
	}

	// Verify size if provided
	if r.expectedSize > 0 && r.totalBytes != int64(r.expectedSize) {
		r.reset()
		return fmt.Errorf("size mismatch: expected %d, received %d", r.expectedSize, r.totalBytes)
	}

	// Verify hash if provided
	if len(end.HashValue) > 0 && r.hashAlg != "" {
		if err := VerifyHash(r.hashAlg, r.buffer.Bytes(), end.HashValue); err != nil {
			r.reset()
			return fmt.Errorf("hash verification failed: %w", err)
		}
	}

	// Call FSIM-specific handler
	var handlerErr error
	if r.OnEnd != nil {
		handlerErr = r.OnEnd(end)
	}

	// Reset state after handler has had a chance to access the buffer
	if handlerErr != nil {
		r.reset()
		return fmt.Errorf("end handler failed: %w", handlerErr)
	}

	// Only reset on successful completion
	r.reset()

	return nil
}

// SendResult sends a *-result message to acknowledge completion.
func (r *ChunkReceiver) SendResult(respond func(string) io.Writer, statusCode int, message string) error {
	result := ResultMessage{
		StatusCode: statusCode,
		Message:    message,
	}

	data, err := result.MarshalCBOR()
	if err != nil {
		return fmt.Errorf("failed to encode result: %w", err)
	}

	w := respond(r.PayloadName + "-result")
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("failed to send result: %w", err)
	}

	return nil
}

// SendAck sends a *-ack message in response to *-begin with RequireAck=true.
// This should be called after HandleMessage for *-begin when IsAckPending() returns true.
func (r *ChunkReceiver) SendAck(respond func(string) io.Writer) error {
	if !r.ackPending {
		return fmt.Errorf("no ack pending")
	}

	ack := AckMessage{
		Accepted:   r.ackAccepted,
		ReasonCode: r.ackReason,
		Message:    r.ackMessage,
	}

	data, err := ack.MarshalCBOR()
	if err != nil {
		return fmt.Errorf("failed to encode ack: %w", err)
	}

	w := respond(r.PayloadName + "-ack")
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("failed to send ack: %w", err)
	}

	r.ackPending = false

	// If rejected, reset state
	if !r.ackAccepted {
		r.reset()
	}

	return nil
}

// IsAckPending returns true if a *-ack message needs to be sent.
func (r *ChunkReceiver) IsAckPending() bool {
	return r.ackPending
}

// IsAckAccepted returns true if the pending ack is an accept (not reject).
func (r *ChunkReceiver) IsAckAccepted() bool {
	return r.ackAccepted
}

// GetBeginMessage returns the stored begin message (useful for ack callback context).
func (r *ChunkReceiver) GetBeginMessage() BeginMessage {
	return r.beginMsg
}

// GetBuffer returns the accumulated payload data.
// This should be called after all chunks have been received.
func (r *ChunkReceiver) GetBuffer() []byte {
	return r.buffer.Bytes()
}

// GetTotalBytes returns the total number of bytes received.
func (r *ChunkReceiver) GetTotalBytes() int64 {
	return r.totalBytes
}

// IsReceiving returns true if currently receiving a payload.
func (r *ChunkReceiver) IsReceiving() bool {
	return r.receiving
}

// Reset clears the internal state and cancels any active transfer.
func (r *ChunkReceiver) Reset() {
	r.reset()
}

// reset clears internal state.
func (r *ChunkReceiver) reset() {
	r.receiving = false
	r.totalBytes = 0
	r.expectedSize = 0
	r.hashAlg = ""
	r.nextChunk = 0
	r.buffer.Reset()
	r.ackPending = false
	r.ackAccepted = false
	r.ackReason = 0
	r.ackMessage = ""
	r.beginMsg = BeginMessage{}
}
