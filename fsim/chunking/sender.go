// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package chunking

import (
	"bytes"
	"fmt"
	"io"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// ProducerWriter is the minimal interface needed for sending chunks.
// This allows both serviceinfo.Producer and test mocks to be used.
type ProducerWriter interface {
	WriteChunk(messageName string, messageBody []byte) error
}

// ChunkSender handles sending chunked payloads on the owner side.
// It implements the generic chunking strategy from chunking-strategy.md.
type ChunkSender struct {
	// PayloadName is the logical name of the payload (e.g., "payload", "cert", "csr")
	PayloadName string

	// Data is the payload to send
	Data []byte

	// ChunkSize is the maximum size of each data chunk (default: 1014 bytes per spec)
	ChunkSize int

	// BeginFields contains metadata for the *-begin message
	BeginFields BeginMessage

	// EndFields contains metadata for the *-end message
	EndFields EndMessage

	// AutoComputeHash automatically computes and includes hash in end message
	AutoComputeHash bool

	// Internal state
	bytesSent     int64
	completed     bool
	beginSent     bool   // Whether begin message has been sent
	waitingForAck bool   // Whether we're waiting for *-ack response
	ackReceived   bool   // Whether ack has been received (only relevant if RequireAck)
	ackRejected   bool   // Whether the transfer was rejected
	rejectReason  int    // Reason code if rejected
	rejectMsg     string // Message if rejected
}

// NewChunkSender creates a new ChunkSender with default settings.
func NewChunkSender(payloadName string, data []byte) *ChunkSender {
	return &ChunkSender{
		PayloadName:     payloadName,
		Data:            data,
		ChunkSize:       1014, // Default per chunking-strategy.md
		AutoComputeHash: true,
		BeginFields: BeginMessage{
			TotalSize:  uint64(len(data)),
			FSIMFields: make(map[int]any),
		},
		EndFields: EndMessage{
			Status:     0,
			FSIMFields: make(map[int]any),
		},
	}
}

// SendBegin sends the *-begin message to initiate the transfer.
// If RequireAck is set, the sender will wait for an *-ack message before sending data.
func (s *ChunkSender) SendBegin(producer ProducerWriter) error {
	if s.beginSent {
		return fmt.Errorf("begin already sent")
	}
	if s.bytesSent > 0 {
		return fmt.Errorf("transfer already started")
	}

	// Encode begin message
	data, err := s.BeginFields.MarshalCBOR()
	if err != nil {
		return fmt.Errorf("failed to encode begin message: %w", err)
	}

	// Send via producer
	if err := producer.WriteChunk(s.PayloadName+"-begin", data); err != nil {
		return fmt.Errorf("failed to send begin message: %w", err)
	}

	s.beginSent = true

	// If RequireAck is set, we need to wait for ack before sending data
	if s.BeginFields.RequireAck {
		s.waitingForAck = true
	}

	return nil
}

// SendNextChunk sends the next data chunk. Returns true when all chunks have been sent.
// Returns an error if waiting for ack or if transfer was rejected.
func (s *ChunkSender) SendNextChunk(producer ProducerWriter) (done bool, err error) {
	if s.completed {
		return true, nil
	}

	// Check if we're waiting for ack
	if s.waitingForAck {
		return false, fmt.Errorf("waiting for ack before sending data")
	}

	// Check if transfer was rejected
	if s.ackRejected {
		return false, fmt.Errorf("transfer rejected: code=%d, message=%s", s.rejectReason, s.rejectMsg)
	}

	if s.bytesSent >= int64(len(s.Data)) {
		return true, nil
	}

	// Calculate chunk size
	remaining := int64(len(s.Data)) - s.bytesSent
	chunkLen := int64(s.ChunkSize)
	if chunkLen > remaining {
		chunkLen = remaining
	}

	// Extract chunk
	chunk := s.Data[s.bytesSent : s.bytesSent+chunkLen]

	// Calculate chunk index
	chunkIndex := s.bytesSent / int64(s.ChunkSize)

	// Encode chunk as CBOR bstr
	var buf bytes.Buffer
	if err := cbor.NewEncoder(&buf).Encode(chunk); err != nil {
		return false, fmt.Errorf("failed to encode chunk: %w", err)
	}

	// Send chunk with indexed key name
	chunkKey := fmt.Sprintf("%s-data-%d", s.PayloadName, chunkIndex)
	if err := producer.WriteChunk(chunkKey, buf.Bytes()); err != nil {
		return false, fmt.Errorf("failed to send chunk: %w", err)
	}

	s.bytesSent += chunkLen

	// Check if done
	return s.bytesSent >= int64(len(s.Data)), nil
}

// SendEnd sends the *-end message to complete the transfer.
func (s *ChunkSender) SendEnd(producer ProducerWriter) error {
	if s.bytesSent < int64(len(s.Data)) {
		return fmt.Errorf("not all data has been sent: %d/%d bytes", s.bytesSent, len(s.Data))
	}

	if s.completed {
		return fmt.Errorf("transfer already completed")
	}

	// Auto-compute hash if enabled and hash algorithm was specified
	if s.AutoComputeHash && s.BeginFields.HashAlg != "" && len(s.EndFields.HashValue) == 0 {
		hash, err := ComputeHash(s.BeginFields.HashAlg, s.Data)
		if err != nil {
			return fmt.Errorf("failed to compute hash: %w", err)
		}
		s.EndFields.HashValue = hash
	}

	// Encode end message
	data, err := s.EndFields.MarshalCBOR()
	if err != nil {
		return fmt.Errorf("failed to encode end message: %w", err)
	}

	// Send via producer
	if err := producer.WriteChunk(s.PayloadName+"-end", data); err != nil {
		return fmt.Errorf("failed to send end message: %w", err)
	}

	s.completed = true
	return nil
}

// HandleResult processes a *-result message from the receiver.
func (s *ChunkSender) HandleResult(messageBody io.Reader) (*ResultMessage, error) {
	data, err := io.ReadAll(messageBody)
	if err != nil {
		return nil, fmt.Errorf("failed to read result message: %w", err)
	}

	var result ResultMessage
	if err := result.UnmarshalCBOR(data); err != nil {
		return nil, fmt.Errorf("failed to decode result message: %w", err)
	}

	return &result, nil
}

// Reset resets the sender state to allow resending.
func (s *ChunkSender) Reset() {
	s.bytesSent = 0
	s.completed = false
	s.beginSent = false
	s.waitingForAck = false
	s.ackReceived = false
	s.ackRejected = false
	s.rejectReason = 0
	s.rejectMsg = ""
}

// IsCompleted returns true if the transfer has been completed.
func (s *ChunkSender) IsCompleted() bool {
	return s.completed
}

// IsWaitingForAck returns true if sender is waiting for *-ack response.
func (s *ChunkSender) IsWaitingForAck() bool {
	return s.waitingForAck
}

// IsRejected returns true if the transfer was rejected by the receiver.
func (s *ChunkSender) IsRejected() bool {
	return s.ackRejected
}

// GetRejectReason returns the rejection reason code and message.
func (s *ChunkSender) GetRejectReason() (int, string) {
	return s.rejectReason, s.rejectMsg
}

// HandleAck processes a *-ack message from the receiver.
// Returns nil if accepted, or an error with the rejection details if rejected.
func (s *ChunkSender) HandleAck(messageBody io.Reader) error {
	if !s.waitingForAck {
		return fmt.Errorf("not waiting for ack")
	}

	data, err := io.ReadAll(messageBody)
	if err != nil {
		return fmt.Errorf("failed to read ack message: %w", err)
	}

	var ack AckMessage
	if err := ack.UnmarshalCBOR(data); err != nil {
		return fmt.Errorf("failed to decode ack message: %w", err)
	}

	s.waitingForAck = false
	s.ackReceived = true

	if ack.Accepted {
		return nil
	}

	// Transfer was rejected
	s.ackRejected = true
	s.rejectReason = ack.ReasonCode
	s.rejectMsg = ack.Message

	return fmt.Errorf("transfer rejected: code=%d, message=%s", ack.ReasonCode, ack.Message)
}

// GetBytesSent returns the number of bytes sent so far.
func (s *ChunkSender) GetBytesSent() int64 {
	return s.bytesSent
}

// GetProgress returns the transfer progress as a percentage (0-100).
func (s *ChunkSender) GetProgress() float64 {
	if len(s.Data) == 0 {
		return 100.0
	}
	return float64(s.bytesSent) / float64(len(s.Data)) * 100.0
}

// SendBeginToWriter sends the *-begin message using a respond function (for device-side sending).
func (s *ChunkSender) SendBeginToWriter(respond func(string) io.Writer) error {
	if s.bytesSent > 0 {
		return fmt.Errorf("transfer already started")
	}

	// Encode begin message
	data, err := s.BeginFields.MarshalCBOR()
	if err != nil {
		return fmt.Errorf("failed to encode begin message: %w", err)
	}

	// Send via respond function
	w := respond(s.PayloadName + "-begin")
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("failed to send begin message: %w", err)
	}

	return nil
}

// SendNextChunkToWriter sends the next data chunk using a respond function. Returns true when all chunks have been sent.
func (s *ChunkSender) SendNextChunkToWriter(respond func(string) io.Writer) (done bool, err error) {
	if s.completed {
		return true, nil
	}

	if s.bytesSent >= int64(len(s.Data)) {
		return true, nil
	}

	// Calculate chunk size
	remaining := int64(len(s.Data)) - s.bytesSent
	chunkLen := int64(s.ChunkSize)
	if chunkLen > remaining {
		chunkLen = remaining
	}

	// Extract chunk
	chunk := s.Data[s.bytesSent : s.bytesSent+chunkLen]

	// Calculate chunk index
	chunkIndex := s.bytesSent / int64(s.ChunkSize)

	// Encode chunk as CBOR bstr
	var buf bytes.Buffer
	if err := cbor.NewEncoder(&buf).Encode(chunk); err != nil {
		return false, fmt.Errorf("failed to encode chunk: %w", err)
	}

	// Send chunk with indexed key name
	chunkKey := fmt.Sprintf("%s-data-%d", s.PayloadName, chunkIndex)
	w := respond(chunkKey)
	if _, err := w.Write(buf.Bytes()); err != nil {
		return false, fmt.Errorf("failed to send chunk: %w", err)
	}

	s.bytesSent += chunkLen

	// Check if done
	return s.bytesSent >= int64(len(s.Data)), nil
}

// SendEndToWriter sends the *-end message using a respond function.
func (s *ChunkSender) SendEndToWriter(respond func(string) io.Writer) error {
	if s.bytesSent < int64(len(s.Data)) {
		return fmt.Errorf("not all data has been sent: %d/%d bytes", s.bytesSent, len(s.Data))
	}

	if s.completed {
		return fmt.Errorf("transfer already completed")
	}

	// Auto-compute hash if enabled and hash algorithm was specified
	if s.AutoComputeHash && s.BeginFields.HashAlg != "" && len(s.EndFields.HashValue) == 0 {
		hash, err := ComputeHash(s.BeginFields.HashAlg, s.Data)
		if err != nil {
			return fmt.Errorf("failed to compute hash: %w", err)
		}
		s.EndFields.HashValue = hash
	}

	// Encode end message
	data, err := s.EndFields.MarshalCBOR()
	if err != nil {
		return fmt.Errorf("failed to encode end message: %w", err)
	}

	// Send via respond function
	w := respond(s.PayloadName + "-end")
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("failed to send end message: %w", err)
	}

	s.completed = true
	return nil
}
