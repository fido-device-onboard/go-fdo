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

// UnifiedImageHandler receives complete boot images at once.
// The framework handles all chunking transparently - the application just processes the complete image.
// This is the recommended approach for most applications.
type UnifiedImageHandler interface {
	// HandleImage receives a complete boot image after all chunks have been assembled.
	// imageType: Image type from field -1 (required, e.g., "application/x-iso9660-image")
	// name: Optional image name from field -2
	// size: Total size in bytes (0 if not provided)
	// metadata: Optional metadata map from field -3
	// image: Complete image data (all chunks assembled)
	// Returns status code (0=success, 1=warning, 2=error) and optional message.
	HandleImage(ctx context.Context, imageType, name string, size uint64, metadata map[string]any, image []byte) (statusCode int, message string, err error)
}

// ChunkedImageHandler receives boot images chunk-by-chunk.
// Use this for memory-constrained scenarios where buffering the entire image is not feasible.
type ChunkedImageHandler interface {
	// SupportsImageType checks if the device supports the given image type.
	// This is called when image-begin is received to validate the image_type field.
	SupportsImageType(imageType string) bool

	// BeginImage prepares to receive a boot image.
	// imageType: Image type from field -1 (required)
	// name: Optional image name from field -2
	// size: Total size in bytes (0 if not provided)
	// metadata: Optional metadata map from field -3
	// Returns error if image type is unsupported or preparation fails.
	BeginImage(imageType, name string, size uint64, metadata map[string]any) error

	// ReceiveChunk processes a data chunk.
	// Returns error if chunk cannot be processed.
	ReceiveChunk(data []byte) error

	// EndImage finalizes and applies the boot image.
	// Returns status code (0=success, 1=warning, 2=error) and optional message.
	EndImage() (statusCode int, message string, err error)

	// CancelImage aborts the current transfer.
	CancelImage() error
}

// ImageAckHandler is called when the owner sends an image-begin with RequireAck=true.
// It allows the application to accept or reject the image before data transfer.
type ImageAckHandler interface {
	// AcceptImage decides whether to accept or reject a boot image based on metadata.
	// imageType: Image type from field -1
	// name: Optional image name from field -2
	// size: Total size in bytes (0 if not provided)
	// metadata: Optional metadata map from field -3
	// Returns: (accepted, reasonCode, message)
	// If accepted is false, reasonCode should be one of:
	//   1 = Unsupported Image Type
	//   2 = Size Exceeded
	//   3 = Not Applicable
	//   4 = Policy Violation
	AcceptImage(imageType, name string, size uint64, metadata map[string]any) (accepted bool, reasonCode int, message string)
}

// BiosParamHandler is called when the owner sends BIOS parameters to set.
// This allows the application to handle BIOS configuration with success/error responses.
type BiosParamHandler interface {
	// SetBiosParameter sets a BIOS parameter and returns the result.
	// name: Parameter name (e.g., "secure-boot", "bios-password", "boot-order")
	// value: Parameter value as string (parsed according to parameter type)
	// Returns: (statusCode, message, error)
	// statusCode: 0=success, 1=warning, 2=error (per BMO spec)
	// message: Human-readable result message
	// error: Internal error (should not be sent to owner)
	SetBiosParameter(name, value string) (statusCode int, message string, err error)
}

// BiosParam represents a BIOS parameter name/value pair.
type BiosParam struct {
	Name  string `cbor:"name"`
	Value string `cbor:"value"`
}

// BMO implements the fdo.bmo FSIM for device-side boot image delivery.
// It follows the specification in fdo.bmo.md and uses the generic chunking strategy.
// This is functionally identical to Payload but uses different message names
// (image-begin, image-data-<n>, image-end, image-result) to signal that the client
// is firmware seeking a bootable image.
type BMO struct {
	// Option 1: Simple unified handler (framework buffers chunks)
	// Recommended for most applications - chunking is transparent.
	UnifiedHandler UnifiedImageHandler

	// Option 2: Chunked handler (app handles chunks individually)
	// Use for memory-constrained scenarios or streaming processing.
	ChunkedHandler ChunkedImageHandler

	// Optional: Handler for accept/reject decision when RequireAck=true
	// If nil and RequireAck=true, images are automatically accepted.
	AckHandler ImageAckHandler

	// Optional: Handler for BIOS parameter setting
	// If nil, BIOS set messages will be ignored.
	BiosParamHandler BiosParamHandler

	// Active indicates if the module is active
	Active bool

	// Internal state
	receiver     *chunking.ChunkReceiver
	buffer       *bytes.Buffer
	begin        chunking.BeginMessage
	resultStatus int
	resultMsg    string

	// BIOS parameter state
	pendingBiosResponses []BiosResponse
}

// BiosResponse represents a BIOS parameter response to be sent to the owner.
type BiosResponse struct {
	StatusCode int    // 0=success, 1=warning, 2=error
	Message    string // Optional message
}

var _ serviceinfo.DeviceModule = (*BMO)(nil)

// Transition implements serviceinfo.DeviceModule.
func (b *BMO) Transition(active bool) error {
	if !active {
		b.reset()
	}
	return nil
}

// Receive implements serviceinfo.DeviceModule.
func (b *BMO) Receive(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	fmt.Printf("[BMODevice] Receive called: messageName=%s\n", messageName)

	// Handle chunked image messages
	if strings.HasPrefix(messageName, "image-") {
		fmt.Printf("[BMODevice] Handling chunked message: %s\n", messageName)
		return b.handleChunkedMessage(ctx, messageName, messageBody, respond)
	}

	// Handle BIOS parameter messages
	switch messageName {
	case "set":
		fmt.Printf("[BMODevice] Handling BIOS set message\n")
		return b.handleBiosSet(messageBody, respond)
	case "response":
		fmt.Printf("[BMODevice] Handling BIOS response message\n")
		return b.handleBiosResponse(messageBody, respond)
	}

	fmt.Printf("[BMODevice] Ignoring unknown message: %s\n", messageName)
	return nil
}

// Yield implements serviceinfo.DeviceModule.
func (b *BMO) Yield(ctx context.Context, respond func(string) io.Writer, yield func()) error {
	// Send pending BIOS responses
	if len(b.pendingBiosResponses) > 0 {
		for _, response := range b.pendingBiosResponses {
			responseData := []any{response.StatusCode}
			if response.Message != "" {
				responseData = append(responseData, response.Message)
			}

			w := respond("response")
			if err := cbor.NewEncoder(w).Encode(responseData); err != nil {
				return fmt.Errorf("failed to encode BIOS response: %w", err)
			}

			if debugEnabled() {
				slog.Debug("fdo.bmo: sent BIOS response", "status", response.StatusCode, "message", response.Message)
			}
		}

		// Clear pending responses
		b.pendingBiosResponses = nil
	}

	return nil
}

// reset clears the internal state.
func (b *BMO) reset() {
	if b.receiver != nil && b.receiver.IsReceiving() && b.ChunkedHandler != nil {
		_ = b.ChunkedHandler.CancelImage()
	}
	b.receiver = nil
	b.buffer = nil
	b.pendingBiosResponses = nil
}

// handleChunkedMessage processes image-begin, image-data-<n>, and image-end messages.
func (b *BMO) handleChunkedMessage(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer) error {
	if b.UnifiedHandler == nil && b.ChunkedHandler == nil {
		return b.sendError(respond, 4, "No image handler configured", "")
	}

	// Initialize receiver on first chunked message
	if b.receiver == nil {
		b.receiver = &chunking.ChunkReceiver{
			PayloadName: "image",
		}

		// Set up ack callback if handler provided
		if b.AckHandler != nil {
			b.receiver.OnBeginAck = b.onBeginAck
		}

		// Set up callbacks based on handler mode
		if b.UnifiedHandler != nil {
			// Unified mode: buffer everything
			b.buffer = &bytes.Buffer{}
			b.receiver.OnBegin = b.onBeginUnified
			b.receiver.OnChunk = b.onChunkUnified
			b.receiver.OnEnd = b.onEndUnified(ctx)
		} else {
			// Chunked mode: delegate to handler
			b.receiver.OnBegin = b.onBeginChunked
			b.receiver.OnChunk = b.onChunkChunked
			b.receiver.OnEnd = b.onEndChunked
		}
	}

	// Handle the message using the chunking receiver
	if err := b.receiver.HandleMessage(messageName, messageBody); err != nil {
		if sendErr := b.sendError(respond, 6, "Transfer error", err.Error()); sendErr != nil {
			return sendErr
		}
		b.receiver = nil
		if b.ChunkedHandler != nil {
			_ = b.ChunkedHandler.CancelImage()
		}
		return nil
	}

	// After begin message with RequireAck, send image-ack
	if strings.HasSuffix(messageName, "-begin") && b.receiver.IsAckPending() {
		fmt.Printf("[BMODevice] Sending image-ack (accepted=%v)\n", b.receiver.IsAckAccepted())
		if err := b.receiver.SendAck(respond); err != nil {
			return fmt.Errorf("failed to send ack: %w", err)
		}
		if !b.receiver.IsAckAccepted() {
			b.receiver = nil
			return nil
		}
	}

	// After successful end message, send result per fdo.bmo.md
	if strings.HasSuffix(messageName, "-end") && !b.receiver.IsReceiving() {
		fmt.Printf("[BMODevice] Received end message, sending result\n")
		result := chunking.ResultMessage{
			StatusCode: b.resultStatus,
			Message:    b.resultMsg,
		}
		resultData, err := result.MarshalCBOR()
		if err != nil {
			fmt.Printf("[BMODevice] ERROR: failed to encode result: %v\n", err)
			return fmt.Errorf("failed to encode result: %w", err)
		}

		w := respond("image-result")
		if _, err := w.Write(resultData); err != nil {
			fmt.Printf("[BMODevice] ERROR: failed to send result: %v\n", err)
			return fmt.Errorf("failed to send result: %w", err)
		}
		fmt.Printf("[BMODevice] Sent result successfully\n")

		b.receiver = nil
	}

	return nil
}

// onBeginAck is called when image-begin with RequireAck=true is received.
func (b *BMO) onBeginAck(begin chunking.BeginMessage) (accepted bool, reasonCode int, message string) {
	if b.AckHandler == nil {
		return true, 0, ""
	}

	imageType, _ := begin.FSIMFields[-1].(string)
	name, _ := begin.FSIMFields[-2].(string)

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

	return b.AckHandler.AcceptImage(imageType, name, begin.TotalSize, metadata)
}

// Unified mode callbacks

func (b *BMO) onBeginUnified(begin chunking.BeginMessage) error {
	b.begin = begin
	return nil
}

func (b *BMO) onChunkUnified(data []byte) error {
	b.buffer.Write(data)
	return nil
}

func (b *BMO) onEndUnified(ctx context.Context) func(chunking.EndMessage) error {
	return func(end chunking.EndMessage) error {
		imageType, ok := b.begin.FSIMFields[-1].(string)
		if !ok || imageType == "" {
			return fmt.Errorf("missing required image_type field (-1)")
		}

		name, _ := b.begin.FSIMFields[-2].(string)

		var metadata map[string]any
		if m, ok := b.begin.FSIMFields[-3].(map[string]any); ok {
			metadata = m
		} else if m, ok := b.begin.FSIMFields[-3].(map[any]any); ok {
			metadata = make(map[string]any)
			for k, v := range m {
				if ks, ok := k.(string); ok {
					metadata[ks] = v
				}
			}
		}

		slog.Debug("fdo.bmo unified",
			"image_type", imageType,
			"name", name,
			"size", b.begin.TotalSize,
			"received", b.buffer.Len())

		statusCode, message, err := b.UnifiedHandler.HandleImage(ctx, imageType, name, b.begin.TotalSize, metadata, b.buffer.Bytes())
		if err != nil {
			return err
		}

		b.resultStatus = statusCode
		b.resultMsg = message

		slog.Debug("fdo.bmo unified end", "status", statusCode, "message", message)
		return nil
	}
}

// Chunked mode callbacks

func (b *BMO) onBeginChunked(begin chunking.BeginMessage) error {
	imageType, ok := begin.FSIMFields[-1].(string)
	if !ok || imageType == "" {
		return fmt.Errorf("missing required image_type field (-1)")
	}

	if !b.ChunkedHandler.SupportsImageType(imageType) {
		return fmt.Errorf("image type '%s' not supported", imageType)
	}

	name, _ := begin.FSIMFields[-2].(string)

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

	slog.Debug("fdo.bmo chunked begin",
		"image_type", imageType,
		"name", name,
		"size", begin.TotalSize)

	return b.ChunkedHandler.BeginImage(imageType, name, begin.TotalSize, metadata)
}

func (b *BMO) onChunkChunked(data []byte) error {
	return b.ChunkedHandler.ReceiveChunk(data)
}

func (b *BMO) onEndChunked(end chunking.EndMessage) error {
	statusCode, message, err := b.ChunkedHandler.EndImage()
	if err != nil {
		return err
	}

	b.resultStatus = statusCode
	b.resultMsg = message

	slog.Debug("fdo.bmo chunked end", "status", statusCode, "message", message)
	return nil
}

// sendError sends an error message to the owner per fdo.bmo.md error format.
func (b *BMO) sendError(respond func(string) io.Writer, code int, message, details string) error {
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

	return nil
}

// handleBiosSet handles BIOS parameter set messages from the owner.
func (b *BMO) handleBiosSet(messageBody io.Reader, respond func(string) io.Writer) error {
	// If no BIOS handler is configured, ignore the message
	if b.BiosParamHandler == nil {
		if debugEnabled() {
			slog.Debug("fdo.bmo: no BiosParamHandler configured, ignoring set message")
		}
		return nil
	}

	// Decode the set message (array of [name, value] pairs)
	var params [][]any
	if err := cbor.NewDecoder(messageBody).Decode(&params); err != nil {
		return fmt.Errorf("error decoding BIOS set message: %w", err)
	}

	if debugEnabled() {
		slog.Debug("fdo.bmo: received BIOS parameters", "count", len(params))
	}

	// Process each parameter and collect responses
	var responses []BiosResponse

	for _, param := range params {
		if len(param) != 2 {
			response := BiosResponse{
				StatusCode: 2, // Error
				Message:    "Invalid parameter format, expected [name, value]",
			}
			responses = append(responses, response)
			continue
		}

		name, nameOk := param[0].(string)
		value, valueOk := param[1].(string)
		if !nameOk || !valueOk {
			response := BiosResponse{
				StatusCode: 2, // Error
				Message:    "Invalid parameter types, expected string name and value",
			}
			responses = append(responses, response)
			continue
		}

		// Call the BIOS parameter handler
		statusCode, message, err := b.BiosParamHandler.SetBiosParameter(name, value)
		if err != nil {
			// Internal error - don't send to owner, just log
			slog.Error("fdo.bmo: internal error setting BIOS parameter", "parameter", name, "error", err)
			response := BiosResponse{
				StatusCode: 2, // Error
				Message:    "Internal error processing parameter",
			}
			responses = append(responses, response)
			continue
		}

		response := BiosResponse{
			StatusCode: statusCode,
			Message:    message,
		}
		responses = append(responses, response)

		if debugEnabled() {
			slog.Debug("fdo.bmo: processed BIOS parameter", "parameter", name, "value", value, "status", statusCode, "message", message)
		}
	}

	// Store responses for Yield() to send
	b.pendingBiosResponses = responses

	// If there was an error and atomic behavior is expected, we could rollback here
	// For now, we send individual responses as per the protocol

	return nil
}

// handleBiosResponse handles BIOS parameter response messages (for owner side).
func (b *BMO) handleBiosResponse(messageBody io.Reader, respond func(string) io.Writer) error {
	// This is typically handled on the owner side, but we include it for completeness
	// On the device side, this would be used for acknowledging responses
	if debugEnabled() {
		slog.Debug("fdo.bmo: received BIOS response (device side)")
	}
	return nil
}
