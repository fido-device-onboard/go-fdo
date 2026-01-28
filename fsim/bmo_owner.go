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

// BMOOwner implements the fdo.bmo FSIM for owner-side boot image delivery.
// It follows the specification in fdo.bmo.md and uses the generic chunking strategy.
// This is functionally identical to PayloadOwner but uses different message names
// (image-begin, image-data-<n>, image-end, image-result) to signal that the client
// is firmware seeking a bootable image rather than an OS seeking configuration payloads.
type BMOOwner struct {
	// Images to send to the device
	images []ImageToSend

	// Internal state
	currentSender *chunking.ChunkSender
	currentIndex  int
	sendState     bmoSendState
	sentActive    bool
	lastResult    *ImageResult
	lastError     *ImageErrorInfo
}

type bmoSendState int

const (
	bmoStateIdle bmoSendState = iota
	bmoStateSendingBegin
	bmoStateWaitingAck
	bmoStateSendingChunks
	bmoStateSendingEnd
	bmoStateWaitingResult
)

// ImageToSend represents a boot image to be sent to the device per fdo.bmo.md.
type ImageToSend struct {
	ImageType  string         // Required: Image type/MIME type (field -1)
	Name       string         // Optional: Image name (field -2)
	Data       []byte         // Image data
	Metadata   map[string]any // Optional: Metadata map (field -3)
	HashAlg    string         // Optional: Hash algorithm (e.g., "sha256")
	RequireAck bool           // Optional: Request ack before sending data (default: false)
}

// ImageResult represents the result received from the device.
type ImageResult struct {
	StatusCode int    // 0=success, 1=warning, 2=error
	Message    string // Optional message
}

// ImageErrorInfo contains error information from the device per fdo.bmo.md.
type ImageErrorInfo struct {
	Code    int    // Error code (see fdo.bmo.md)
	Message string // Human-readable error message
	Details string // Optional additional details
}

var _ serviceinfo.OwnerModule = (*BMOOwner)(nil)

// HandleInfo implements serviceinfo.OwnerModule.
func (b *BMOOwner) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
	return b.receive(ctx, messageName, messageBody, nil)
}

// ProduceInfo implements serviceinfo.OwnerModule.
func (b *BMOOwner) ProduceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	return b.produceInfo(ctx, producer)
}

// AddImage adds a boot image to be sent to the device.
func (b *BMOOwner) AddImage(imageType, name string, data []byte, metadata map[string]any) {
	b.images = append(b.images, ImageToSend{
		ImageType: imageType,
		Name:      name,
		Data:      data,
		Metadata:  metadata,
		HashAlg:   "sha256", // Default hash algorithm
	})
}

// AddImageWithAck adds a boot image that requires acknowledgment before data transfer.
// This allows the device to reject the image based on type before receiving data.
func (b *BMOOwner) AddImageWithAck(imageType, name string, data []byte, metadata map[string]any) {
	b.images = append(b.images, ImageToSend{
		ImageType:  imageType,
		Name:       name,
		Data:       data,
		Metadata:   metadata,
		HashAlg:    "sha256",
		RequireAck: true,
	})
}

// Transition implements serviceinfo.OwnerModule.
func (b *BMOOwner) Transition(active bool) error {
	if !active {
		b.reset()
	}
	return nil
}

// reset clears the internal state.
func (b *BMOOwner) reset() {
	b.currentSender = nil
	b.currentIndex = 0
	b.sendState = bmoStateIdle
	b.lastResult = nil
	b.lastError = nil
}

// produceInfo generates messages to send to the device using the chunking library.
func (b *BMOOwner) produceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	// Send active message first if we have images to send
	if !b.sentActive && len(b.images) > 0 {
		if err := producer.WriteChunk("active", []byte{0xf5}); err != nil { // 0xf5 is CBOR true
			return false, false, fmt.Errorf("error sending active message: %w", err)
		}
		b.sentActive = true
		return false, false, nil
	}

	// Check if we're done with all images
	if b.currentIndex >= len(b.images) && b.sendState == bmoStateIdle {
		return false, true, nil
	}

	// Initialize sender for next image if needed
	if b.currentSender == nil && b.currentIndex < len(b.images) {
		image := &b.images[b.currentIndex]
		b.currentSender = chunking.NewChunkSender("image", image.Data)

		// Set hash algorithm if provided
		if image.HashAlg != "" {
			b.currentSender.BeginFields.HashAlg = image.HashAlg
		}

		// Set FSIM-specific fields per fdo.bmo.md
		b.currentSender.BeginFields.FSIMFields[-1] = image.ImageType // Required
		if image.Name != "" {
			b.currentSender.BeginFields.FSIMFields[-2] = image.Name
		}
		if image.Metadata != nil {
			b.currentSender.BeginFields.FSIMFields[-3] = image.Metadata
		}

		// Set RequireAck if requested
		if image.RequireAck {
			b.currentSender.BeginFields.RequireAck = true
		}

		b.sendState = bmoStateSendingBegin
	}

	// State machine for sending
	switch b.sendState {
	case bmoStateSendingBegin:
		fmt.Printf("[BMOOwner] Sending image-begin message\n")
		if err := b.currentSender.SendBegin(producer); err != nil {
			return false, false, fmt.Errorf("failed to send begin: %w", err)
		}
		slog.Debug("fdo.bmo sent begin",
			"image_type", b.currentSender.BeginFields.FSIMFields[-1],
			"size", len(b.currentSender.Data),
			"require_ack", b.currentSender.BeginFields.RequireAck)

		// If RequireAck, wait for image-ack before sending chunks
		if b.currentSender.IsWaitingForAck() {
			fmt.Printf("[BMOOwner] RequireAck set, waiting for image-ack\n")
			b.sendState = bmoStateWaitingAck
			return false, false, nil
		}

		b.sendState = bmoStateSendingChunks
		fmt.Printf("[BMOOwner] Sent begin, continuing to send chunks\n")
		fallthrough

	case bmoStateWaitingAck:
		if b.currentSender.IsWaitingForAck() {
			return false, false, nil
		}
		if b.currentSender.IsRejected() {
			reason, msg := b.currentSender.GetRejectReason()
			slog.Warn("fdo.bmo rejected by device",
				"image_type", b.currentSender.BeginFields.FSIMFields[-1],
				"reason_code", reason,
				"message", msg)
			b.currentSender = nil
			b.currentIndex++
			b.sendState = bmoStateIdle
			return false, false, nil
		}
		fmt.Printf("[BMOOwner] image-ack received, proceeding to send chunks\n")
		b.sendState = bmoStateSendingChunks
		fallthrough

	case bmoStateSendingChunks:
		chunkIndex := b.currentSender.GetBytesSent() / int64(b.currentSender.ChunkSize)
		chunkKey := fmt.Sprintf("image-data-%d", chunkIndex)

		estimatedSize := b.currentSender.ChunkSize + 50
		if producer.Available(chunkKey) < estimatedSize {
			fmt.Printf("[BMOOwner] Not enough MTU space for next chunk, blocking\n")
			return true, false, nil
		}

		fmt.Printf("[BMOOwner] Sending chunk %d, totalSize=%d\n", chunkIndex, len(b.currentSender.Data))
		done, err := b.currentSender.SendNextChunk(producer)
		if err != nil {
			return false, false, fmt.Errorf("failed to send chunk: %w", err)
		}
		if done {
			fmt.Printf("[BMOOwner] All chunks sent, transitioning to send end\n")
			b.sendState = bmoStateSendingEnd
			return true, false, nil
		}
		fmt.Printf("[BMOOwner] Chunk sent, will continue in next round\n")
		return true, false, nil

	case bmoStateSendingEnd:
		fmt.Printf("[BMOOwner] Sending image-end message\n")
		if err := b.currentSender.SendEnd(producer); err != nil {
			return false, false, fmt.Errorf("failed to send end: %w", err)
		}
		slog.Debug("fdo.bmo sent end")
		fmt.Printf("[BMOOwner] Sent end, waiting for result\n")
		b.sendState = bmoStateWaitingResult
		return false, false, nil

	case bmoStateWaitingResult:
		return false, false, nil
	}

	return false, false, nil
}

// receive processes incoming messages from the device.
func (b *BMOOwner) receive(ctx context.Context, key string, messageBody io.Reader, respond func(string) io.Writer) error {
	slog.Debug("fdo.bmo owner received message", "key", key)

	switch key {
	case "active":
		var deviceActive bool
		if err := cbor.NewDecoder(messageBody).Decode(&deviceActive); err != nil {
			return fmt.Errorf("error decoding active message: %w", err)
		}
		if !deviceActive {
			return fmt.Errorf("device bmo module is not active")
		}
		slog.Debug("fdo.bmo device active status received")
		return nil

	case "image-ack":
		if b.currentSender == nil {
			return fmt.Errorf("received ack without active transfer")
		}
		if !b.currentSender.IsWaitingForAck() {
			return fmt.Errorf("received unexpected ack")
		}

		if err := b.currentSender.HandleAck(messageBody); err != nil {
			slog.Debug("fdo.bmo ack received", "error", err)
		}
		return nil

	case "image-result":
		if b.currentSender == nil {
			return fmt.Errorf("received result without active transfer")
		}

		result, err := b.currentSender.HandleResult(messageBody)
		if err != nil {
			return fmt.Errorf("failed to decode result: %w", err)
		}

		b.lastResult = &ImageResult{
			StatusCode: result.StatusCode,
			Message:    result.Message,
		}

		if result.StatusCode == 0 {
			slog.Info("fdo.bmo image delivered successfully",
				"image_type", b.currentSender.BeginFields.FSIMFields[-1],
				"message", result.Message)
		} else {
			slog.Warn("fdo.bmo image delivery failed",
				"image_type", b.currentSender.BeginFields.FSIMFields[-1],
				"status", result.StatusCode,
				"message", result.Message)
		}

		b.currentSender = nil
		b.currentIndex++
		b.sendState = bmoStateIdle

	case "error":
		var errorMap map[any]any
		data, err := io.ReadAll(messageBody)
		if err != nil {
			return fmt.Errorf("failed to read error: %w", err)
		}
		if err := cbor.Unmarshal(data, &errorMap); err != nil {
			return fmt.Errorf("failed to decode error: %w", err)
		}

		code, _ := errorMap[0].(int)
		message, _ := errorMap[1].(string)
		details, _ := errorMap[2].(string)

		b.lastError = &ImageErrorInfo{
			Code:    code,
			Message: message,
			Details: details,
		}

		slog.Error("fdo.bmo device error",
			"code", code,
			"message", message,
			"details", details)

		b.currentSender = nil
		b.sendState = bmoStateIdle

		return fmt.Errorf("bmo error %d: %s", code, message)

	default:
		if debugEnabled() {
			slog.Debug("fdo.bmo: ignoring unknown message", "messageName", key)
		}
		return nil
	}

	return nil
}

// GetLastError returns the last error reported by the device.
func (b *BMOOwner) GetLastError() *ImageErrorInfo {
	return b.lastError
}

// GetLastResult returns the last result reported by the device.
func (b *BMOOwner) GetLastResult() *ImageResult {
	return b.lastResult
}

// SetChunkSize sets the chunk size for data transfer (default 1014 bytes per spec).
func (b *BMOOwner) SetChunkSize(size int) {
	if b.currentSender != nil {
		b.currentSender.ChunkSize = size
	}
}
