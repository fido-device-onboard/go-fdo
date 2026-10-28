// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bytes"
	"context"
	"crypto"
	"crypto/subtle"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"strings"

	fdo "github.com/fido-device-onboard/go-fdo"
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

// AtomicBiosParamHandler applies all parameters of one fdo.bmo:set message
// atomically: either every parameter is applied, or none is (fdo.bmo.md
// "Atomicity"). A BiosParamHandler that also implements this interface is
// used for multi-parameter sets; one that does not can only accept a set
// with a single parameter.
type AtomicBiosParamHandler interface {
	// SetBiosParameters applies params all-or-nothing and returns one
	// result for the whole set: statusCode 0=success (all applied),
	// 1=warning (all applied), 2=error (none applied).
	SetBiosParameters(params []BiosParam) (statusCode int, message string, err error)
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

	// URL delivery mode support (fdo.bmo.md extension)
	// URLFetcher is used to fetch images from URLs (Mode 1 and 2).
	// If nil, URL delivery modes will be rejected with error code 14.
	URLFetcher URLFetcher

	// SupportedDeliveryModes specifies which delivery modes the device supports.
	// If nil or empty, all modes are supported (assuming URLFetcher is set for modes 1/2).
	// Use this to explicitly restrict supported modes for NAK testing.
	SupportedDeliveryModes []uint

	// URLTimeout is the timeout for URL fetches in seconds. Default: 30.
	URLTimeout int

	// OwnerPublicKey is the TO2-proven Owner public key used as the trust
	// anchor for authenticated BMO provisioning messages (image-begin-signed,
	// set-signed). When non-nil, the device verifies every signed BMO
	// provisioning message per fdo.bmo.md "Authenticated Provisioning":
	// the Owner key verifies directly, or (when x5chain is present) chains
	// to a delegate cert carrying OIDPermitProvision.
	//
	// When nil, signed BMO messages (image-begin-signed / set-signed) are
	// rejected with error BMOErrorProvisionNotAuthorized (15).
	OwnerPublicKey crypto.PublicKey

	// Active indicates if the module is active
	Active bool

	// Internal state
	receiver     *chunking.ChunkReceiver
	buffer       *bytes.Buffer
	begin        chunking.BeginMessage
	resultStatus int
	resultMsg    string
	beginHasher  hash.Hash // chunked mode: running hash for begin expected_hash

	// BIOS parameter state: the single response to the last set message
	pendingBiosResponse *BiosResponse
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

	switch messageName {
	case "image-begin":
		// Per fdo.bmo.md §"Authorization of Provisioning Messages", image-begin
		// MUST be a tagged COSE_Sign1. Unwrap-and-verify, then fall through to
		// the ordinary chunked handler with the inner payload. A raw CBOR map
		// is accepted only in non-conforming legacy mode (OwnerPublicKey unset
		// AND no owner key in ctx), for back-compat with test scaffolding.
		inner, signed, err := b.unwrapProvisioning(ctx, messageBody, BMOContentTypeImageBegin)
		if err != nil {
			slog.Error("fdo.bmo: image-begin rejected", "error", err)
			return b.sendError(respond, chunking.ErrorCode(err, BMOErrorProvisionNotAuthorized), "Provisioning not authorized", err.Error())
		}
		if err := checkSignedBeginBindsContent(inner, signed); err != nil {
			slog.Error("fdo.bmo: image-begin rejected", "error", err)
			return b.sendError(respond, BMOErrorProvisionNotAuthorized, "Provisioning not authorized", err.Error())
		}
		return b.handleChunkedMessage(ctx, "image-begin", bytes.NewReader(inner), respond)

	case "set":
		inner, _, err := b.unwrapProvisioning(ctx, messageBody, BMOContentTypeSet)
		if err != nil {
			slog.Error("fdo.bmo: set rejected", "error", err)
			return b.sendError(respond, chunking.ErrorCode(err, BMOErrorProvisionNotAuthorized), "Provisioning not authorized", err.Error())
		}
		return b.handleBiosSet(bytes.NewReader(inner), respond)

	case "response":
		fmt.Printf("[BMODevice] Handling BIOS response message\n")
		return b.handleBiosResponse(messageBody, respond)
	}

	// Other image-* messages (image-ack, image-data-<n>, image-end) are
	// unsigned per spec; pass them straight to the chunked handler.
	if strings.HasPrefix(messageName, "image-") {
		fmt.Printf("[BMODevice] Handling chunked message: %s\n", messageName)
		return b.handleChunkedMessage(ctx, messageName, messageBody, respond)
	}

	fmt.Printf("[BMODevice] Ignoring unknown message: %s\n", messageName)
	return nil
}

// unwrapProvisioning reads the body of a provisioning message (image-begin or
// set) and returns the inner payload bytes.
//
// If the body is a tagged COSE_Sign1 (CBOR tag 18), it is verified per
// fdo.bmo.md §"Authorization of Provisioning Messages": trust anchor is the
// TO2-proven Owner public key (from BMO.OwnerPublicKey or ctx via
// fdo.OwnerPublicKeyFromContext), an optional x5chain carries a delegate
// certificate whose leaf MUST bear OIDPermitProvision, and the signature is
// verified with external AAD FdoBmoProvisionAAD.
//
// If the body is a raw CBOR map/array (no tag 18), it relies on channel
// authority: it is accepted only if the TO2 peer holds provisioning
// authority (Owner-direct, or a Delegate with PERM.7), per
// unsignedProvisioningAllowed. Otherwise it is rejected with error 15.
//
// The second return is true if the message was verified as a COSE_Sign1,
// false if it was accepted unsigned under channel authority.
func (b *BMO) unwrapProvisioning(ctx context.Context, messageBody io.Reader, expectedContentType string) (inner []byte, signed bool, err error) {
	raw, err := io.ReadAll(messageBody)
	if err != nil {
		return nil, false, fmt.Errorf("read provisioning message: %w", err)
	}

	ownerKey := b.OwnerPublicKey
	if ownerKey == nil {
		ownerKey = fdo.OwnerPublicKeyFromContext(ctx)
	}

	return authorizeGated(ctx, raw, ownerKey, expectedContentType, fdoBmoProvisionAAD(), nil)
}

// Yield implements serviceinfo.DeviceModule.
func (b *BMO) Yield(ctx context.Context, respond func(string) io.Writer, yield func()) error {
	// Send the response to the last set message (exactly one per set)
	if response := b.pendingBiosResponse; response != nil {
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
		b.pendingBiosResponse = nil
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
	b.pendingBiosResponse = nil
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
		// Extract error code from bmoURLError if available, otherwise use generic transfer error
		errorCode := chunking.ErrorCode(err, BMOErrorTransferError)
		if sendErr := b.sendError(respond, errorCode, "Transfer error", err.Error()); sendErr != nil {
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
	imageType, _ := begin.FSIMFields[-1].(string)
	name, _ := begin.FSIMFields[-3].(string) // Note: -3 is name per spec, -2 is boot_args

	// Check delivery mode support
	deliveryMode := begin.DeliveryMode
	if !b.supportsDeliveryMode(deliveryMode) || deliveryMode > DeliveryModeMetaURL {
		return false, BMOErrorDeliveryModeNotSupported, fmt.Sprintf("delivery mode %d not supported", deliveryMode)
	}

	// For URL modes, check if URLFetcher is configured
	if (deliveryMode == DeliveryModeURL || deliveryMode == DeliveryModeMetaURL) && b.URLFetcher == nil {
		return false, BMOErrorDeliveryModeNotSupported, "URL delivery not supported (no URLFetcher configured)"
	}

	// Delegate to application's AckHandler if provided
	if b.AckHandler != nil {
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

	return true, 0, ""
}

// supportsDeliveryMode checks if the device supports the given delivery mode.
func (b *BMO) supportsDeliveryMode(mode uint) bool {
	// If no explicit list, support all modes
	if len(b.SupportedDeliveryModes) == 0 {
		return true
	}
	for _, supported := range b.SupportedDeliveryModes {
		if supported == mode {
			return true
		}
	}
	return false
}

// Unified mode callbacks

func (b *BMO) onBeginUnified(begin chunking.BeginMessage) error {
	if begin.EstimatedDuration > 0 {
		slog.Info("fdo.bmo: server estimates transfer+apply time",
			"estimated_duration_sec", begin.EstimatedDuration,
			"total_size", begin.TotalSize)
	}
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

		name, _ := b.begin.FSIMFields[-3].(string)
		bootArgs, _ := b.begin.FSIMFields[-2].(string)

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

		var imageData []byte

		switch b.begin.DeliveryMode {
		case DeliveryModeInline:
			// Mode 0: buffered inline data. A hash in image-begin binds the
			// bytes to the authorisation (image-end's hash is checked by the
			// chunk receiver).
			imageData = b.buffer.Bytes()
			if len(b.begin.ExpectedHash) > 0 {
				if err := b.verifyHash(imageData, b.begin.ExpectedHash, b.begin.HashAlg); err != nil {
					b.resultStatus = 2
					b.resultMsg = fmt.Sprintf("Hash verification failed: %v", err)
					return &chunking.TransferError{Code: BMOErrorHashMismatch, Msg: b.resultMsg}
				}
			}
			slog.Debug("fdo.bmo unified inline",
				"image_type", imageType,
				"name", name,
				"size", b.begin.TotalSize,
				"received", len(imageData))

		case DeliveryModeURL, DeliveryModeMetaURL:
			// Modes 1/2: fetch by reference. Every fetched object must be
			// authenticated (chunking-strategy.md "Authenticating Fetched
			// Content"); chunking.Resolve enforces that.
			ownerKey := b.OwnerPublicKey
			if ownerKey == nil {
				ownerKey = fdo.OwnerPublicKeyFromContext(ctx)
			}
			res, err := chunking.Resolve(b.URLFetcher, b.begin, ownerKey)
			if err != nil {
				b.resultStatus = 2
				b.resultMsg = err.Error()
				slog.Error("fdo.bmo delivery failed", "mode", b.begin.DeliveryMode, "url", b.begin.URL, "error", err)
				return err
			}
			imageData = res.Content
			if res.Meta != nil {
				// The meta-payload names the actual image. Resolve has already
				// rejected an unauthenticated meta-payload carrying instruction
				// fields, so boot_args here is authenticated.
				imageType = res.Meta.MIMEType
				if res.Meta.Name != "" {
					name = res.Meta.Name
				}
				if res.Meta.BootArgs != "" {
					bootArgs = res.Meta.BootArgs
				}
			}

		default:
			return &chunking.TransferError{Code: BMOErrorDeliveryModeNotSupported,
				Msg: fmt.Sprintf("unsupported delivery mode: %d", b.begin.DeliveryMode)}
		}

		// Add boot args to metadata if present
		if bootArgs != "" && metadata == nil {
			metadata = make(map[string]any)
		}
		if bootArgs != "" {
			metadata["boot_args"] = bootArgs
		}

		statusCode, message, err := b.UnifiedHandler.HandleImage(ctx, imageType, name, uint64(len(imageData)), metadata, imageData)
		if err != nil {
			return err
		}

		b.resultStatus = statusCode
		b.resultMsg = message

		slog.Debug("fdo.bmo unified end", "status", statusCode, "message", message)
		return nil
	}
}

// verifyHash verifies that the data matches the expected hash.
func (b *BMO) verifyHash(data, expectedHash []byte, hashAlg string) error {
	alg := strings.ToLower(hashAlg)
	if alg == "" {
		alg = "sha256"
	}
	return chunking.VerifyHash(alg, data, expectedHash)
}

// Chunked mode callbacks

func (b *BMO) onBeginChunked(begin chunking.BeginMessage) error {
	// Streaming mode handles inline transfers only.
	if begin.DeliveryMode != DeliveryModeInline {
		return &chunking.TransferError{Code: BMOErrorDeliveryModeNotSupported,
			Msg: fmt.Sprintf("delivery mode %d not supported with a chunked image handler", begin.DeliveryMode)}
	}
	b.beginHasher = nil
	if len(begin.ExpectedHash) > 0 {
		h, err := newBeginHasher(begin.HashAlg)
		if err != nil {
			return err
		}
		b.beginHasher = h
		b.begin = begin
	}

	imageType, ok := begin.FSIMFields[-1].(string)
	if !ok || imageType == "" {
		return fmt.Errorf("missing required image_type field (-1)")
	}

	if !b.ChunkedHandler.SupportsImageType(imageType) {
		return fmt.Errorf("image type '%s' not supported", imageType)
	}

	name, _ := begin.FSIMFields[-3].(string) // -3 is name per spec, -2 is boot_args

	// Metadata is already map[string]any from chunking.BeginMessage
	metadata := begin.Metadata

	slog.Debug("fdo.bmo chunked begin",
		"image_type", imageType,
		"name", name,
		"size", begin.TotalSize)

	if begin.EstimatedDuration > 0 {
		slog.Info("fdo.bmo: server estimates transfer+apply time",
			"estimated_duration_sec", begin.EstimatedDuration,
			"image_type", imageType,
			"total_size", begin.TotalSize)
	}

	return b.ChunkedHandler.BeginImage(imageType, name, begin.TotalSize, metadata)
}

func (b *BMO) onChunkChunked(data []byte) error {
	if b.beginHasher != nil {
		b.beginHasher.Write(data)
	}
	return b.ChunkedHandler.ReceiveChunk(data)
}

func (b *BMO) onEndChunked(end chunking.EndMessage) error {
	// The handler has already seen the bytes; a mismatch cancels the image
	// before it is finalized and applied.
	if b.beginHasher != nil {
		sum := b.beginHasher.Sum(nil)
		b.beginHasher = nil
		if subtle.ConstantTimeCompare(sum, b.begin.ExpectedHash) != 1 {
			_ = b.ChunkedHandler.CancelImage()
			return &chunking.TransferError{Code: BMOErrorHashMismatch, Msg: "image does not match expected_hash (key 8)"}
		}
	}
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

// handleBiosSet handles a BIOS parameter set message from the owner.
//
// A set is atomic (fdo.bmo.md "Atomicity"): every parameter is applied or
// none is, and exactly one response describes the outcome. A device that
// cannot apply the set atomically rejects all of it.
func (b *BMO) handleBiosSet(messageBody io.Reader, respond func(string) io.Writer) error {
	b.pendingBiosResponse = b.applyBiosSet(messageBody)
	return nil
}

func (b *BMO) applyBiosSet(messageBody io.Reader) *BiosResponse {
	reject := func(msg string) *BiosResponse {
		return &BiosResponse{StatusCode: 2, Message: msg}
	}

	// Decode the set message (array of [name, value] pairs). Validate every
	// parameter before applying any.
	var raw [][]any
	if err := cbor.NewDecoder(messageBody).Decode(&raw); err != nil {
		return reject("Invalid set message; no parameters applied")
	}
	if len(raw) == 0 {
		return reject("Empty set message")
	}
	params := make([]BiosParam, 0, len(raw))
	for _, param := range raw {
		if len(param) != 2 {
			return reject("Invalid parameter format, expected [name, value]; no parameters applied")
		}
		name, nameOk := param[0].(string)
		value, valueOk := param[1].(string)
		if !nameOk || !valueOk {
			return reject("Invalid parameter types, expected string name and value; no parameters applied")
		}
		params = append(params, BiosParam{Name: name, Value: value})
	}

	if b.BiosParamHandler == nil {
		return reject("BIOS configuration not supported")
	}

	var statusCode int
	var message string
	var err error
	if atomic, ok := b.BiosParamHandler.(AtomicBiosParamHandler); ok {
		statusCode, message, err = atomic.SetBiosParameters(params)
	} else if len(params) == 1 {
		statusCode, message, err = b.BiosParamHandler.SetBiosParameter(params[0].Name, params[0].Value)
	} else {
		return reject("Multi-parameter set requires atomic application, which this device does not support; no parameters applied")
	}
	if err != nil {
		// Internal error - don't send details to owner, just log
		slog.Error("fdo.bmo: internal error applying BIOS parameters", "count", len(params), "error", err)
		return reject("Internal error processing parameters")
	}
	if debugEnabled() {
		slog.Debug("fdo.bmo: applied BIOS set", "count", len(params), "status", statusCode, "message", message)
	}
	return &BiosResponse{StatusCode: statusCode, Message: message}
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
