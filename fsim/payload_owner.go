// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
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

	// Signer, if set, wraps every payload-begin in a COSE_Sign1 (artifact
	// authority) with content type PayloadContentTypeBegin and external AAD
	// cose.AADPayloadProvision. It must be the Owner key or a Delegate whose
	// chain grants fdo-ekt-permit-provision. Required when this service's
	// TO2 identity is an onboard-only Delegate; optional (channel authority)
	// when it holds the Owner key or a PERM.7 Delegate certificate.
	Signer ArtifactSigner

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

	// Standalone diagnostic transfers (chunking-strategy.md "Standalone
	// Diagnostic Transfers"): whether the log in progress is standalone, the
	// payload-log-result still to be sent, and whether the device declined
	// to activate the module.
	logStandalone  bool
	logResult      *chunking.ResultMessage
	deviceInactive bool
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

	// Delivery by reference (chunking-strategy.md "Delivery Modes"). When
	// DeliveryMode is URL or meta-URL, Data is not sent.
	DeliveryMode uint   // generic key 5: 0=inline (default), 1=url, 2=meta-url
	URL          string // generic key 6
	TLSCA        []byte // generic key 7
	ExpectedHash []byte // generic key 8; computed automatically for inline Data
	MetaSigner   []byte // generic key 9: COSE_Key of a third-party meta-payload publisher
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

	// Standalone is true for a log the device sent on its own initiative,
	// not tied to a payload in this session (fdo.payload.md "Standalone
	// Diagnostics"). The fields below are only meaningful when it is set.
	Standalone bool
	// Phase is the device's label for the step the log describes.
	Phase string
	// Outcome is the payload-log-end status (0 = success, 1 = warning,
	// 2 = error), or nil if the device did not state one.
	Outcome *int
	// OutcomeMessage is the one-line summary from payload-log-end.
	OutcomeMessage string
	// PayloadName and PayloadVersion identify a payload delivered in an
	// earlier session that this log reports on.
	PayloadName    string
	PayloadVersion string
}

// PayloadLogHandler receives diagnostic logs uploaded by the device, either
// after a payload has been applied (nested) or on the device's own
// initiative (standalone).
//
// Logs are supplementary. Declining one, or failing to store it, never
// changes the outcome reported in payload-result.
type PayloadLogHandler interface {
	// AcceptLog decides whether to receive a log the device has offered.
	// Returning false sends payload-log-ack [false, reasonCode, message]. A
	// reasonCode of 0 is replaced with AckReasonDiagnosticsNotRequested.
	// For a standalone log, mimeType is empty and name is the payload_name
	// the device supplied, if any.
	AcceptLog(mimeType, name string, size uint64, contentType string) (accepted bool, reasonCode int, message string)

	// HandleLog is called with the fully assembled log. An error is logged
	// but does not fail the session; for a standalone log it is reported to
	// the device as payload-log-result [2, ...] (received, not retained).
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

// AddPayloadURL adds a payload the device fetches from url (delivery mode 1).
// expectedHash SHOULD be provided; without it the device accepts the content
// only over TLS it can validate.
func (p *PayloadOwner) AddPayloadURL(mimeType, name, url string, expectedHash, tlsCA []byte) {
	p.payloads = append(p.payloads, PayloadToSend{
		MimeType: mimeType, Name: name, HashAlg: "sha256", RequireAck: true,
		DeliveryMode: DeliveryModeURL, URL: url, ExpectedHash: expectedHash, TLSCA: tlsCA,
	})
}

// AddPayloadMetaURL adds a payload delivered via a meta-payload at metaURL
// (delivery mode 2). metaSigner names a third-party publisher's COSE_Key; if
// nil, the meta-payload must be signed by the Owner or a PERM.7 Delegate, or
// be used as a pointer with expectedHash pinned.
func (p *PayloadOwner) AddPayloadMetaURL(mimeType, metaURL string, metaSigner, expectedHash, tlsCA []byte) {
	p.payloads = append(p.payloads, PayloadToSend{
		MimeType: mimeType, HashAlg: "sha256", RequireAck: true,
		DeliveryMode: DeliveryModeMetaURL, URL: metaURL, MetaSigner: metaSigner,
		ExpectedHash: expectedHash, TLSCA: tlsCA,
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
	p.logStandalone = false
	p.logResult = nil
	p.deviceInactive = false
}

// produceInfo generates messages to send to the device using the chunking library.
func (p *PayloadOwner) produceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	// Send active message first if we have payloads to send, or if we accept
	// logs: a device may then send standalone diagnostics. Returning here
	// also satisfies "MUST NOT conclude the FSIM before processing the
	// device's response to activation": the next call happens after it.
	if !p.sentActive && (len(p.payloads) > 0 || p.LogHandler != nil) {
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

	// Terminal message of a standalone log. The device may start another
	// standalone log in response, so give it a turn before concluding.
	if p.logResult != nil {
		res := p.logResult
		p.logResult = nil
		data, err := res.MarshalCBOR()
		if err != nil {
			return false, false, fmt.Errorf("failed to encode payload-log-result: %w", err)
		}
		if err := producer.WriteChunk("payload-log-result", data); err != nil {
			return false, false, fmt.Errorf("failed to send payload-log-result: %w", err)
		}
		slog.Debug("fdo.payload sent log result", "status", res.StatusCode)
		return false, false, nil
	}

	if p.deviceInactive {
		return false, true, nil
	}

	// No primary transfer may start while a standalone log is in progress.
	if p.logReceiver != nil && p.logStandalone {
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

			// Delivery fields (generic keys 5-9).
			bf := &p.currentSender.BeginFields
			bf.DeliveryMode = payload.DeliveryMode
			bf.URL = payload.URL
			bf.TLSCA = payload.TLSCA
			bf.MetaSigner = payload.MetaSigner
			bf.ExpectedHash = payload.ExpectedHash
			if payload.DeliveryMode == DeliveryModeInline && len(bf.ExpectedHash) == 0 &&
				len(payload.Data) > 0 && (bf.HashAlg == "" || bf.HashAlg == "sha256") {
				// Bind the bytes to payload-begin (key 8): mandatory under
				// artifact authority (payload-end is unsigned), recommended always.
				h := sha256.Sum256(payload.Data)
				bf.ExpectedHash = h[:]
				bf.HashAlg = "sha256"
			}

			p.sendState = stateSendingBegin
		}

		// State machine for sending - send begin, all chunks, and end in one call
		switch p.sendState {
		case stateSendingBegin:
			fmt.Printf("[PayloadOwner] Sending begin message\n")
			if p.Signer != nil {
				// Artifact authority: wrap the begin map in a COSE_Sign1. The
				// wire key stays "payload-begin".
				beginCBOR, err := p.currentSender.BeginFields.MarshalCBOR()
				if err != nil {
					return false, false, fmt.Errorf("failed to encode payload-begin for signing: %w", err)
				}
				signed, err := p.Signer.SignArtifact(beginCBOR, PayloadContentTypeBegin, cose.AADPayloadProvision)
				if err != nil {
					return false, false, fmt.Errorf("failed to sign payload-begin: %w", err)
				}
				if err := p.currentSender.SendBeginAs(producer, "payload-begin", signed); err != nil {
					return false, false, fmt.Errorf("failed to send signed payload-begin: %w", err)
				}
			} else if err := p.currentSender.SendBegin(producer); err != nil {
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
			// Delivery by reference: no payload-data chunks; payload-end
			// signals "fetch now".
			if p.currentSender.BeginFields.DeliveryMode != DeliveryModeInline {
				p.sendState = stateSendingEnd
				return true, false, nil
			}
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
			// Block to continue sending more chunks in next round.
			//
			// This sends the whole payload as one IsMoreServiceInfo run. It
			// relies on the device loop handing owner info to modules as it
			// arrives (to2.go exchangeServiceInfo, TestClientLongOwnerRunFDO20).
			// A device loop that buffers the whole run (upstream before that
			// fix, including the FDO 2.0 core PR #285) deadlocks after 1000
			// chunks. Do not upstream this FSIM ahead of that fix; see
			// TODO.md "UPSTREAMING ORDER".
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
			if len(p.payloads) == 0 {
				// Activated only to accept standalone logs: nothing lost.
				p.deviceInactive = true
				return nil
			}
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
			// End the transfer now, not in the next ProduceInfo: a
			// standalone log the device offers alongside this rejection
			// must not be answered Busy.
			reason, msg := p.currentSender.GetRejectReason()
			slog.Warn("fdo.payload rejected by device",
				"mime_type", p.currentSender.BeginFields.FSIMFields[-1],
				"reason_code", reason, "message", msg)
			p.currentSender = nil
			p.currentIndex++
			p.sendState = stateIdle
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
		if p.logReceiver != nil && p.logStandalone {
			// One standalone log at a time; the device must wait for
			// payload-log-result before offering the next.
			slog.Warn("fdo.payload: log-begin while a standalone log is in progress; ignoring")
			_, _ = io.Copy(io.Discard, messageBody)
			return nil
		}
		p.logStandalone = false
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
		if p.logStandalone && !isBegin {
			// The device waits for a result; tell it the log was not kept.
			p.logResult = &chunking.ResultMessage{StatusCode: 2, Message: "log discarded: " + err.Error()}
		}
		p.logReceiver = nil
		return nil
	}

	// A begin without require_ack gets no ack to decline with: classify it
	// here and simply drop a log that would have been declined.
	if isBegin && !p.logReceiver.IsAckPending() {
		standalone, accepted, reason, _ := p.classifyLog(p.logReceiver.GetBeginMessage())
		p.logStandalone = standalone
		if !accepted {
			slog.Warn("fdo.payload: dropping unacknowledged log", "standalone", standalone, "reason", reason)
			p.logReceiver = nil
			return nil
		}
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

// classifyLog decides whether an offered log is standalone and whether it
// may be received, per chunking-strategy.md "Standalone Diagnostic
// Transfers", then applies the LogHandler's own policy.
func (p *PayloadOwner) classifyLog(begin chunking.BeginMessage) (standalone, accepted bool, reasonCode int, message string) {
	standalone, _ = begin.Metadata["standalone"].(bool)
	contentType, _ := begin.Metadata["content_type"].(string)
	if contentType == "" {
		contentType = "text/plain"
	}

	switch {
	case standalone && p.currentSender != nil:
		return true, false, chunking.AckReasonBusy, "Busy: payload transfer in progress"
	case !standalone && p.currentSender == nil:
		return false, false, chunking.AckReasonDiagnosticsNotRequested, "No payload in progress and log not marked standalone"
	case p.LogHandler == nil:
		return standalone, false, chunking.AckReasonDiagnosticsNotRequested, "Diagnostics not collected"
	}

	mimeType, name := p.logContext(begin, standalone)
	accepted, reasonCode, message = p.LogHandler.AcceptLog(mimeType, name, begin.TotalSize, contentType)
	if !accepted && reasonCode == 0 {
		reasonCode = chunking.AckReasonDiagnosticsNotRequested
	}
	return standalone, accepted, reasonCode, message
}

// logContext returns the mimeType and name passed to the LogHandler: the
// payload in progress for a nested log, or the payload_name the device
// supplied for a standalone one.
func (p *PayloadOwner) logContext(begin chunking.BeginMessage, standalone bool) (mimeType, name string) {
	if standalone {
		name, _ = begin.Metadata["payload_name"].(string)
		return "", name
	}
	if p.currentSender != nil {
		mimeType, _ = p.currentSender.BeginFields.FSIMFields[-1].(string)
		name, _ = p.currentSender.BeginFields.FSIMFields[-2].(string)
	}
	return mimeType, name
}

// onLogBeginAck applies the accept/reject policy to a log offered with
// require_ack.
func (p *PayloadOwner) onLogBeginAck(begin chunking.BeginMessage) (accepted bool, reasonCode int, message string) {
	p.logStandalone, accepted, reasonCode, message = p.classifyLog(begin)
	p.logAckReasonCode, p.logAckMessage = reasonCode, message
	return accepted, reasonCode, message
}

// onLogEnd assembles the log and hands it to the LogHandler. For a
// standalone log it also queues the terminal payload-log-result.
func (p *PayloadOwner) onLogEnd(ctx context.Context) func(chunking.EndMessage) error {
	return func(end chunking.EndMessage) error {
		if p.logReceiver == nil {
			return nil
		}
		standalone := p.logStandalone
		if p.LogHandler == nil {
			if standalone {
				p.logResult = &chunking.ResultMessage{StatusCode: 2, Message: "Diagnostics not collected"}
			}
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
			Standalone:  standalone,
		}
		if standalone {
			log.Phase, _ = begin.Metadata["phase"].(string)
			log.PayloadName, _ = begin.Metadata["payload_name"].(string)
			log.PayloadVersion, _ = begin.Metadata["payload_version"].(string)
			if end.StatusSet {
				outcome := end.Status
				log.Outcome = &outcome
			}
			log.OutcomeMessage = end.Message
		}
		p.lastLog = log

		mimeType, name := p.logContext(begin, standalone)

		slog.Info("fdo.payload received device diagnostics",
			"bytes", len(data), "content_type", contentType, "truncated", truncated, "source", source,
			"standalone", standalone, "phase", log.Phase)

		err := p.LogHandler.HandleLog(ctx, mimeType, name, log)
		if err != nil {
			slog.Warn("fdo.payload: log handler failed", "error", err)
		}
		if standalone {
			if err != nil {
				p.logResult = &chunking.ResultMessage{StatusCode: 2, Message: "log not retained"}
			} else {
				p.logResult = &chunking.ResultMessage{StatusCode: 0}
			}
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
