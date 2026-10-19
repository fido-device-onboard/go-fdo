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
	"slices"
	"strings"

	fdo "github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/cose"
	"github.com/fido-device-onboard/go-fdo/fsim/chunking"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// PayloadContentTypeBegin is the registered content type of a signed
// fdo.payload:payload-begin (fdo.payload.md, "Authorization of Payload
// Delivery"). Its external_aad is cose.AADPayloadProvision.
const PayloadContentTypeBegin = "application/cbor+fdo.payload.payload-begin"

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

// StandaloneLog is a diagnostic log the device sends on its own initiative,
// not tied to a payload in the current session (fdo.payload.md "Standalone
// Diagnostics"), e.g. to report the outcome of an install that ran after an
// earlier session staged its configuration.
type StandaloneLog struct {
	PayloadLog

	// Phase labels the step the log describes, e.g. "install".
	Phase string
	// Outcome is sent as the payload-log-end status (0 = success,
	// 1 = warning, 2 = error); nil means "not stated".
	Outcome *int
	// OutcomeMessage is an optional one-line summary for payload-log-end.
	OutcomeMessage string
	// PayloadName and PayloadVersion identify a payload delivered in an
	// earlier session that this log reports on.
	PayloadName    string
	PayloadVersion string

	// Set by the module once the owner has answered.
	Result   *chunking.ResultMessage // the owner's payload-log-result
	Declined *chunking.AckMessage    // the owner's final payload-log-ack rejection
}

// Delivered reports whether the owner confirmed it retained the log.
func (l *StandaloneLog) Delivered() bool { return l.Result != nil && l.Result.StatusCode == 0 }

type standaloneState int

const (
	standaloneIdle standaloneState = iota
	standaloneAwaitingAck
	standaloneAwaitingResult
)

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

	// StandaloneLogs are sent, in order, as standalone payload-log-*
	// transfers once the owner activates the module and no payload transfer
	// is in progress. Each entry's Result / Declined is filled in as the
	// owner answers.
	StandaloneLogs []*StandaloneLog

	// ReportOnly makes this a report-only session: every payload-begin is
	// rejected (payload-ack [false, 3]) before any data is sent, and a
	// payload offered without require_ack is received, discarded and
	// answered with payload-result [1, ...]. No handler is needed.
	ReportOnly bool

	// payload-begin is authorization-gated (chunking-strategy.md
	// "Authorization of Begin Messages"): it is accepted signed by the Owner
	// or a PERM.7 Delegate, or unsigned from a TO2 peer that holds
	// provisioning authority.

	// OwnerPublicKey overrides the TO2-proven Owner key taken from ctx
	// (fdo.OwnerPublicKeyFromContext). Normally left nil.
	OwnerPublicKey crypto.PublicKey

	// UnauthorizedMIMETypes is a documented local policy (fdo.payload.md): MIME
	// types accepted unsigned even from a peer WITHOUT provisioning authority
	// (e.g. an onboard-only Delegate). For these types that peer is
	// effectively a provisioning authority; list only genuinely low-risk
	// types. Empty (the default) means none.
	UnauthorizedMIMETypes []string

	// URLFetcher enables delivery modes 1 (URL) and 2 (meta-URL) in unified
	// mode. If nil, those modes are rejected with error 14. Implement
	// chunking.ValidatingFetcher to let validated TLS count as evidence.
	URLFetcher chunking.URLFetcher

	// Active indicates if the module is active
	Active bool

	// Internal state
	receiver     *chunking.ChunkReceiver
	buffer       *bytes.Buffer
	begin        chunking.BeginMessage
	resultStatus int
	resultMsg    string
	logSender    *chunking.ChunkSender
	beginHasher  hash.Hash // chunked mode: running hash for begin expected_hash

	standaloneIdx    int
	standaloneState  standaloneState
	standaloneSender *chunking.ChunkSender
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
		if p.standaloneState == standaloneAwaitingAck {
			return p.handleStandaloneAck(ctx, messageBody, respond, yield)
		}
		return p.handleLogAck(ctx, messageBody, respond, yield)
	}
	if messageName == "payload-log-result" {
		return p.handleStandaloneResult(ctx, messageBody, respond)
	}

	// payload-begin is authorization-gated.
	if messageName == "payload-begin" {
		inner, err := p.authorizeBegin(ctx, messageBody)
		if err != nil {
			slog.Error("fdo.payload: payload-begin rejected", "error", err)
			return p.sendError(respond, chunking.ErrorCode(err, chunking.CodeNotAuthorized), "Provisioning not authorized", err.Error())
		}
		return p.handleChunkedMessage(ctx, messageName, bytes.NewReader(inner), respond)
	}

	// Handle chunked payload messages
	if strings.HasPrefix(messageName, "payload-") {
		return p.handleChunkedMessage(ctx, messageName, messageBody, respond)
	}

	// Silently ignore unknown messages for protocol compatibility
	return nil
}

// authorizeBegin authorizes payload-begin and returns the inner (unsigned)
// begin map.
func (p *Payload) authorizeBegin(ctx context.Context, body io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("read payload-begin: %w", err)
	}
	ownerKey := p.OwnerPublicKey
	if ownerKey == nil {
		ownerKey = fdo.OwnerPublicKeyFromContext(ctx)
	}
	inner, signed, err := authorizeGated(ctx, raw, ownerKey, PayloadContentTypeBegin, cose.AADPayloadProvision, p.allowUnauthorized)
	if err != nil {
		return nil, err
	}
	if err := checkSignedBeginBindsContent(inner, signed); err != nil {
		return nil, &chunking.TransferError{Code: chunking.CodeNotAuthorized, Msg: err.Error()}
	}
	return inner, nil
}

// allowUnauthorized applies the UnauthorizedMIMETypes local policy.
func (p *Payload) allowUnauthorized(inner []byte) (bool, string) {
	if len(p.UnauthorizedMIMETypes) == 0 {
		return false, ""
	}
	var begin chunking.BeginMessage
	if err := begin.UnmarshalCBOR(inner); err != nil {
		return false, ""
	}
	mime, _ := begin.FSIMFields[-1].(string)
	if begin.DeliveryMode == chunking.DeliveryModeInline && slices.Contains(p.UnauthorizedMIMETypes, mime) {
		return true, "UnauthorizedMIMETypes includes " + mime
	}
	return false, ""
}

// checkDeliveryMode validates the delivery mode for the configured handler.
func (p *Payload) checkDeliveryMode(begin chunking.BeginMessage) error {
	switch begin.DeliveryMode {
	case chunking.DeliveryModeInline:
		return nil
	case chunking.DeliveryModeURL, chunking.DeliveryModeMetaURL:
		if p.UnifiedHandler == nil || p.URLFetcher == nil {
			return &chunking.TransferError{Code: chunking.CodeDeliveryModeNotSupported,
				Msg: fmt.Sprintf("delivery mode %d requires a unified handler and a URLFetcher", begin.DeliveryMode)}
		}
		return nil
	default:
		return &chunking.TransferError{Code: chunking.CodeDeliveryModeNotSupported,
			Msg: fmt.Sprintf("delivery mode %d not supported", begin.DeliveryMode)}
	}
}

// Yield implements serviceinfo.DeviceModule. It is the device's chance to
// start a standalone log after the owner's messages have been handled,
// including right after the owner activates the module.
func (p *Payload) Yield(ctx context.Context, respond func(string) io.Writer, yield func()) error {
	return p.maybeStartStandalone(ctx, respond)
}

// reset clears the internal state.
func (p *Payload) reset() {
	if p.receiver != nil && p.receiver.IsReceiving() && p.ChunkedHandler != nil {
		_ = p.ChunkedHandler.CancelPayload()
	}
	p.receiver = nil
	p.buffer = nil
	p.logSender = nil
	p.standaloneState = standaloneIdle
	p.standaloneSender = nil
}

// handleChunkedMessage processes payload-begin, payload-data-<n>, and payload-end messages.
func (p *Payload) handleChunkedMessage(ctx context.Context, messageName string, messageBody io.Reader, respond func(string) io.Writer) error {
	if p.UnifiedHandler == nil && p.ChunkedHandler == nil && !p.ReportOnly {
		return p.sendError(respond, 4, "No payload handler configured", "")
	}

	if p.receiver == nil && p.ReportOnly {
		p.receiver = &chunking.ChunkReceiver{
			PayloadName:    "payload",
			DiscardPayload: true,
			OnBeginAck: func(chunking.BeginMessage) (bool, int, string) {
				return false, chunking.AckReasonNotApplicable, "Report-only session"
			},
			OnEnd: func(chunking.EndMessage) error {
				p.resultStatus, p.resultMsg = 1, "Report-only session; payload ignored"
				return nil
			},
		}
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
		if sendErr := p.sendError(respond, chunking.ErrorCode(err, 6), "Transfer error", err.Error()); sendErr != nil {
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
			return p.maybeStartStandalone(ctx, respond)
		}
	}

	// After successful end message, offer diagnostics and then send the
	// result. payload-result is terminal per chunking-strategy.md, so the
	// log transfer must precede it.
	if strings.HasSuffix(messageName, "-end") && !p.receiver.IsReceiving() {
		p.receiver = nil
		if p.ReportOnly {
			return p.finishPayload(ctx, respond)
		}

		started, err := p.startLogTransfer(ctx, respond)
		if err != nil {
			return err
		}
		if started {
			// Result is deferred until the owner accepts or declines the log.
			return nil
		}

		return p.finishPayload(ctx, respond)
	}

	return nil
}

// finishPayload sends payload-result, ending the primary transfer, and then
// offers any standalone log that had to wait for it.
func (p *Payload) finishPayload(ctx context.Context, respond func(string) io.Writer) error {
	if err := p.sendResult(respond); err != nil {
		return err
	}
	return p.maybeStartStandalone(ctx, respond)
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

	sender := p.newLogSender(ctx, *log, nil)
	if err := sender.SendBeginToWriter(respond); err != nil {
		return false, fmt.Errorf("failed to send payload-log-begin: %w", err)
	}
	p.logSender = sender

	slog.Debug("fdo.payload sent log begin",
		"size", len(sender.Data), "metadata", sender.BeginFields.Metadata)

	return true, nil
}

// newLogSender builds a payload-log sender for log, clamped to MaxLogSize,
// with require_ack set and extra merged into the begin metadata.
func (p *Payload) newLogSender(ctx context.Context, log PayloadLog, extra map[string]any) *chunking.ChunkSender {
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
	for k, v := range extra {
		metadata[k] = v
	}

	sender := chunking.NewChunkSender("payload-log", data)
	sender.BeginFields.HashAlg = "sha256"
	sender.BeginFields.RequireAck = true
	sender.BeginFields.Metadata = metadata
	if mtu, ok := ctx.Value(serviceinfo.MTUKey{}).(uint16); ok && int(mtu) > logChunkOverhead {
		sender.ChunkSize = int(mtu) - logChunkOverhead
	}
	return sender
}

// defaultLogMTU is assumed when the context carries no negotiated MTU: the
// FDO minimum ServiceInfo size, less message framing.
const defaultLogMTU = 1300 - 5

// logAlreadyQueuedReserve is the room sendLogBody assumes is already used in
// the current message when it starts.
const logAlreadyQueuedReserve = 256

// sendLogBody sends the data chunks and *-end of an accepted log so that no
// service info KV straddles a message boundary. The serviceinfo chunker
// otherwise splits a value wherever a message fills up, and an owner that
// does not reassemble a value split across messages (go-fdo's does not)
// receives a truncated chunk. The owner side avoids this the same way, by
// packing chunks to producer.Available().
func sendLogBody(ctx context.Context, sender *chunking.ChunkSender, respond func(string) io.Writer, yield func()) error {
	mtu := defaultLogMTU
	if v, ok := ctx.Value(serviceinfo.MTUKey{}).(uint16); ok && int(v) > logChunkOverhead {
		mtu = int(v)
	}
	// What is already in the current message is unknown, but small: at most
	// the replies to the owner's other messages in this round. Reserve room
	// for it, and size chunks so the first one always fits, rather than
	// yielding first: a yield while the message is still empty ends the
	// round, and what is written after it is lost (exchangeServiceInfoRound
	// in to2.go treats it as "nothing more to send").
	if limit := mtu - logChunkOverhead - logAlreadyQueuedReserve; sender.ChunkSize > limit {
		sender.ChunkSize = limit
	}
	used := logAlreadyQueuedReserve
	fit := func(n int) {
		if used+n > mtu {
			yield()
			used = 0
		}
		used += n
	}

	for remaining := len(sender.Data); remaining > 0; remaining = len(sender.Data) - int(sender.GetBytesSent()) {
		fit(min(sender.ChunkSize, remaining) + logChunkOverhead)
		if _, err := sender.SendNextChunkToWriter(respond); err != nil {
			return fmt.Errorf("failed to send payload-log chunk: %w", err)
		}
	}
	fit(logChunkOverhead + len(sender.EndFields.Message))
	if err := sender.SendEndToWriter(respond); err != nil {
		return fmt.Errorf("failed to send payload-log-end: %w", err)
	}
	return nil
}

// maybeStartStandalone offers the next queued standalone log, if the module
// is idle: no payload transfer, nested log or standalone log in progress.
func (p *Payload) maybeStartStandalone(ctx context.Context, respond func(string) io.Writer) error {
	if p.standaloneState != standaloneIdle || p.receiver != nil || p.logSender != nil ||
		p.standaloneIdx >= len(p.StandaloneLogs) {
		return nil
	}
	l := p.StandaloneLogs[p.standaloneIdx]

	extra := map[string]any{"standalone": true}
	if l.Phase != "" {
		extra["phase"] = l.Phase
	}
	if l.PayloadName != "" {
		extra["payload_name"] = l.PayloadName
	}
	if l.PayloadVersion != "" {
		extra["payload_version"] = l.PayloadVersion
	}
	sender := p.newLogSender(ctx, l.PayloadLog, extra)
	if l.Outcome != nil {
		sender.EndFields.Status, sender.EndFields.StatusSet = *l.Outcome, true
	}
	sender.EndFields.Message = l.OutcomeMessage

	if err := sender.SendBeginToWriter(respond); err != nil {
		return fmt.Errorf("failed to send standalone payload-log-begin: %w", err)
	}
	p.standaloneSender = sender
	p.standaloneState = standaloneAwaitingAck
	slog.Debug("fdo.payload offered standalone log", "index", p.standaloneIdx, "size", len(sender.Data), "phase", l.Phase)
	return nil
}

// handleStandaloneAck processes the owner's payload-log-ack for a standalone
// log. Accepted: send the log and await payload-log-result. Busy: retry once
// the owner's transfer is over. Otherwise the log is declined for good.
func (p *Payload) handleStandaloneAck(ctx context.Context, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
	sender := p.standaloneSender
	data, err := io.ReadAll(messageBody)
	if err != nil {
		return fmt.Errorf("failed to read payload-log-ack: %w", err)
	}
	var ack chunking.AckMessage
	if err := ack.UnmarshalCBOR(data); err != nil {
		return fmt.Errorf("failed to decode payload-log-ack: %w", err)
	}

	if !ack.Accepted {
		p.standaloneState, p.standaloneSender = standaloneIdle, nil
		if ack.ReasonCode == chunking.AckReasonBusy {
			slog.Debug("fdo.payload: owner busy; will offer standalone log again")
			return nil
		}
		slog.Info("fdo.payload: owner declined standalone log", "reason_code", ack.ReasonCode, "message", ack.Message)
		p.StandaloneLogs[p.standaloneIdx].Declined = &ack
		p.standaloneIdx++
		return p.maybeStartStandalone(ctx, respond)
	}

	if err := sendLogBody(ctx, sender, respond, yield); err != nil {
		return err
	}
	p.standaloneState = standaloneAwaitingResult
	slog.Debug("fdo.payload sent standalone log", "bytes", sender.GetBytesSent())
	return nil
}

// handleStandaloneResult records the owner's payload-log-result and offers
// the next queued log.
func (p *Payload) handleStandaloneResult(ctx context.Context, messageBody io.Reader, respond func(string) io.Writer) error {
	data, err := io.ReadAll(messageBody)
	if err != nil {
		return fmt.Errorf("failed to read payload-log-result: %w", err)
	}
	if p.standaloneState != standaloneAwaitingResult {
		slog.Warn("fdo.payload: unexpected payload-log-result")
		return nil
	}
	var res chunking.ResultMessage
	if err := res.UnmarshalCBOR(data); err != nil {
		return fmt.Errorf("failed to decode payload-log-result: %w", err)
	}
	slog.Info("fdo.payload: standalone log result", "status", res.StatusCode, "message", res.Message)
	p.StandaloneLogs[p.standaloneIdx].Result = &res
	p.standaloneIdx++
	p.standaloneState, p.standaloneSender = standaloneIdle, nil
	return p.maybeStartStandalone(ctx, respond)
}

// handleLogAck processes the owner's payload-log-ack. On acceptance the log
// chunks and payload-log-end are sent, followed by the terminal
// payload-result. On rejection the result is sent immediately.
func (p *Payload) handleLogAck(ctx context.Context, messageBody io.Reader, respond func(string) io.Writer, yield func()) error {
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
		return p.finishPayload(ctx, respond)
	}

	if err := sendLogBody(ctx, sender, respond, yield); err != nil {
		return err
	}

	slog.Debug("fdo.payload sent log", "bytes", sender.GetBytesSent())

	return p.finishPayload(ctx, respond)
}

// onBeginAck is called when payload-begin with RequireAck=true is received.
// It delegates to the AckHandler to decide whether to accept or reject.
func (p *Payload) onBeginAck(begin chunking.BeginMessage) (accepted bool, reasonCode int, message string) {
	if err := p.checkDeliveryMode(begin); err != nil {
		return false, chunking.ErrorCode(err, chunking.CodeDeliveryModeNotSupported), err.Error()
	}
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
	if err := p.checkDeliveryMode(begin); err != nil {
		return err
	}
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

		data := p.buffer.Bytes()
		size := p.begin.TotalSize
		switch p.begin.DeliveryMode {
		case chunking.DeliveryModeInline:
			// A hash in payload-begin binds the bytes to the authorisation
			// (payload-end's hash is checked by the chunk receiver).
			if err := verifyBeginHash(data, p.begin); err != nil {
				return err
			}
		default:
			// Modes 1/2: every fetched object must be authenticated
			// (chunking-strategy.md "Authenticating Fetched Content").
			ownerKey := p.OwnerPublicKey
			if ownerKey == nil {
				ownerKey = fdo.OwnerPublicKeyFromContext(ctx)
			}
			res, err := chunking.Resolve(p.URLFetcher, p.begin, ownerKey)
			if err != nil {
				return err
			}
			data = res.Content
			size = uint64(len(data))
			if res.Meta != nil {
				mimeType = res.Meta.MIMEType
				if res.Meta.Name != "" {
					name = res.Meta.Name
				}
			}
		}

		slog.Debug("fdo.payload unified",
			"mime_type", mimeType,
			"name", name,
			"size", size,
			"received", len(data))

		// Call unified handler with complete payload
		statusCode, message, err := p.UnifiedHandler.HandlePayload(ctx, mimeType, name, size, metadata, data)
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
	if err := p.checkDeliveryMode(begin); err != nil {
		return err
	}
	p.beginHasher = nil
	if len(begin.ExpectedHash) > 0 {
		h, err := newBeginHasher(begin.HashAlg)
		if err != nil {
			return err
		}
		p.beginHasher = h
		p.begin = begin
	}

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
	if p.beginHasher != nil {
		p.beginHasher.Write(data)
	}
	return p.ChunkedHandler.ReceiveChunk(data)
}

// onEndChunked is called when payload-end is received in chunked mode.
func (p *Payload) onEndChunked(end chunking.EndMessage) error {
	// The application has already seen the bytes, so a mismatch cancels the
	// payload before it is finalized and applied.
	if p.beginHasher != nil {
		sum := p.beginHasher.Sum(nil)
		p.beginHasher = nil
		if subtle.ConstantTimeCompare(sum, p.begin.ExpectedHash) != 1 {
			_ = p.ChunkedHandler.CancelPayload()
			return &chunking.TransferError{Code: chunking.CodeHashMismatch, Msg: "payload does not match expected_hash (key 8)"}
		}
	}

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
