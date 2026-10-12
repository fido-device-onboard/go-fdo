// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package http

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

const bearerPrefix = "Bearer "

// Handler implements http.Handler and responds to all DI, TO1, and TO2 message
// types. It is expected that the request will use the POST method and the path
// will be of the form "/fdo/$VER/msg/$MSG".
type Handler struct {
	Tokens protocol.TokenService

	DIResponder  protocol.Responder
	TO0Responder protocol.Responder
	TO1Responder protocol.Responder
	TO2Responder protocol.Responder

	// MaxContentLength defaults to 65535. Negative values disable content
	// length checking.
	MaxContentLength int64
}

// versionAndMsgFromPath parses the FDO version and message type from the URL path.
// Expected path format: /fdo/{version}/msg/{msgType}
// Returns version (101, 200), message type, and success flag.
func versionAndMsgFromPath(w http.ResponseWriter, r *http.Request) (protocol.Version, uint8, bool) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return 0, 0, false
	}

	// Parse path: /fdo/{ver}/msg/{type}
	path := strings.TrimPrefix(r.URL.Path, "/fdo/")
	parts := strings.Split(path, "/")
	if len(parts) != 3 || parts[1] != "msg" {
		w.WriteHeader(http.StatusNotFound)
		return 0, 0, false
	}

	// Parse version
	ver, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		writeErr(w, 0, fmt.Errorf("invalid FDO version"))
		return 0, 0, false
	}
	version := protocol.Version(ver)
	if !version.IsValid() {
		writeErr(w, 0, fmt.Errorf("unsupported FDO version: %d", ver))
		return 0, 0, false
	}

	// Parse message type
	typ, err := strconv.ParseUint(parts[2], 10, 8)
	if err != nil {
		writeErr(w, 0, fmt.Errorf("invalid message type"))
		return 0, 0, false
	}

	return version, uint8(typ), true
}

// msgTypeAllowedForVersion reports whether a message type may be sent under
// the given protocol (URL) version: TO2 1.01 messages (60-71) only under
// 101, and TO2 2.0 messages (80-91) only under 200.
func msgTypeAllowedForVersion(msgType uint8, version protocol.Version) bool {
	switch {
	case protocol.TO2HelloDeviceMsgType <= msgType && msgType <= protocol.TO2Done2MsgType:
		return version == protocol.Version101
	case protocol.TO2HelloDeviceProbeMsgType <= msgType && msgType <= protocol.TO2DoneAck20MsgType:
		return version == protocol.Version200
	default:
		return true
	}
}

// isEncryptedTO2Message returns true if the message type requires encryption/decryption.
// In FDO 1.01: messages 65-71 (after ProveDevice/64, key exchange complete)
// In FDO 2.0: messages 86-91 (after OVNextEntry/85, key exchange complete)
func isEncryptedTO2Message(msgType uint8) bool {
	// 1.01: encrypted messages are 65-71
	if protocol.TO2ProveDeviceMsgType < msgType && msgType <= protocol.TO2Done2MsgType {
		return true
	}
	// 2.0: encrypted messages are 86-91
	if protocol.TO2OVNextEntry20MsgType < msgType && msgType <= protocol.TO2DoneAck20MsgType {
		return true
	}
	return false
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Tokens == nil {
		panic("token service not set")
	}

	ctx := r.Context()

	// Parse version and message type from request URL
	version, msgType, ok := versionAndMsgFromPath(w, r)
	if !ok {
		return
	}

	// Inject version into context for downstream handlers
	ctx = protocol.ContextWithVersion(ctx, version)

	// TO2 message types are version specific
	if !msgTypeAllowedForVersion(msgType, version) {
		writeErr(w, msgType, fmt.Errorf("message type %d is not part of FDO version %s", msgType, version))
		return
	}

	proto := protocol.Of(msgType)

	// Parse request headers
	token := r.Header.Get("Authorization")
	if token != "" && !strings.HasPrefix(token, bearerPrefix) {
		writeErr(w, msgType, fmt.Errorf("invalid bearer token"))
		return
	}
	if token != "" {
		token = strings.TrimPrefix(token, bearerPrefix)
		ctx = h.Tokens.TokenContext(ctx, token)
	}

	// Immediately respond to an error
	if msgType == protocol.ErrorMsgType {
		debugRequest(w, r, h.handleError(ctx, token))
		return
	}

	// Get responder for message
	resp, isProtocolStart := h.responder(proto, msgType)
	if resp == nil {
		writeErr(w, msgType, fmt.Errorf("unsupported message type"))
		return
	}

	// Inject token state into context to keep method signatures clean while
	// allowing some implementations to mutate tokens on every message.
	if isProtocolStart {
		initToken, err := h.Tokens.NewToken(ctx, proto)
		if err != nil {
			writeErr(w, msgType, protocol.ErrorMessage{
				Code:        500,
				PrevMsgType: msgType,
				ErrString:   err.Error(),
				Timestamp:   time.Now().Unix(),
			})
			return
		}
		ctx = h.Tokens.TokenContext(ctx, initToken)
	}
	if err := h.checkSessionProtocol(ctx, isProtocolStart, proto); err != nil {
		writeErr(w, msgType, err)
		return
	}
	if err := h.pinSessionVersion(ctx, isProtocolStart, version); err != nil {
		writeErr(w, msgType, err)
		return
	}

	debugRequest(w, r, func(w http.ResponseWriter, r *http.Request) {
		h.handleRequest(ctx, w, r, msgType, resp)
	})
}

// responder returns the responder for a message and whether the message
// starts its protocol.
func (h Handler) responder(proto protocol.Protocol, msgType uint8) (resp protocol.Responder, isProtocolStart bool) {
	switch proto {
	case protocol.DIProtocol:
		return h.DIResponder, msgType == protocol.DIAppStartMsgType
	case protocol.TO0Protocol:
		return h.TO0Responder, msgType == protocol.TO0HelloMsgType
	case protocol.TO1Protocol:
		return h.TO1Responder, msgType == protocol.TO1HelloRVMsgType
	case protocol.TO2Protocol:
		// TO2 starts at msg 60 (1.01) or msg 80 (2.0)
		return h.TO2Responder, msgType == protocol.TO2HelloDeviceMsgType || msgType == protocol.TO2HelloDeviceProbeMsgType
	default:
		return nil, false
	}
}

// checkSessionProtocol checks that a message of an existing session belongs to
// the protocol (DI, TO0, TO1, TO2) the session was started for. It does nothing
// for protocol start messages, which create a new session, or if the
// TokenService does not implement protocol.TokenProtocolService.
func (h Handler) checkSessionProtocol(ctx context.Context, isProtocolStart bool, proto protocol.Protocol) error {
	tps, ok := h.Tokens.(protocol.TokenProtocolService)
	if !ok || isProtocolStart {
		return nil
	}
	sessProto, err := tps.TokenProtocol(ctx)
	if err != nil {
		return fmt.Errorf("error retrieving session protocol: %w", err)
	}
	if sessProto != proto {
		return fmt.Errorf("%s message in a session started for %s", proto, sessProto)
	}
	return nil
}

// pinSessionVersion records the protocol version of a new session, or checks
// that a message of an existing session uses the version the session started
// with. It does nothing if the TokenService does not implement
// protocol.TokenVersionService.
func (h Handler) pinSessionVersion(ctx context.Context, isProtocolStart bool, version protocol.Version) error {
	tvs, ok := h.Tokens.(protocol.TokenVersionService)
	if !ok {
		return nil
	}
	if isProtocolStart {
		if err := tvs.SetTokenVersion(ctx, version); err != nil {
			return fmt.Errorf("error recording session protocol version: %w", err)
		}
		return nil
	}
	sessVersion, err := tvs.TokenVersion(ctx)
	if err != nil {
		return fmt.Errorf("error retrieving session protocol version: %w", err)
	}
	if sessVersion != version {
		return fmt.Errorf("message for FDO version %s in a session started with version %s", version, sessVersion)
	}
	return nil
}

func (h Handler) handleError(ctx context.Context, token string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var errMsg protocol.ErrorMessage
		if err := cbor.NewDecoder(r.Body).Decode(&errMsg); err != nil {
			slog.Warn("decoding error message request body", "error", err)
		} else {
			switch protocol.Of(errMsg.PrevMsgType) {
			case protocol.DIProtocol:
				h.DIResponder.HandleError(ctx, errMsg)
			case protocol.TO0Protocol:
				h.TO0Responder.HandleError(ctx, errMsg)
			case protocol.TO1Protocol:
				h.TO1Responder.HandleError(ctx, errMsg)
			case protocol.TO2Protocol:
				h.TO2Responder.HandleError(ctx, errMsg)
			}
		}

		if token != "" {
			if err := h.Tokens.InvalidateToken(ctx); err != nil {
				slog.Warn("invalidating token", "error", err)
			}
		}
	}
}

func (h Handler) handleRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, msgType uint8, resp protocol.Responder) {
	// Validate content length
	maxSize := h.MaxContentLength
	if maxSize == 0 {
		maxSize = 65535
	}
	if maxSize > 0 && r.ContentLength > maxSize {
		_ = r.Body.Close()
		writeErr(w, msgType, fmt.Errorf("content too large (%d bytes)", r.ContentLength))
		h.invalidateToken(ctx)
		return
	}
	if maxSize > 0 && r.ContentLength < 0 {
		_ = r.Body.Close()
		writeErr(w, msgType, errors.New("content length must be specified in request headers"))
		h.invalidateToken(ctx)
		return
	}

	// Allow reading up to expected msg length
	msg := r.Body
	if r.ContentLength > 0 {
		msg = io.ReadCloser(struct {
			io.Reader
			io.Closer
		}{
			Reader: io.LimitReader(r.Body, r.ContentLength),
			Closer: r.Body,
		})
	}

	// Decrypt TO2 messages after key exchange is complete
	// 1.01: messages 65-71 (after ProveDevice/64)
	// 2.0: messages 86-91 (after OVNextEntry/85)
	if isEncryptedTO2Message(msgType) {
		sess, err := resp.(interface {
			CryptSession(ctx context.Context) (kex.Session, error)
		}).CryptSession(ctx)
		if err != nil {
			writeErr(w, msgType, err)
			h.invalidateToken(ctx)
			return
		}
		defer sess.Destroy()
		defer func() { _ = r.Body.Close() }()

		decrypted, err := sess.Decrypt(rand.Reader, msg)
		if err != nil {
			writeErr(w, msgType, fmt.Errorf("error decrypting message %d: %w", msgType, err))
			h.invalidateToken(ctx)
			return
		}

		if debugEnabled() {
			// #nosec G706 -- sanitizeLogValue removes newline/control characters
			slog.Debug("decrypted request", "msg", msgType, "body", sanitizeLogValue(tryDebugNotation(decrypted)))
		}

		msg = io.NopCloser(bytes.NewBuffer(decrypted))
	}

	// Handle request message
	h.writeResponse(ctx, w, msgType, msg, resp)
}

func (h Handler) writeResponse(ctx context.Context, w http.ResponseWriter, msgType uint8, msg io.Reader, resp protocol.Responder) {
	// Perform business logic of message handling
	respType, respData := resp.Respond(ctx, msgType, msg)
	if respType == protocol.ErrorMsgType {
		if err := h.Tokens.InvalidateToken(ctx); err != nil {
			slog.Warn("invalidating token", "error", err)
		}
	}

	// Encrypt TO2 messages after key exchange is complete
	if isEncryptedTO2Message(respType) {
		sess, err := resp.(interface {
			CryptSession(ctx context.Context) (kex.Session, error)
		}).CryptSession(ctx)
		if err != nil {
			writeErr(w, msgType, err)
			h.invalidateToken(ctx)
			return
		}
		defer sess.Destroy()

		if debugEnabled() {
			body, _ := cbor.Marshal(respData)
			// #nosec G706 -- sanitizeLogValue removes newline/control characters
			slog.Debug("unencrypted response", "msg", respType, "body", sanitizeLogValue(tryDebugNotation(body)))
		}

		respData, err = sess.Encrypt(rand.Reader, respData)
		if err != nil {
			writeErr(w, msgType, fmt.Errorf("error encrypting message %d: %w", respType, err))
			h.invalidateToken(ctx)
			return
		}
	}

	// Invalidate token when finishing a protocol
	// DI: 13, TO0: 23, TO1: 33, TO2 1.01: 71, TO2 2.0: 91
	switch respType {
	case protocol.DIDoneMsgType, protocol.TO0AcceptOwnerMsgType, protocol.TO1RVRedirectMsgType,
		protocol.TO2Done2MsgType, protocol.TO2DoneAck20MsgType:
		h.invalidateToken(ctx)
	}

	// Marshal response to get size
	var body bytes.Buffer
	if err := cbor.NewEncoder(&body).Encode(respData); err != nil {
		writeErr(w, msgType, fmt.Errorf("error marshaling response message %d: %w", respType, err))
		h.invalidateToken(ctx)
		return
	}

	// Add response headers
	newToken, _ := h.Tokens.TokenFromContext(ctx)
	w.Header().Add("Authorization", bearerPrefix+newToken)
	w.Header().Add("Content-Length", strconv.Itoa(body.Len()))
	w.Header().Add("Content-Type", "application/cbor")
	w.Header().Add("Message-Type", strconv.Itoa(int(respType)))
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(body.Bytes()); err != nil {
		writeErr(w, msgType, fmt.Errorf("error writing response message %d: %w", respType, err))
		h.invalidateToken(ctx)
		return
	}
}

func (h Handler) invalidateToken(ctx context.Context) {
	token, _ := h.Tokens.TokenFromContext(ctx)
	if token == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ctx = h.Tokens.TokenContext(ctx, token)
	if err := h.Tokens.InvalidateToken(ctx); err != nil {
		slog.Warn("invalidating token", "error", err)
	}
}

func writeErr(w http.ResponseWriter, prevMsgType uint8, err error) {
	var msg protocol.ErrorMessage
	if !errors.As(err, &msg) {
		msg.Code = 500
		msg.PrevMsgType = prevMsgType
		msg.ErrString = err.Error()
		msg.Timestamp = time.Now().Unix()
	}

	// TODO: Set correlation ID. EMErrorCID is always sent as a uint; 0
	// means none (FDO 2.0 Errata 1, E4). Receivers accept null as 0.
	var none uint
	msg.CorrelationID = &none

	var body bytes.Buffer
	_ = cbor.NewEncoder(&body).Encode(msg)

	w.Header().Add("Content-Length", strconv.Itoa(body.Len()))
	w.Header().Add("Content-Type", "application/cbor")
	w.Header().Add("Message-Type", strconv.Itoa(int(protocol.ErrorMsgType)))
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write(body.Bytes())
}
