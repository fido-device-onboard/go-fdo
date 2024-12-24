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

func msgTypeFromPath(w http.ResponseWriter, r *http.Request) (uint8, bool) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return 0, false
	}
	path := strings.TrimPrefix(r.URL.Path, "/fdo/101/msg/")
	if strings.Contains(path, "/") {
		w.WriteHeader(http.StatusNotFound)
		return 0, false
	}
	typ, err := strconv.ParseUint(path, 10, 8)
	if err != nil {
		writeErr(w, 0, fmt.Errorf("invalid message type"))
		return 0, false
	}
	return uint8(typ), true
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Tokens == nil {
		panic("token service not set")
	}

	// Parse message type from request URL
	msgType, ok := msgTypeFromPath(w, r)
	if !ok {
		return
	}
	proto := protocol.Of(msgType)

	// Parse request headers
	token := r.Header.Get("Authorization")
	if token != "" && !strings.HasPrefix(token, bearerPrefix) {
		writeErr(w, msgType, fmt.Errorf("invalid bearer token"))
		return
	}
	token = strings.TrimPrefix(token, bearerPrefix)
	ctx := h.Tokens.TokenContext(r.Context(), token)

	// Get responder for message
	var resp protocol.Responder
	var isProtocolStart bool
	switch proto {
	case protocol.DIProtocol:
		resp = h.DIResponder
		isProtocolStart = msgType == 10
	case protocol.TO0Protocol:
		resp = h.TO0Responder
		isProtocolStart = msgType == 20
	case protocol.TO1Protocol:
		resp = h.TO1Responder
		isProtocolStart = msgType == 30
	case protocol.TO2Protocol:
		resp = h.TO2Responder
		isProtocolStart = msgType == 60
	case protocol.AnyProtocol:
		// Immediately respond to an error
		if token == "" {
			return
		}
		if err := h.Tokens.InvalidateToken(ctx); err != nil {
			slog.Warn("invalidating token", "error", err)
		}
		return
	}
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
				Code:          500,
				PrevMsgType:   msgType,
				ErrString:     err.Error(),
				Timestamp:     time.Now().Unix(),
				CorrelationID: nil,
			})
			return
		}
		ctx = h.Tokens.TokenContext(ctx, initToken)
	}

	debugRequest(w, r, func(w http.ResponseWriter, r *http.Request) {
		h.handleRequest(ctx, w, r, msgType, resp)
	})
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
		return
	}
	if maxSize > 0 && r.ContentLength < 0 {
		_ = r.Body.Close()
		writeErr(w, msgType, errors.New("content length must be specified in request headers"))
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

	// Decrypt TO2 messages after 64
	if protocol.TO2ProveDeviceMsgType < msgType && msgType < protocol.ErrorMsgType {
		sess, err := resp.(interface {
			CryptSession(ctx context.Context) (kex.Session, error)
		}).CryptSession(ctx)
		if err != nil {
			writeErr(w, msgType, err)
			return
		}
		defer sess.Destroy()
		defer func() { _ = r.Body.Close() }()

		decrypted, err := sess.Decrypt(rand.Reader, msg)
		if err != nil {
			writeErr(w, msgType, fmt.Errorf("error decrypting message %d: %w", msgType, err))
			return
		}

		if debugEnabled() {
			slog.Debug("decrypted request", "msg", msgType, "body", tryDebugNotation(decrypted))
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
			slog.Warn("error invalidating token", "error", err)
		}
	}

	// Encrypt TO2 messages beginning with 64
	if protocol.TO2ProveDeviceMsgType < respType && respType < protocol.ErrorMsgType {
		sess, err := resp.(interface {
			CryptSession(ctx context.Context) (kex.Session, error)
		}).CryptSession(ctx)
		if err != nil {
			writeErr(w, msgType, err)
			return
		}
		defer sess.Destroy()

		if debugEnabled() {
			body, _ := cbor.Marshal(respData)
			slog.Debug("unencrypted response", "msg", respType, "body", tryDebugNotation(body))
		}

		respData, err = sess.Encrypt(rand.Reader, respData)
		if err != nil {
			writeErr(w, msgType, fmt.Errorf("error encrypting message %d: %w", respType, err))
			return
		}
	}

	// Invalidate token when finishing a protocol or erroring
	newToken, _ := h.Tokens.TokenFromContext(ctx)
	switch respType {
	case 13, 32, 71, protocol.ErrorMsgType:
		if newToken != "" {
			ctx := h.Tokens.TokenContext(ctx, newToken)
			if err := h.Tokens.InvalidateToken(ctx); err != nil {
				slog.Warn("invalidating token", "error", err)
			}
		}
	}

	// Marshal response to get size
	var body bytes.Buffer
	if err := cbor.NewEncoder(&body).Encode(respData); err != nil {
		writeErr(w, msgType, fmt.Errorf("error marshaling response message %d: %w", respType, err))
		return
	}

	// Add response headers
	w.Header().Add("Authorization", bearerPrefix+newToken)
	w.Header().Add("Content-Length", strconv.Itoa(body.Len()))
	w.Header().Add("Content-Type", "application/cbor")
	w.Header().Add("Message-Type", strconv.Itoa(int(respType)))
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(body.Bytes()); err != nil {
		writeErr(w, msgType, fmt.Errorf("error writing response message %d: %w", respType, err))
		return
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

	// TODO: Set correlation ID
	msg.CorrelationID = nil

	var body bytes.Buffer
	_ = cbor.NewEncoder(&body).Encode(msg)

	w.Header().Add("Content-Length", strconv.Itoa(body.Len()))
	w.Header().Add("Content-Type", "application/cbor")
	w.Header().Add("Message-Type", strconv.Itoa(int(protocol.ErrorMsgType)))
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write(body.Bytes())
}
