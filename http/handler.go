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
	"net/http/httptest"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
)

const bearerPrefix = "Bearer "

// Handler implements http.Handler and responds to all DI, TO1, and TO2 message
// types.
type Handler[T any] struct {
	Tokens fdo.TokenService

	DIResponder  *fdo.DIServer[T]
	TO0Responder *fdo.TO0Server
	TO1Responder *fdo.TO1Server
	TO2Responder *fdo.TO2Server

	// MaxContentLength defaults to 65535. Negative values disable content
	// length checking.
	MaxContentLength int64
}

var _ http.Handler = (*Handler[fdo.DeviceMfgInfo])(nil)

type responder interface {
	Respond(ctx context.Context, msgType uint8, msg io.Reader) (respType uint8, resp any)
}

func (h Handler[T]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Parse message type from request URL
	typ, err := strconv.ParseUint(r.PathValue("msg"), 10, 8)
	if err != nil {
		writeErr(w, 0, fmt.Errorf("invalid message type"))
		return
	}
	msgType := uint8(typ)
	protocol := fdo.ProtocolOf(msgType)

	// Parse request headers
	token := r.Header.Get("Authorization")
	if token != "" && !strings.HasPrefix(token, bearerPrefix) {
		writeErr(w, msgType, fmt.Errorf("invalid bearer token"))
		return
	}
	token = strings.TrimPrefix(token, bearerPrefix)
	ctx := h.Tokens.TokenContext(r.Context(), token)

	// Get responder for message
	var resp responder
	var isProtocolStart bool
	switch protocol {
	case fdo.DIProtocol:
		resp = h.DIResponder
		isProtocolStart = msgType == 10
	case fdo.TO0Protocol:
		resp = h.TO0Responder
		isProtocolStart = msgType == 20
	case fdo.TO1Protocol:
		resp = h.TO1Responder
		isProtocolStart = msgType == 30
	case fdo.TO2Protocol:
		resp = h.TO2Responder
		isProtocolStart = msgType == 60
	case fdo.AnyProtocol:
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
		initToken, err := h.Tokens.NewToken(ctx, protocol)
		if err != nil {
			writeErr(w, msgType, fdo.ErrorMessage{
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

	if debugEnabled() {
		h.debugRequest(ctx, w, r, msgType, resp)
		return
	}
	h.handleRequest(ctx, w, r, msgType, resp)
}

func (h Handler[T]) debugRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, msgType uint8, resp responder) {
	// Dump request
	debugReq, _ := httputil.DumpRequest(r, false)
	var saveBody bytes.Buffer
	if _, err := saveBody.ReadFrom(r.Body); err == nil {
		r.Body = io.NopCloser(&saveBody)
	}
	slog.Debug("request", "dump", string(bytes.TrimSpace(debugReq)),
		"body", tryDebugNotation(saveBody.Bytes()))

	// Dump response
	rr := httptest.NewRecorder()
	h.handleRequest(ctx, rr, r, msgType, resp)
	debugResp, _ := httputil.DumpResponse(rr.Result(), false)
	slog.Debug("response", "dump", string(bytes.TrimSpace(debugResp)),
		"body", tryDebugNotation(rr.Body.Bytes()))

	// Copy recorded response into response writer
	for key, values := range rr.Header() {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(rr.Code)
	_, _ = w.Write(rr.Body.Bytes())
}

func (h Handler[T]) handleRequest(ctx context.Context, w http.ResponseWriter, r *http.Request, msgType uint8, resp responder) {
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
	if 64 < msgType && msgType < fdo.ErrorMsgType {
		_, sess, err := resp.(*fdo.TO2Server).Session.XSession(ctx)
		if err != nil {
			writeErr(w, msgType, err)
			return
		}
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

func (h Handler[T]) writeResponse(ctx context.Context, w http.ResponseWriter, msgType uint8, msg io.Reader, resp responder) {
	// Perform business logic of message handling
	respType, respData := resp.Respond(ctx, msgType, msg)
	if respType == fdo.ErrorMsgType {
		if err := h.Tokens.InvalidateToken(ctx); err != nil {
			slog.Warn("error invalidating token", "error", err)
		}
	}

	// Encrypt TO2 messages beginning with 64
	if 64 < respType && respType < fdo.ErrorMsgType {
		_, sess, err := resp.(*fdo.TO2Server).Session.XSession(ctx)
		if err != nil {
			writeErr(w, msgType, err)
			return
		}

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
	case 13, 32, 71, fdo.ErrorMsgType:
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
	var msg fdo.ErrorMessage
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
	w.Header().Add("Message-Type", strconv.Itoa(int(fdo.ErrorMsgType)))
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write(body.Bytes())
}
