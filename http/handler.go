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
type Handler struct {
	Responder *fdo.Server

	// MaxContentLength defaults to 65535. Negative values disable content
	// length checking.
	MaxContentLength int64
}

var _ http.Handler = (*Handler)(nil)

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !debugEnabled() {
		h.handleRequest(w, r)
		return
	}

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
	h.handleRequest(rr, r)
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

func (h Handler) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Parse message type from request URL
	typ, err := strconv.ParseUint(r.PathValue("msg"), 10, 8)
	if err != nil {
		h.error(w, 0, fmt.Errorf("invalid message type"))
		return
	}
	msgType := uint8(typ)

	// Parse request headers
	token := r.Header.Get("Authorization")
	if token != "" && !strings.HasPrefix(token, bearerPrefix) {
		h.error(w, msgType, fmt.Errorf("invalid bearer token"))
		return
	}
	token = strings.TrimPrefix(token, bearerPrefix)

	// Validate content length
	maxSize := h.MaxContentLength
	if maxSize == 0 {
		maxSize = 65535
	}
	if maxSize > 0 && r.ContentLength > maxSize {
		_ = r.Body.Close()
		h.error(w, msgType, fmt.Errorf("content too large (%d bytes)", r.ContentLength))
		return
	}
	if maxSize > 0 && r.ContentLength < 0 {
		_ = r.Body.Close()
		h.error(w, msgType, errors.New("content length must be specified in request headers"))
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
		_, sess, err := h.Responder.TO2.Session(r.Context(), token)
		if err != nil {
			h.error(w, msgType, err)
			return
		}
		defer func() { _ = r.Body.Close() }()

		decrypted, err := sess.Decrypt(rand.Reader, msg)
		if err != nil {
			h.error(w, msgType, fmt.Errorf("error decrypting message %d: %w", msgType, err))
			return
		}

		if debugEnabled() {
			slog.Debug("decrypted request", "msg", msgType, "body", tryDebugNotation(decrypted))
		}

		msg = io.NopCloser(bytes.NewBuffer(decrypted))
	}

	// Handle request message
	h.writeResponse(r.Context(), w, token, msgType, msg)
}

func (h Handler) writeResponse(ctx context.Context, w http.ResponseWriter, token string, msgType uint8, msg io.Reader) {
	// Immediately respond to an error
	if msgType == fdo.ErrorMsgType && token != "" {
		ctx := h.Responder.Tokens.TokenContext(ctx, token)
		if err := h.Responder.Tokens.InvalidateToken(ctx); err != nil {
			slog.Warn("invalidating token", "error", err)
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	// Perform business logic of message handling
	newToken, respType, resp := h.Responder.Respond(ctx, token, msgType, msg)

	// Encrypt TO2 messages beginning with 64
	if 64 < respType && respType < fdo.ErrorMsgType {
		_, sess, err := h.Responder.TO2.Session(ctx, newToken)
		if err != nil {
			h.error(w, msgType, err)
			return
		}

		if debugEnabled() {
			body, _ := cbor.Marshal(resp)
			slog.Debug("unencrypted response", "msg", respType, "body", tryDebugNotation(body))
		}

		resp, err = sess.Encrypt(rand.Reader, resp)
		if err != nil {
			h.error(w, msgType, fmt.Errorf("error encrypting message %d: %w", respType, err))
			return
		}
	}

	// Invalidate token when finishing a protocol or erroring
	switch respType {
	case 13, 32, 71, fdo.ErrorMsgType:
		if newToken != "" {
			ctx := h.Responder.Tokens.TokenContext(ctx, newToken)
			if err := h.Responder.Tokens.InvalidateToken(ctx); err != nil {
				slog.Warn("invalidating token", "error", err)
			}
		}
	}

	// Marshal response to get size
	var body bytes.Buffer
	if err := cbor.NewEncoder(&body).Encode(resp); err != nil {
		h.error(w, msgType, fmt.Errorf("error marshaling response message %d: %w", respType, err))
		return
	}

	// Add response headers
	w.Header().Add("Authorization", bearerPrefix+newToken)
	w.Header().Add("Content-Length", strconv.Itoa(body.Len()))
	w.Header().Add("Content-Type", "application/cbor")
	w.Header().Add("Message-Type", strconv.Itoa(int(respType)))
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(body.Bytes()); err != nil {
		h.error(w, msgType, fmt.Errorf("error writing response message %d: %w", respType, err))
		return
	}
}

func (h Handler) error(w http.ResponseWriter, prevMsgType uint8, err error) {
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
