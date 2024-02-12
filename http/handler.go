// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package http

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/kex"
)

const bearerPrefix = "Bearer "

// Handler implements http.Handler and responds to all DI, TO1, and TO2 message
// types.
type Handler struct {
	fdo.Responder

	// Session returns the given key exchange/encryption session based on an
	// opaque "authorization" token.
	Session func(ctx context.Context, token string) (kex.Session, error)

	// MaxContentLength defaults to 65535. Negative values disable content
	// length checking.
	MaxContentLength int64

	// Debug will dump the request and response to stderr.
	Debug bool
}

var _ http.Handler = (*Handler)(nil)

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.Debug {
		h.handleRequest(w, r)
	}

	// Dump request
	if debugReq, err := httputil.DumpRequest(r, false); err == nil {
		fmt.Fprintln(os.Stderr, "Request:", string(debugReq))
	}
	var saveBody bytes.Buffer
	if _, err := saveBody.ReadFrom(r.Body); err == nil {
		fmt.Fprintf(os.Stderr, "%x\n", saveBody.Bytes())
		r.Body = io.NopCloser(&saveBody)
	}

	// Dump response
	rr := httptest.NewRecorder()
	h.handleRequest(rr, r)
	if debugResp, err := httputil.DumpResponse(rr.Result(), false); err == nil {
		fmt.Fprintln(os.Stderr, "Response:", string(debugResp))
	}
	fmt.Fprintf(os.Stderr, "%x\n", rr.Body.Bytes())

	// Copy recorded response into response writer
	for key, values := range rr.Header() {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(rr.Code)
	_, _ = w.Write(rr.Body.Bytes())
}

//nolint:gocyclo
func (h Handler) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Parse message type from request URL
	typ, err := strconv.ParseUint(path.Base(r.URL.Path), 10, 8)
	if err != nil {
		h.error(w, fmt.Errorf("invalid message type"))
		return
	}
	msgType := uint8(typ)

	// Parse request headers
	token := r.Header.Get("Authorization")
	if token != "" && !strings.HasPrefix(token, bearerPrefix) {
		h.error(w, fmt.Errorf("invalid bearer token"))
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
		h.error(w, fmt.Errorf("content too large (%d bytes)", r.ContentLength))
		return
	}
	if maxSize > 0 && r.ContentLength < 0 {
		_ = r.Body.Close()
		h.error(w, errors.New("content length must be specified in request headers"))
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

	// Decrypt message when appropriate
	sess, err := h.Session(r.Context(), token)
	if err != nil {
		h.error(w, err)
		return
	}
	if sess != nil && msgType != fdo.ErrorMsgType {
		defer func() { _ = r.Body.Close() }()

		decrypted, err := sess.Decrypt(rand.Reader, msg)
		if err != nil {
			h.error(w, fmt.Errorf("error decrypting message %d: %w", msgType, err))
			return
		}

		if h.Debug {
			fmt.Fprintf(os.Stderr, "Decrypted request body [msg %d]:\n%x\n", msgType, decrypted)
		}

		msg = io.NopCloser(bytes.NewBuffer(decrypted))
	}

	// Handle request message
	h.writeResponse(r.Context(), w, token, msgType, msg, sess)
}

//nolint:gocyclo
func (h Handler) writeResponse(ctx context.Context, w http.ResponseWriter, token string, msgType uint8, msg io.Reader, sess kex.Session) {
	// Perform business logic of message handling
	token, respType, resp, err := h.Respond(ctx, token, msgType, msg)
	if err != nil {
		h.error(w, err)
		return
	}

	// Encrypt as needed
	if sess != nil && respType != fdo.ErrorMsgType {
		if h.Debug {
			body, _ := cbor.Marshal(resp)
			fmt.Fprintf(os.Stderr, "Unencrypted response body [msg %d]:\n%x\n", respType, body)
		}
		var err error
		resp, err = sess.Encrypt(rand.Reader, resp)
		if err != nil {
			h.error(w, fmt.Errorf("error encrypting message %d: %w", respType, err))
			return
		}
	}

	// Marshal response to get size
	var body bytes.Buffer
	if err := cbor.NewEncoder(&body).Encode(resp); err != nil {
		h.error(w, fmt.Errorf("error marshaling response message %d: %w", respType, err))
		return
	}

	// Add response headers
	w.Header().Add("Authorization", bearerPrefix+token)
	w.Header().Add("Content-Length", strconv.Itoa(body.Len()))
	w.Header().Add("Content-Type", "application/cbor")
	w.Header().Add("Message-Type", strconv.Itoa(int(respType)))

	if _, err := w.Write(body.Bytes()); err != nil {
		h.error(w, fmt.Errorf("error writing response message %d: %w", respType, err))
		return
	}
}

func (h Handler) error(rw http.ResponseWriter, err error) {
	// TODO: Write error message
}
