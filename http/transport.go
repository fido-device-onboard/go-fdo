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
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/kex"
)

// Transport implements FDO message sending capabilities over HTTP. Send may be
// used for sending one message and receiving one response message.
type Transport struct {
	// Client to use for HTTP requests. Nil indicates that the default client
	// should be used.
	Client *http.Client

	// Auth stores Authorization headers much like a CookieJar in a standard
	// *http.Client stores cookie headers. As specified in Section 4.3, each
	// protocol (TO1, TO2, etc.) generally starts with a message containing no
	// Authorization header and the server responds with one. This header, like
	// a cookie, is used for tracking protocol state on the server side.
	//
	// If no jar is set, then a default jar will be used. The default jar
	// stores tokens based on DI/TO1/TO2 protocol classification of the request
	// message type.
	Auth AuthorizationJar

	// MaxContentLength defaults to 65535. Negative values disable content
	// length checking.
	MaxContentLength int64

	// Debug will dump the request and response to stderr.
	Debug bool
}

var _ fdo.Transport = (*Transport)(nil)

// Send sends a single message and receives a single response message.
//
//nolint:gocyclo
func (t *Transport) Send(ctx context.Context, base string, msgType uint8, msg any, sess kex.Session) (respType uint8, _ io.ReadCloser, _ error) {
	// Initialize default values
	if t.Client == nil {
		t.Client = http.DefaultClient
	}
	if t.Auth == nil {
		t.Auth = make(jar)
	}

	// Encrypt if a key exchange session is provided
	if sess != nil {
		if t.Debug {
			body, _ := cbor.Marshal(msg)
			fmt.Fprintf(os.Stderr, "Unencrypted request body [msg %d]:\n%x\n", msgType, body)
		}
		var err error
		msg, err = sess.Encrypt(rand.Reader, msg)
		if err != nil {
			return 0, nil, fmt.Errorf("error encrypting message %d: %w", msgType, err)
		}
	}

	// Create request with URL and body
	uri, err := url.JoinPath(base, "fdo/101/msg", strconv.Itoa(int(msgType)))
	if err != nil {
		return 0, nil, fmt.Errorf("error parsing base URL: %w", err)
	}
	body := new(bytes.Buffer)
	if err := cbor.NewEncoder(body).Encode(msg); err != nil {
		return 0, nil, fmt.Errorf("error encoding message %d: %w", msgType, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, body)
	if err != nil {
		return 0, nil, fmt.Errorf("error creating FDO request: %w", err)
	}

	// Add request headers
	req.Header.Add("Content-Type", "application/cbor")
	prot := fdo.ProtocolOf(msgType)
	if errMsg, ok := msg.(fdo.ErrorMessage); ok {
		// Error messages use the authorization token for the protocol where
		// failure occurred
		prot = fdo.ProtocolOf(errMsg.PrevMsgType)
	}
	if prot == fdo.UnknownProtocol || prot == fdo.AnyProtocol {
		return 0, nil, fmt.Errorf("invalid message type: unknown protocol or error message not using fdo.ErrorMessage type")
	}
	if token := t.Auth.GetToken(ctx, prot); token != "" {
		req.Header.Add("Authorization", token)
	}

	// Perform HTTP request
	if t.Debug {
		if debugReq, err := httputil.DumpRequestOut(req, false); err == nil {
			fmt.Fprintln(os.Stderr, "Request:", string(debugReq))
		}
		fmt.Fprintf(os.Stderr, "%x\n", body.Bytes())
	}
	resp, err := t.Client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("error making HTTP request for message %d: %w", msgType, err)
	}
	if t.Debug {
		if debugResp, err := httputil.DumpResponse(resp, false); err == nil {
			fmt.Fprintln(os.Stderr, "Response:", string(debugResp))
		}
		var saveBody bytes.Buffer
		if _, err = saveBody.ReadFrom(resp.Body); err == nil {
			fmt.Fprintf(os.Stderr, "%x\n", saveBody.Bytes())
			resp.Body = io.NopCloser(&saveBody)
		}
	}

	return t.handleResponse(resp, sess)
}

//nolint:gocyclo
func (t *Transport) handleResponse(resp *http.Response, sess kex.Session) (msgType uint8, _ io.ReadCloser, _ error) {
	// Store token header in AuthorizationJar
	if token := resp.Header.Get("Authorization"); token != "" {
		reqType, err := strconv.ParseUint(path.Base(resp.Request.URL.Path), 10, 8)
		if err != nil {
			_ = resp.Body.Close()
			return 0, nil, fmt.Errorf("request contains invalid message type in path: %w", err)
		}
		t.Auth.StoreToken(resp.Request.Context(), fdo.ProtocolOf(uint8(reqType)), token)
	}

	// Parse message type from headers (or implicit from response code)
	switch resp.StatusCode {
	case http.StatusOK:
		typ, err := strconv.ParseUint(strings.TrimSpace(resp.Header.Get("Message-Type")), 10, 8)
		if err != nil {
			_ = resp.Body.Close()
			return 0, nil, fmt.Errorf("response contains invalid message type header: %w", err)
		}
		msgType = uint8(typ)
	case http.StatusInternalServerError:
		msgType = 255
	default:
		_ = resp.Body.Close()
		return 0, nil, fmt.Errorf("unexpected HTTP response code: %s", resp.Status)
	}

	// Validate content length
	maxSize := t.MaxContentLength
	if maxSize == 0 {
		maxSize = 65535
	}
	if maxSize > 0 && resp.ContentLength > maxSize {
		_ = resp.Body.Close()
		return 0, nil, fmt.Errorf("content too large (%d bytes)", resp.ContentLength)
	}
	if maxSize > 0 && resp.ContentLength < 0 {
		_ = resp.Body.Close()
		return 0, nil, errors.New("content length must be specified in response headers")
	}
	if resp.ContentLength < 0 {
		return msgType, resp.Body, nil
	}

	// Allow reading up to expected content length
	content := io.ReadCloser(struct {
		io.Reader
		io.Closer
	}{
		Reader: io.LimitReader(resp.Body, resp.ContentLength),
		Closer: resp.Body,
	})

	// Decrypt if a key exchange session is provided for types other than error
	if sess != nil && msgType != fdo.ErrorMsgType {
		defer func() { _ = resp.Body.Close() }()

		decrypted, err := sess.Decrypt(rand.Reader, content)
		if err != nil {
			return 0, nil, fmt.Errorf("error decrypting message %d: %w", msgType, err)
		}

		if t.Debug {
			fmt.Fprintf(os.Stderr, "Decrypted response body [msg %d]:\n%x\n", msgType, decrypted)
		}

		content = io.NopCloser(bytes.NewBuffer(decrypted))
	}

	return msgType, content, nil
}
