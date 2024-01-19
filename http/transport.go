// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package http

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
)

// Transport implements FDO message sending capabilities over HTTP. Send may be
// used for sending one message and receiving one response message.
type Transport struct {
	// Client to use for HTTP requests. Nil indicates that the default client
	// should be used.
	Client *http.Client

	// Base URL including scheme. e.g. https://example.com/something_or_not
	Base string

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
}

var _ fdo.Transport = (*Transport)(nil)

// Send sends a single message and receives a single response message.
func (t *Transport) Send(ctx context.Context, msgType uint8, msg any) (respType uint8, _ io.ReadCloser, _ error) {
	// Initialize default values
	if t.Client == nil {
		t.Client = http.DefaultClient
	}
	if t.Auth == nil {
		t.Auth = make(jar)
	}

	// Create request with URL and body
	uri, err := url.JoinPath(t.Base, "fdo/101/msg", strconv.Itoa(int(msgType)))
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
	if token := t.Auth.GetToken(ctx, fdo.ProtocolOf(msgType)); token != "" {
		req.Header.Add("Authorization", token)
	}

	// Perform HTTP request
	res, err := t.Client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("error making HTTP request for message %d: %w", msgType, err)
	}

	return t.handleResponse(res)
}

func (t *Transport) handleResponse(resp *http.Response) (msgType uint8, _ io.ReadCloser, _ error) {
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
	content := struct {
		io.Reader
		io.Closer
	}{
		Reader: io.LimitReader(resp.Body, resp.ContentLength),
		Closer: resp.Body,
	}
	return msgType, content, nil
}

// ResetContext clears the protocol state, e.g. the session authorization token.
func (t *Transport) ResetContext(prot fdo.Protocol) {
	t.Auth.Clear(context.Background(), prot)
}
