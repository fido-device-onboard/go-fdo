// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

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

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// Protocol is the FDO specification-defined protocol.
type Protocol uint8

const (
	UnknownProtocol Protocol = iota
	DIProtocol
	TO0Protocol
	TO1Protocol
	TO2Protocol
	AnyProtocol // for error message types
)

// ProtocolOf returns the protocol a given message type belongs to.
func ProtocolOf(msgType uint8) Protocol {
	switch msgType {
	case 10, 11, 12, 13:
		return DIProtocol
	case 20, 21, 22, 23:
		return TO0Protocol
	case 30, 31, 32, 33:
		return TO1Protocol
	case 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71:
		return TO2Protocol
	case 255:
		return AnyProtocol
	default:
		return UnknownProtocol
	}
}

// AuthorizationJar stores authorization tokens. Context parameters are used to
// allow passing arbitrary data which may be needed for thread-safe
// implementations.
type AuthorizationJar interface {
	Clear(ctx context.Context)
	GetToken(ctx context.Context, msgType uint8) string
	StoreToken(ctx context.Context, msgType uint8, token string)
}

// The default AuthorizationJar implementation which does not support
// concurrent use.
type jar map[Protocol]string

var _ AuthorizationJar = jar(nil)

func (j jar) Clear(context.Context) {
	clear(j)
}
func (j jar) GetToken(_ context.Context, msgType uint8) string {
	return j[ProtocolOf(msgType)]
}
func (j jar) StoreToken(_ context.Context, msgType uint8, token string) {
	j[ProtocolOf(msgType)] = token
}

// Client implements FDO message sending capabilities over HTTP. Send may be
// used for sending one message and receiving one response message. Higher
// level protocols may also be run using the respective methods.
type Client struct {
	// Http client to use. Nil indicates that the default client should be
	// used.
	Http *http.Client

	// BaseURL of HTTP endpoint. The URL should not end in a forward slash and
	// should not include the /fdo/$ver/msg part of the path.
	BaseURL string

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

	// Retry optionally sets a policy for retrying protocol messages.
	Retry RetryDecider
}

// SendOnce sends a single message and receives a single response message. The
// message is never retried, even if the Retry field is set.
func (c *Client) SendOnce(ctx context.Context, msgType uint8, msg any) (respType uint8, _ io.ReadCloser, _ error) {
	// Initialize default values
	if c.Auth == nil {
		c.Auth = make(jar)
	}
	if c.Retry == nil {
		c.Retry = neverRetry{}
	}

	// Create request with URL and body
	uri, err := url.JoinPath(c.BaseURL, "fdo/101/msg", strconv.Itoa(int(msgType)))
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
	if token := c.Auth.GetToken(ctx, msgType); token != "" {
		req.Header.Add("Authorization", token)
	}

	// Perform HTTP request
	res, err := c.Http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("error making HTTP request for message %d: %w", msgType, err)
	}

	return c.handleResponse(res)
}

func (c *Client) handleResponse(resp *http.Response) (msgType uint8, _ io.ReadCloser, _ error) {
	// Store token header in AuthorizationJar
	if token := resp.Header.Get("Authorization"); token != "" {
		reqType, err := strconv.ParseUint(path.Base(resp.Request.URL.Path), 10, 8)
		if err != nil {
			_ = resp.Body.Close()
			return 0, nil, fmt.Errorf("request contains invalid message type in path: %w", err)
		}
		c.Auth.StoreToken(resp.Request.Context(), uint8(reqType), token)
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
	maxSize := c.MaxContentLength
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
