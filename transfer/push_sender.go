// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package transfer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"strconv"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// PushError represents an HTTP error from a voucher push attempt.
// It carries the status code and optional Retry-After duration so
// callers can classify transient vs permanent failures.
type PushError struct {
	StatusCode int
	Body       string
	RetryAfter time.Duration // parsed from Retry-After header; zero if absent
}

func (e *PushError) Error() string {
	return fmt.Sprintf("push returned HTTP %d: %s", e.StatusCode, e.Body)
}

// IsTransient returns true for errors that are worth retrying:
// 429 Too Many Requests, 5xx server errors, and network errors.
// 4xx (except 429) are permanent — the request itself is wrong.
func (e *PushError) IsTransient() bool {
	if e.StatusCode == http.StatusTooManyRequests {
		return true
	}
	return e.StatusCode >= 500
}

// parseRetryAfter parses the Retry-After header value.
// Supports both seconds (integer) and HTTP-date formats.
func parseRetryAfter(val string) time.Duration {
	if val == "" {
		return 0
	}
	if secs, err := strconv.Atoi(val); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(val); err == nil {
		d := time.Until(t)
		if d > 0 {
			return d
		}
	}
	return 0
}

// HTTPPushSender implements PushSender using HTTP multipart upload.
type HTTPPushSender struct {
	HTTPClient *http.Client
}

// NewHTTPPushSender creates a push sender with sensible defaults.
func NewHTTPPushSender() *HTTPPushSender {
	return &HTTPPushSender{
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Push uploads a voucher to the destination via HTTP multipart POST.
func (s *HTTPPushSender) Push(ctx context.Context, dest PushDestination, data *VoucherData) error {
	if dest.URL == "" {
		return fmt.Errorf("push destination URL is empty")
	}
	if data == nil || data.Voucher == nil {
		return fmt.Errorf("voucher data is nil")
	}

	// Encode voucher if raw bytes not already available
	raw := data.Raw
	if raw == nil {
		var err error
		raw, err = cbor.Marshal(data.Voucher)
		if err != nil {
			return fmt.Errorf("failed to encode voucher: %w", err)
		}
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	filename := data.GUID + ".fdoov"
	part, err := writer.CreateFormFile("voucher", filename)
	if err != nil {
		return fmt.Errorf("failed to create multipart part: %w", err)
	}
	if _, err := part.Write(raw); err != nil {
		return fmt.Errorf("failed to write voucher data: %w", err)
	}

	if data.SerialNumber != "" {
		_ = writer.WriteField("serial", data.SerialNumber)
	}
	if data.ModelNumber != "" {
		_ = writer.WriteField("model", data.ModelNumber)
	}
	if data.GUID != "" {
		_ = writer.WriteField("guid", data.GUID)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close multipart writer: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dest.URL, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if dest.Token != "" {
		req.Header.Set("Authorization", "Bearer "+dest.Token)
	}

	client := s.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("push request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return &PushError{
			StatusCode: resp.StatusCode,
			Body:       string(respBody),
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
		}
	}

	return nil
}
