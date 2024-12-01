// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package httputil implements APIs misssing from the TinyGo stdlib.
package httputil

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
)

// ResponseRecorder implements a simplfied version of the same type in the Go
// stdlib.
type ResponseRecorder struct {
	body *bytes.Buffer
	code int

	header             http.Header
	headerAtFirstWrite http.Header
	wroteHeader        bool

	result *http.Response
}

// Header implements http.ResponseWriter.
func (rr *ResponseRecorder) Header() http.Header {
	if rr.header == nil {
		rr.header = make(http.Header)
	}
	return rr.header
}

// Write implements http.ResponseWriter.
func (rr *ResponseRecorder) Write(p []byte) (int, error) {
	if !rr.wroteHeader {
		m := rr.Header()
		if _, hasType := m["Content-Type"]; !hasType && m.Get("Transfer-Encoding") == "" {
			m.Set("Content-Type", http.DetectContentType(p))
		}
		rr.WriteHeader(200)
	}
	if rr.body == nil {
		rr.body = bytes.NewBuffer(p)
		return len(p), nil
	}
	return rr.body.Write(p)
}

// WriteHeader implements http.ResponseWriter.
func (rr *ResponseRecorder) WriteHeader(statusCode int) {
	if rr.wroteHeader {
		return
	}

	rr.code = statusCode
	rr.wroteHeader = true
	rr.headerAtFirstWrite = rr.Header().Clone()
}

// Result returns the recorded response.
func (rr *ResponseRecorder) Result() *http.Response {
	if rr.result != nil {
		return rr.result
	}
	if rr.code == 0 {
		rr.code = 200
	}
	if rr.headerAtFirstWrite == nil {
		rr.headerAtFirstWrite = rr.Header().Clone()
	}
	if rr.body == nil {
		rr.body = bytes.NewBuffer([]byte{})
	}

	res := &http.Response{
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		StatusCode: rr.code,
		Header:     rr.headerAtFirstWrite,
	}
	if res.StatusCode == 0 {
		res.StatusCode = 200
	}
	res.Status = fmt.Sprintf("%03d %s", res.StatusCode, http.StatusText(res.StatusCode))
	res.Body = io.NopCloser(bytes.NewReader(rr.body.Bytes()))
	res.ContentLength = func(length string) int64 {
		n, err := strconv.ParseUint(strings.TrimSpace(length), 10, 63)
		if err != nil {
			return -1
		}
		if n > math.MaxInt64 {
			panic("unreachable")
		}
		return int64(n)
	}(res.Header.Get("Content-Length"))
	// Trailers are not used in FDO

	rr.result = res
	return res
}
