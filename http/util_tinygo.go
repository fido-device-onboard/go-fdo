// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build tinygo

package http

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
)

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

func debugRequest(w http.ResponseWriter, r *http.Request, handler http.HandlerFunc) {
	// Dump request
	debugReq, _ := dumpRequest(r)
	var saveBody bytes.Buffer
	if _, err := saveBody.ReadFrom(r.Body); err == nil {
		r.Body = io.NopCloser(&saveBody)
	}
	slog.Debug("request", "dump", string(bytes.TrimSpace(debugReq)),
		"body", tryDebugNotation(saveBody.Bytes()))

	// Dump response
	rr := new(responseRecorder)
	handler(rr, r)
	resp := rr.Result()
	debugResp, _ := dumpResponse(resp)
	slog.Debug("response", "dump", string(bytes.TrimSpace(debugResp)),
		"body", tryDebugNotation(rr.body.Bytes()))

	// Copy recorded response into response writer
	for key, values := range rr.Header() {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(rr.body.Bytes())
}

func debugRequestOut(req *http.Request, body *bytes.Buffer) {
	if !debugEnabled() {
		return
	}

	// Unlike httputil.DumpRequestOut, this does not use an actual HTTP
	// transport to ensure that the output has all relevant headers updated and
	// canonicalized. Improvements are welcome.
	debugReq, _ := dumpRequest(req)
	slog.Debug("request", "dump", string(bytes.TrimSpace(debugReq)),
		"body", tryDebugNotation(body.Bytes()))
}

func debugResponse(resp *http.Response) {
	if !debugEnabled() {
		return
	}

	var saveBody bytes.Buffer
	if _, err := saveBody.ReadFrom(resp.Body); err == nil {
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(&saveBody)
	}
	debugResp, _ := dumpResponse(resp)
	slog.Debug("response", "dump", string(bytes.TrimSpace(debugResp)),
		"body", tryDebugNotation(saveBody.Bytes()))
}

func dumpRequest(req *http.Request) ([]byte, error) {
	var out bytes.Buffer

	fmt.Fprintf(&out, "%s %s HTTP/%d.%d\r\n", req.Method, req.RequestURI, req.ProtoMajor, req.ProtoMinor)

	absRequestURI := strings.HasPrefix(req.RequestURI, "http://") || strings.HasPrefix(req.RequestURI, "https://")
	if !absRequestURI {
		host := req.Host
		if host == "" && req.URL != nil {
			host = req.URL.Host
		}
		if host != "" {
			fmt.Fprintf(&out, "Host: %s\r\n", host)
		}
	}

	if len(req.TransferEncoding) > 0 {
		fmt.Fprintf(&out, "Transfer-Encoding: %s\r\n", strings.Join(req.TransferEncoding, ","))
	}

	if err := req.Header.WriteSubset(&out, map[string]bool{
		"Transfer-Encoding": true,
		"Trailer":           true,
	}); err != nil {
		return nil, err
	}

	io.WriteString(&out, "\r\n")

	return out.Bytes(), nil
}

var errNoBody = fmt.Errorf("no body")

type failureToReadBody struct{}

func (failureToReadBody) Read([]byte) (int, error) { return 0, errNoBody }
func (failureToReadBody) Close() error             { return nil }

func dumpResponse(resp *http.Response) ([]byte, error) {
	var out bytes.Buffer
	savecl := resp.ContentLength
	if resp.ContentLength == 0 {
		resp.Body = io.NopCloser(strings.NewReader(""))
	} else {
		resp.Body = failureToReadBody{}
	}
	err := resp.Write(&out)
	resp.ContentLength = savecl
	if err != nil && err != errNoBody {
		return nil, err
	}
	return out.Bytes(), nil
}

type responseRecorder struct {
	body *bytes.Buffer
	code int

	header             http.Header
	headerAtFirstWrite http.Header
	wroteHeader        bool

	result *http.Response
}

func (rr *responseRecorder) Header() http.Header {
	if rr.header == nil {
		rr.header = make(http.Header)
	}
	return rr.header
}

func (rr *responseRecorder) Write(p []byte) (int, error) {
	if !rr.wroteHeader {
		m := rr.Header()
		if _, hasType := m["Content-Type"]; !hasType && m.Get("Transfer-Encoding") == "" {
			m.Set("Content-Type", http.DetectContentType(p))
		}
		rr.WriteHeader(200)
	}
	if rr.body == nil {
		rr.body = new(bytes.Buffer)
	}
	return rr.body.Write(p)
}

func (rr *responseRecorder) WriteHeader(statusCode int) {
	if rr.wroteHeader {
		return
	}

	rr.code = statusCode
	rr.wroteHeader = true
	rr.headerAtFirstWrite = rr.Header().Clone()
}

func (rr *responseRecorder) Result() *http.Response {
	if rr.result != nil {
		return rr.result
	}
	if rr.code == 0 {
		rr.code = 200
	}
	if rr.headerAtFirstWrite == nil {
		rr.headerAtFirstWrite = rr.Header().Clone()
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
		return int64(n)
	}(res.Header.Get("Content-Length"))
	// Trailers are not used in FDO

	rr.result = res
	return res
}
