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
	"strings"

	"github.com/fido-device-onboard/go-fdo/http/internal/httputil"
)

func debugRequest(w http.ResponseWriter, r *http.Request, handler http.HandlerFunc) {
	if !debugEnabled() {
		handler(w, r)
		return
	}

	// Dump request
	debugReq, _ := dumpRequest(r)
	var saveBody bytes.Buffer
	if _, err := saveBody.ReadFrom(r.Body); err == nil {
		r.Body = io.NopCloser(&saveBody)
	}
	slog.Debug("request", "dump", string(bytes.TrimSpace(debugReq)),
		"body", tryDebugNotation(saveBody.Bytes()))

	// Dump response
	rr := new(httputil.ResponseRecorder)
	handler(rr, r)
	resp := rr.Result()
	debugResp, _ := dumpResponse(resp)
	respBody, _ := io.ReadAll(resp.Body)
	slog.Debug("response", "dump", string(bytes.TrimSpace(debugResp)),
		"body", tryDebugNotation(respBody))

	// Copy recorded response into response writer
	for key, values := range rr.Header() {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
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

	_, _ = io.WriteString(&out, "\r\n")

	return out.Bytes(), nil
}

var errNoBody = fmt.Errorf("no body")

type failureToReadBody struct{}

func (failureToReadBody) Read([]byte) (int, error) { return 0, errNoBody }
func (failureToReadBody) Close() error             { return nil }

func dumpResponse(resp *http.Response) ([]byte, error) {
	saveBody := resp.Body
	defer func() { resp.Body = saveBody }()

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
