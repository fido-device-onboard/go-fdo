// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build !tinygo

package http

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strconv"
)

func msgTypeFromPath(w http.ResponseWriter, r *http.Request) (uint8, bool) {
	typ, err := strconv.ParseUint(r.PathValue("msg"), 10, 8)
	if err != nil {
		writeErr(w, 0, fmt.Errorf("invalid message type"))
		return 0, false
	}
	return uint8(typ), true
}

func debugRequest(w http.ResponseWriter, r *http.Request, handler http.HandlerFunc) {
	if !debugEnabled() {
		handler.ServeHTTP(w, r)
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
	handler(rr, r)
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

func debugRequestOut(req *http.Request, body *bytes.Buffer) {
	if !debugEnabled() {
		return
	}
	debugReq, _ := httputil.DumpRequestOut(req, false)
	slog.Debug("request", "dump", string(bytes.TrimSpace(debugReq)),
		"body", tryDebugNotation(body.Bytes()))
}

func debugResponse(resp *http.Response) {
	if !debugEnabled() {
		return
	}
	debugResp, _ := httputil.DumpResponse(resp, false)
	var saveBody bytes.Buffer
	if _, err := saveBody.ReadFrom(resp.Body); err == nil {
		resp.Body = io.NopCloser(&saveBody)
	}
	slog.Debug("response", "dump", string(bytes.TrimSpace(debugResp)),
		"body", tryDebugNotation(saveBody.Bytes()))
}
