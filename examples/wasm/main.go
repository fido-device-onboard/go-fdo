// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package main implements a WASM AIO server example (that would panic with
// real use).
package main

import (
	"log"
	"net/http"

	"github.com/syumai/workers"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/custom"
	fdo_http "github.com/fido-device-onboard/go-fdo/http"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

// Build with tinygo build -target wasm -no-debug -o rv.wasm ./main.go

func main() {
	db, err := sqlite.Init(nil)
	if err != nil {
		log.Fatal(err)
	}
	workers.Serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(&fdo_http.Handler{
			DIResponder:  &fdo.DIServer[custom.DeviceMfgInfo]{Session: db},
			TO0Responder: &fdo.TO0Server{Session: db},
			TO1Responder: &fdo.TO1Server{Session: db},
			// TO2Server uses goroutines and cannot be compiled with TinyGo
		}).ServeHTTP(w, r)
	}))
}
