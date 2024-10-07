// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package main implements a WASM AIO server example (that would panic with
// real use).
package main

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/syumai/workers"
	_ "github.com/syumai/workers/cloudflare/d1"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/custom"
	fdo_http "github.com/fido-device-onboard/go-fdo/http"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

// Build with tinygo build -target wasm -no-debug -o rv.wasm ./main.go

var connectionString string

func main() {
	dbConn, err := sql.Open("d1", connectionString)
	if err != nil {
		log.Fatal(err)
	}
	if err := sqlite.Init(dbConn); err != nil {
		log.Fatal(err)
	}
	db := sqlite.New(dbConn)
	workers.Serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(&fdo_http.Handler{
			DIResponder:  &fdo.DIServer[custom.DeviceMfgInfo]{Session: db},
			TO0Responder: &fdo.TO0Server{Session: db},
			TO1Responder: &fdo.TO1Server{Session: db},
			// TO2Server uses goroutines and cannot be compiled with TinyGo
		}).ServeHTTP(w, r)
	}))
}
