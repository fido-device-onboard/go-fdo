// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build tinygo

// Package main implements a Rendezvous Server which can be compiled with
// TinyGo and run on Cloudflare Workers within the free tier (under reasonable
// load).
package main

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/syumai/workers"
	"github.com/syumai/workers/cloudflare/cron"
	_ "github.com/syumai/workers/cloudflare/d1"

	"github.com/fido-device-onboard/go-fdo"
	fdo_http "github.com/fido-device-onboard/go-fdo/http"
	"github.com/fido-device-onboard/go-fdo/sqlite"
)

const oneWeekInSeconds uint32 = 7 * 24 * 60 * 60

func main() {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	db, err := sql.Open("d1", "RendezvousDB")
	if err != nil {
		slog.Error("d1 connect", "error", err)
		os.Exit(1)
	}
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		slog.Error("d1 pragma", "error", err)
		os.Exit(1)
	}

	// Handle FDO protocol endpoint
	state := sqlite.New(db)
	handler := http.NewServeMux()

	// If building with Go instead of TinyGo, use:
	//handler.Handle("POST /fdo/101/msg/{msg}", &fdo_http.Handler{
	handler.Handle("/fdo/101/msg/", &fdo_http.Handler{
		Tokens: state,
		TO0Responder: &fdo.TO0Server{
			Session: state,
			RVBlobs: state,
			AcceptVoucher: func(ctx context.Context, ov fdo.Voucher) (accept bool, err error) {
				owner, err := ov.OwnerPublicKey()
				if err != nil {
					return false, fmt.Errorf("error getting voucher owner key: %w", err)
				}
				der, err := x509.MarshalPKIXPublicKey(owner)
				if err != nil {
					return false, fmt.Errorf("error marshaling voucher owner key: %w", err)
				}
				return trustedOwner(ctx, db, der)
			},
			NegotiateTTL: func(requestedSeconds uint32, ov fdo.Voucher) (waitSeconds uint32) {
				return min(requestedSeconds, oneWeekInSeconds)
			},
		},
		TO1Responder: &fdo.TO1Server{
			Session: state,
			RVBlobs: state,
		},
	})

	// Schedule a daily task to cleanup expired RV blobs
	cron.ScheduleTaskNonBlock(func(ctx context.Context) error {
		e, err := cron.NewEvent(ctx)
		if err != nil {
			return err
		}
		return removeExpiredBlobs(ctx, db, e.ScheduledTime)
	})

	workers.Serve(handler)
}

func trustedOwner(ctx context.Context, db *sql.DB, pkixKey []byte) (bool, error) {
	var email string
	row := db.QueryRowContext(ctx, `SELECT email FROM trusted_owners WHERE pkix = ?`, pkixKey)
	if err := row.Scan(&email); errors.Is(err, sql.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	slog.Info("accepting voucher", "user", email)

	return true, nil
}

func removeExpiredBlobs(ctx context.Context, db *sql.DB, nowish time.Time) error {
	_, err := db.ExecContext(ctx, `DELETE FROM rv_blobs WHERE exp < ?`, nowish.Unix())
	return err
}
