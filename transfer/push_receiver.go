// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package transfer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	fdo "github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
)

// maxPushVoucherSize is the maximum size of a pushed voucher (10 MB).
const maxPushVoucherSize = 10 * 1024 * 1024

// PushReceiverAuth is a callback to authenticate incoming push requests.
// Returns true if the request is authenticated.
type PushReceiverAuth func(r *http.Request) bool

// HTTPPushReceiver implements PushReceiver as an HTTP handler.
type HTTPPushReceiver struct {
	// Store persists received vouchers.
	Store VoucherStore

	// Authenticate validates incoming requests. If nil, all requests are accepted.
	Authenticate PushReceiverAuth

	// OnReceive is an optional callback invoked after a voucher is successfully stored.
	// It can be used to trigger downstream processing (e.g., sign-over, forwarding).
	OnReceive func(ctx context.Context, data *VoucherData, storagePath string)
}

// ServeHTTP handles incoming push requests.
func (h *HTTPPushReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method != http.MethodPost {
		h.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if h.Authenticate != nil && !h.Authenticate(r) {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	if err := r.ParseMultipartForm(maxPushVoucherSize); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to parse multipart data"})
		return
	}

	file, _, err := r.FormFile("voucher")
	if err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing voucher file"})
		return
	}
	defer func() {
		if err := file.Close(); err != nil {
			slog.Error("failed to close file", "error", err)
		}
	}()

	raw, err := io.ReadAll(io.LimitReader(file, maxPushVoucherSize))
	if err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read voucher"})
		return
	}

	// Decode the voucher
	var ov fdo.Voucher
	if err := cbor.Unmarshal(raw, &ov); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid voucher format: " + err.Error()})
		return
	}

	guid := fmt.Sprintf("%x", ov.Header.Val.GUID[:])
	data := &VoucherData{
		VoucherInfo: VoucherInfo{
			GUID:         guid,
			SerialNumber: r.FormValue("serial"),
			ModelNumber:  r.FormValue("model"),
			DeviceInfo:   ov.Header.Val.DeviceInfo,
		},
		Voucher: &ov,
		Raw:     raw,
	}

	storagePath, err := h.Store.Save(ctx, data)
	if err != nil {
		slog.Error("push receiver: failed to store voucher", "guid", guid, "error", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to store voucher"})
		return
	}

	slog.Info("push receiver: voucher stored", "guid", guid, "path", storagePath)

	if h.OnReceive != nil {
		go h.OnReceive(ctx, data, storagePath)
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "accepted",
		"voucher_id": guid,
		"message":    "voucher received and stored",
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *HTTPPushReceiver) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode response: %v", err), http.StatusInternalServerError)
	}
}
