// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package transfer

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// TokenValidator validates a Bearer token and returns the owner key fingerprint
// it is scoped to. Returns an error if the token is invalid or expired.
type TokenValidator func(token string) (ownerKeyFingerprint []byte, err error)

// HTTPPullHolder serves vouchers to authenticated Recipients via the Pull API.
// It handles the JSON-based list/download endpoints that follow PullAuth.
type HTTPPullHolder struct {
	// Store provides access to vouchers.
	Store VoucherStore

	// ValidateToken checks the Bearer token and returns the owner key fingerprint.
	ValidateToken TokenValidator

	// DefaultPageSize is the default number of vouchers per page.
	DefaultPageSize int
}

// RegisterHandlers registers the Pull API HTTP handlers on the given mux.
// These handlers expect a valid Bearer token from a completed PullAuth handshake.
func (h *HTTPPullHolder) RegisterHandlers(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/pull/vouchers", h.HandleListVouchers)
	mux.HandleFunc("GET /api/v1/pull/vouchers/{guid}", h.HandleDownloadVoucher)
}

// HandleListVouchers handles GET /api/v1/pull/vouchers.
func (h *HTTPPullHolder) HandleListVouchers(w http.ResponseWriter, r *http.Request) {
	fingerprint, err := h.authenticate(r)
	if err != nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	continuation := r.URL.Query().Get("continuation")
	limit := h.DefaultPageSize
	if limit <= 0 {
		limit = 50
	}

	listResp, err := h.Store.List(r.Context(), fingerprint, continuation, limit)
	if err != nil {
		slog.Error("pull holder: list vouchers failed", "error", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"vouchers":     listResp.Vouchers,
		"continuation": listResp.Continuation,
		"total_count":  listResp.TotalCount,
	})
}

// HandleDownloadVoucher handles GET /api/v1/pull/vouchers/{guid}.
func (h *HTTPPullHolder) HandleDownloadVoucher(w http.ResponseWriter, r *http.Request) {
	fingerprint, err := h.authenticate(r)
	if err != nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}

	guid := r.PathValue("guid")
	if guid == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing guid"})
		return
	}

	data, err := h.Store.GetVoucher(r.Context(), fingerprint, guid)
	if err != nil {
		slog.Error("pull holder: get voucher failed", "guid", guid, "error", err)
		h.writeJSON(w, http.StatusNotFound, map[string]string{"error": "voucher not found"})
		return
	}

	if data.Raw != nil {
		w.Header().Set("Content-Type", ContentTypeCBOR)
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(data.Raw); err != nil {
			http.Error(w, fmt.Sprintf("failed to write response: %v", err), http.StatusInternalServerError)
			return
		}
		return
	}

	// Fallback: encode from Voucher struct
	h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "voucher raw data not available"})
}

// GetVoucher is a convenience method wrapping Store.GetVoucher for the PullHolder interface.
func (h *HTTPPullHolder) GetVoucher(fingerprint []byte, guid string) (*VoucherData, error) {
	return nil, fmt.Errorf("use Store.GetVoucher directly")
}

// authenticate extracts and validates the Bearer token from the request.
func (h *HTTPPullHolder) authenticate(r *http.Request) ([]byte, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, fmt.Errorf("missing or invalid Authorization header")
	}
	token := strings.TrimPrefix(auth, "Bearer ")

	if h.ValidateToken == nil {
		return nil, fmt.Errorf("token validator not configured")
	}

	fingerprint, err := h.ValidateToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	return fingerprint, nil
}

func (h *HTTPPullHolder) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, fmt.Sprintf("failed to encode response: %v", err), http.StatusInternalServerError)
	}
}
