// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package transfer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
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
// The root parameter is the Pull Service Root path (e.g., "/api/v1/pull/vouchers").
// List is at GET {root} and download is at GET {root}/{guid}/download.
func (h *HTTPPullHolder) RegisterHandlers(mux *http.ServeMux, root ...string) {
	prefix := "/api/v1/pull/vouchers"
	if len(root) > 0 && root[0] != "" {
		prefix = strings.TrimRight(root[0], "/")
	}
	mux.HandleFunc("GET "+prefix, h.HandleListVouchers)
	mux.HandleFunc("GET "+prefix+"/{guid}/download", h.HandleDownloadVoucher)
}

// HandleListVouchers handles GET /api/v1/pull/vouchers.
func (h *HTTPPullHolder) HandleListVouchers(w http.ResponseWriter, r *http.Request) {
	fingerprint, err := h.authenticate(r)
	if err != nil {
		h.writeErrorJSON(w, r, http.StatusUnauthorized, err.Error())
		return
	}

	filter := h.parseListFilter(r)

	listResp, err := h.Store.List(r.Context(), fingerprint, filter)
	if err != nil {
		slog.Error("pull holder: list vouchers failed", "error", err)
		h.writeErrorJSON(w, r, http.StatusInternalServerError, "internal error")
		return
	}

	// Apply field selection: if fields param was specified, zero out
	// unrequested optional fields so omitempty drops them from JSON.
	if len(filter.Fields) > 0 {
		allowed := make(map[string]bool, len(filter.Fields))
		for _, f := range filter.Fields {
			allowed[f] = true
		}
		for i := range listResp.Vouchers {
			if !allowed["serial_number"] {
				listResp.Vouchers[i].SerialNumber = ""
			}
			if !allowed["model_number"] {
				listResp.Vouchers[i].ModelNumber = ""
			}
			if !allowed["device_info"] {
				listResp.Vouchers[i].DeviceInfo = ""
			}
			if !allowed["created_at"] {
				listResp.Vouchers[i].CreatedAt = nil
			}
		}
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"vouchers":     listResp.Vouchers,
		"continuation": listResp.Continuation,
		"has_more":     listResp.HasMore,
		"total_count":  listResp.TotalCount,
	})
}

// parseListFilter extracts ListFilter from query parameters.
func (h *HTTPPullHolder) parseListFilter(r *http.Request) ListFilter {
	q := r.URL.Query()
	filter := ListFilter{
		Continuation: q.Get("continuation"),
		Status:       q.Get("status"),
	}

	if sinceStr := q.Get("since"); sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			filter.Since = &t
		}
	}
	if untilStr := q.Get("until"); untilStr != "" {
		if t, err := time.Parse(time.RFC3339, untilStr); err == nil {
			filter.Until = &t
		}
	}
	if limitStr := q.Get("limit"); limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			filter.Limit = n
		}
	}

	if filter.Limit <= 0 {
		filter.Limit = h.DefaultPageSize
		if filter.Limit <= 0 {
			filter.Limit = 50
		}
	}

	if fieldsStr := q.Get("fields"); fieldsStr != "" {
		for _, f := range strings.Split(fieldsStr, ",") {
			f = strings.TrimSpace(f)
			if f != "" {
				filter.Fields = append(filter.Fields, f)
			}
		}
	}

	return filter
}

// HandleDownloadVoucher handles GET /api/v1/pull/vouchers/{guid}.
func (h *HTTPPullHolder) HandleDownloadVoucher(w http.ResponseWriter, r *http.Request) {
	fingerprint, err := h.authenticate(r)
	if err != nil {
		h.writeErrorJSON(w, r, http.StatusUnauthorized, err.Error())
		return
	}

	guid := r.PathValue("guid")
	if guid == "" {
		h.writeErrorJSON(w, r, http.StatusBadRequest, "missing guid")
		return
	}

	data, err := h.Store.GetVoucher(r.Context(), fingerprint, guid)
	if err != nil {
		slog.Error("pull holder: get voucher failed", "guid", guid, "error", err)
		h.writeErrorJSON(w, r, http.StatusNotFound, "voucher not found")
		return
	}

	if data.Raw != nil {
		hash := sha256.Sum256(data.Raw)
		w.Header().Set("Content-Type", "application/x-fdo-voucher")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", guid+".fdoov"))
		w.Header().Set("Content-Length", strconv.Itoa(len(data.Raw)))
		w.Header().Set("X-FDO-Checksum", "sha256:"+hex.EncodeToString(hash[:]))
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(data.Raw); err != nil {
			http.Error(w, fmt.Sprintf("failed to write response: %v", err), http.StatusInternalServerError)
			return
		}
		return
	}

	// Fallback: encode from Voucher struct
	h.writeErrorJSON(w, r, http.StatusInternalServerError, "voucher raw data not available")
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

// writeErrorJSON writes a JSON error response with a request_id field.
func (h *HTTPPullHolder) writeErrorJSON(w http.ResponseWriter, r *http.Request, status int, msg string) {
	h.writeJSON(w, status, map[string]string{
		"error":      msg,
		"request_id": requestID(r),
	})
}
