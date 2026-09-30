// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package did

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"
)

// Handler serves DID Documents via HTTP.
// It serves the document at /.well-known/did.json (for root did:web)
// and optionally at /{path}/did.json (for path-based did:web).
type Handler struct {
	mu       sync.RWMutex
	document *Document
	jsonData []byte
}

// NewHandler creates a DID Document HTTP handler.
func NewHandler(doc *Document) (*Handler, error) {
	h := &Handler{}
	if err := h.SetDocument(doc); err != nil {
		return nil, err
	}
	return h, nil
}

// SetDocument updates the served DID Document. Thread-safe.
func (h *Handler) SetDocument(doc *Document) error {
	if doc == nil {
		return nil
	}
	data, err := doc.JSON()
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.document = doc
	h.jsonData = data
	return nil
}

// ServeHTTP serves the DID Document as JSON.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.mu.RLock()
	data := h.jsonData
	h.mu.RUnlock()

	if data == nil {
		http.Error(w, "DID document not configured", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/did+ld+json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		http.Error(w, fmt.Sprintf("failed to write response: %v", err), http.StatusInternalServerError)
		return
	}
}

// RegisterHandlers registers the DID Document handler on the given mux.
// It registers both the well-known path and an optional sub-path.
func (h *Handler) RegisterHandlers(mux *http.ServeMux, subPath string) {
	mux.Handle("GET /.well-known/did.json", h)
	if subPath != "" {
		mux.Handle("GET /"+subPath+"/did.json", h)
	}
	slog.Info("DID document handler registered",
		"well_known", "/.well-known/did.json",
		"sub_path", subPath,
	)
}
