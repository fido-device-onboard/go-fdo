// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package transfer

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// requestID returns a request identifier for error responses.
// If the HTTP request contains an X-Request-ID header, that value is echoed back.
// Otherwise, a short random hex string is generated.
func requestID(r *http.Request) string {
	if r != nil {
		if id := r.Header.Get("X-Request-ID"); id != "" {
			return id
		}
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b)
}
