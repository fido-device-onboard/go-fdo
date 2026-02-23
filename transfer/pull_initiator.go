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
	"net/url"
	"strconv"
	"time"

	fdo "github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
)

// HTTPPullInitiator implements PullInitiator using PullAuth + JSON Pull API.
type HTTPPullInitiator struct {
	// Auth is the PullAuth client used for authentication.
	Auth *PullAuthClient

	// Store is used to persist downloaded vouchers. If nil, vouchers are
	// returned but not persisted.
	Store VoucherStore
}

// Authenticate performs the PullAuth handshake.
func (p *HTTPPullInitiator) Authenticate(ctx context.Context) (*PullAuthClientResult, error) {
	return p.Auth.Authenticate()
}

// ListVouchers retrieves the list of available vouchers using the session token.
func (p *HTTPPullInitiator) ListVouchers(ctx context.Context, token string, filter ListFilter) (*VoucherListResponse, error) {
	baseURL := p.Auth.BaseURL + "/api/v1/pull/vouchers"
	params := url.Values{}
	if filter.Continuation != "" {
		params.Set("continuation", filter.Continuation)
	}
	if filter.Since != nil {
		params.Set("since", filter.Since.Format(time.RFC3339))
	}
	if filter.Until != nil {
		params.Set("until", filter.Until.Format(time.RFC3339))
	}
	if filter.Status != "" {
		params.Set("status", filter.Status)
	}
	if filter.Limit > 0 {
		params.Set("limit", strconv.Itoa(filter.Limit))
	}
	if encoded := params.Encode(); encoded != "" {
		baseURL += "?" + encoded
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create list request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	client := p.Auth.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list vouchers request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("failed to close response body", "error", err)
		}
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read list response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list vouchers returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var listResp struct {
		Vouchers     []VoucherInfo `json:"vouchers"`
		Continuation string        `json:"continuation"`
		HasMore      bool          `json:"has_more"`
		TotalCount   uint          `json:"total_count"`
	}
	if err := json.Unmarshal(body, &listResp); err != nil {
		return nil, fmt.Errorf("failed to decode list response: %w", err)
	}

	return &VoucherListResponse{
		Vouchers:     listResp.Vouchers,
		Continuation: listResp.Continuation,
		HasMore:      listResp.HasMore,
		TotalCount:   listResp.TotalCount,
	}, nil
}

// DownloadVoucher downloads a single voucher by GUID.
func (p *HTTPPullInitiator) DownloadVoucher(ctx context.Context, token string, guid string) (*VoucherData, error) {
	url := p.Auth.BaseURL + "/api/v1/pull/vouchers/" + guid

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create download request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", ContentTypeCBOR)

	client := p.Auth.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download voucher request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("failed to close response body", "error", err)
		}
	}()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxPushVoucherSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read voucher response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download voucher returned HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var ov fdo.Voucher
	if err := cbor.Unmarshal(raw, &ov); err != nil {
		return nil, fmt.Errorf("failed to decode voucher: %w", err)
	}

	voucherGUID := fmt.Sprintf("%x", ov.Header.Val.GUID[:])
	return &VoucherData{
		VoucherInfo: VoucherInfo{
			GUID:       voucherGUID,
			DeviceInfo: ov.Header.Val.DeviceInfo,
		},
		Voucher: &ov,
		Raw:     raw,
	}, nil
}

// PullAll performs authentication, then downloads all available vouchers.
func (p *HTTPPullInitiator) PullAll(ctx context.Context) ([]*VoucherData, error) {
	// Step 1: Authenticate
	authResult, err := p.Authenticate(ctx)
	if err != nil {
		return nil, fmt.Errorf("pull authentication failed: %w", err)
	}

	slog.Info("pull: authenticated",
		"token_expires", authResult.TokenExpiresAt,
		"voucher_count", authResult.VoucherCount,
	)

	// Step 2: List all vouchers (with pagination)
	var allVouchers []VoucherInfo
	filter := ListFilter{}
	for {
		listResp, err := p.ListVouchers(ctx, authResult.SessionToken, filter)
		if err != nil {
			return nil, fmt.Errorf("pull: list vouchers failed: %w", err)
		}
		allVouchers = append(allVouchers, listResp.Vouchers...)

		if listResp.Continuation == "" {
			break
		}
		filter.Continuation = listResp.Continuation
	}

	slog.Info("pull: listed vouchers", "count", len(allVouchers))

	// Step 3: Download each voucher
	var downloaded []*VoucherData
	for _, vi := range allVouchers {
		data, err := p.DownloadVoucher(ctx, authResult.SessionToken, vi.GUID)
		if err != nil {
			slog.Error("pull: failed to download voucher", "guid", vi.GUID, "error", err)
			continue
		}

		// Persist if store is configured
		if p.Store != nil {
			path, err := p.Store.Save(ctx, data)
			if err != nil {
				slog.Error("pull: failed to store voucher", "guid", vi.GUID, "error", err)
				continue
			}
			slog.Info("pull: voucher stored", "guid", vi.GUID, "path", path)
		}

		downloaded = append(downloaded, data)
	}

	slog.Info("pull: completed", "downloaded", len(downloaded), "total", len(allVouchers))
	return downloaded, nil
}
