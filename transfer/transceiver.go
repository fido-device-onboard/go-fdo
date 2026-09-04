// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package transfer

import (
	"context"
	"time"

	fdo "github.com/fido-device-onboard/go-fdo"
)

// VoucherInfo contains metadata about a voucher available for transfer.
type VoucherInfo struct {
	GUID         string     `json:"voucher_id"`
	SerialNumber string     `json:"serial_number,omitempty"`
	ModelNumber  string     `json:"model_number,omitempty"`
	DeviceInfo   string     `json:"device_info,omitempty"`
	CreatedAt    *time.Time `json:"created_at,omitempty"`
}

// VoucherData contains a voucher and its metadata for transfer.
type VoucherData struct {
	VoucherInfo
	Voucher *fdo.Voucher
	Raw     []byte // CBOR-encoded voucher bytes
}

// PushSender sends vouchers to a remote receiver via HTTP push.
type PushSender interface {
	// Push uploads a single voucher to the destination.
	Push(ctx context.Context, dest PushDestination, data *VoucherData) error
}

// PushDestination describes where to push a voucher.
type PushDestination struct {
	URL   string
	Token string // Bearer token for authentication
}

// PushReceiver accepts vouchers pushed by a remote sender.
type PushReceiver interface {
	// Receive processes an incoming voucher. Implementations should validate,
	// store, and optionally forward the voucher.
	Receive(ctx context.Context, data *VoucherData, sourceIP string) error
}

// PullInitiator authenticates to a Server and downloads vouchers.
type PullInitiator interface {
	// Authenticate performs the FDOKeyAuth handshake and returns a session token.
	Authenticate(ctx context.Context) (*FDOKeyAuthClientResult, error)

	// ListVouchers retrieves the list of available vouchers using the session token.
	ListVouchers(ctx context.Context, token string, filter ListFilter) (*VoucherListResponse, error)

	// DownloadVoucher downloads a single voucher by GUID using the session token.
	DownloadVoucher(ctx context.Context, token string, guid string) (*VoucherData, error)

	// PullAll performs authentication, then downloads all available vouchers.
	// Returns the list of successfully downloaded vouchers.
	PullAll(ctx context.Context) ([]*VoucherData, error)
}

// ListFilter contains query parameters for listing vouchers per the Pull API spec.
type ListFilter struct {
	Since        *time.Time // return vouchers created after this time
	Until        *time.Time // return vouchers created before this time
	Status       string     // filter by status: "pending", "downloaded", "all" (default: "pending")
	Limit        int        // max vouchers to return; 0 means use server default
	Continuation string     // opaque continuation token from a previous response
	Fields       []string   // if non-empty, only include these fields (voucher_id is always included)
}

// VoucherListResponse is the response from a voucher list endpoint.
type VoucherListResponse struct {
	Vouchers     []VoucherInfo
	Continuation string // opaque token for pagination; empty if no more pages
	HasMore      bool   // true if more pages are available
	TotalCount   uint
}

// PullHolder serves vouchers to authenticated Recipients.
type PullHolder interface {
	// VouchersForKey returns voucher metadata for vouchers signed to the given owner key fingerprint.
	VouchersForKey(ctx context.Context, ownerKeyFingerprint []byte, filter ListFilter) (*VoucherListResponse, error)

	// GetVoucher returns a single voucher by GUID, scoped to the authenticated owner key.
	GetVoucher(ctx context.Context, ownerKeyFingerprint []byte, guid string) (*VoucherData, error)
}

// VoucherStore is the storage interface used by both push and pull implementations.
// Implementations may use file-based, database, or in-memory storage.
type VoucherStore interface {
	// Save persists a voucher and returns its storage path/identifier.
	Save(ctx context.Context, data *VoucherData) (string, error)

	// Load retrieves a voucher by GUID.
	Load(ctx context.Context, guid string) (*VoucherData, error)

	// GetVoucher retrieves a voucher by GUID, scoped to the given owner key fingerprint.
	// Returns an error if the voucher does not exist or does not belong to the owner.
	GetVoucher(ctx context.Context, ownerKeyFingerprint []byte, guid string) (*VoucherData, error)

	// List returns voucher metadata, optionally filtered by owner key fingerprint and ListFilter.
	List(ctx context.Context, ownerKeyFingerprint []byte, filter ListFilter) (*VoucherListResponse, error)

	// Delete removes a voucher by GUID.
	Delete(ctx context.Context, guid string) error
}
