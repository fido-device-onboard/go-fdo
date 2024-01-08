// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"time"
)

// Client implements methods for performing FDO protocols DI (non-normative),
// TO1, and TO2.
type Client struct {
	// Transport performs message passing and may be implemented over TCP,
	// HTTP, CoAP, and others.
	Transport Transport

	// Signer performs COSE sign/verify and HMAC hash/verify functions.
	Signer Signer

	// OwnerServiceBaseAddrs TO2 base address list
	OwnerServiceBaseAddrs func(context.Context) []string

	// ServiceInfoModulesForOwner returns a map of registered FDO Service Info
	// Modules (FSIMs) for a given Owner Service.
	ServiceInfoModulesForOwner func(RVTO2AddrEntry) map[string]ServiceInfoModule

	// Retry optionally sets a policy for retrying protocol messages.
	Retry RetryDecider
}

// DeviceInitialization runs the DI protocol and has side effects of setting
// device credentials.
func (*Client) DeviceInitialization(ctx context.Context) (*DeviceCredential, error) {
	panic("unimplemented")
}

// TransferOwnership1 runs the TO1 protocol and has side effects of setting the
// RV blob for TO2 addresses.
func (*Client) TransferOwnership1(ctx context.Context) error {
	panic("unimplemented")
}

// TransferOwnership2 runs the TO2 protocol and has side effects of performing
// FSIMs.
func (*Client) TransferOwnership2(ctx context.Context) error {
	panic("unimplemented")
}

// RetryDecider allows for deciding whether a retry should occur, based on the
// request's message type and the error response.
type RetryDecider interface {
	// ShouldRetry returns nil when a retry should not be attempted. Otherwise
	// it returns a non-nil channel. The channel will have exactly one value
	// sent on it and is not guaranteed to close.
	//
	// TODO: Return next set of options for RV?
	ShouldRetry(ErrorMessage) <-chan time.Time
}
