// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"context"
	"crypto"
	"crypto/x509"
	"time"
)

// Client implements methods for performing FDO protocols DI (non-normative),
// TO1, and TO2.
type Client struct {
	// Transport performs message passing and may be implemented over TCP,
	// HTTP, CoAP, and others.
	Transport Transport

	// OwnerServiceBaseAddrs TO2 base address list
	OwnerServiceBaseAddrs func(context.Context) []string

	// ServiceInfoModulesForOwner returns a map of registered FDO Service Info
	// Modules (FSIMs) for a given Owner Service.
	ServiceInfoModulesForOwner func(RvTO2Addr) map[string]ServiceInfoModule

	// Retry optionally sets a policy for retrying protocol messages.
	Retry RetryDecider
}

// Generate a CSR
// var guid Guid
// csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
// 	Subject:            pkix.Name{CommonName: fmt.Sprintf("%x.device.fdo", guid)},
// 	SignatureAlgorithm: x509.SHA256WithRSA,
// }, priv)
// if err != nil {
// 	return nil, nil, fmt.Errorf("error generating certificate signing request: %w", err)
// }

// DeviceInitialize runs the DI protocol and returns the voucher header and
// manufacturer public key hash.
func (c *Client) DeviceInitialize(ctx context.Context, id string, chain []*x509.Certificate, priv crypto.Signer, h KeyedHasher) (*VoucherHeader, *Hash, error) {
	panic("unimplemented")
}

// TransferOwnership1 runs the TO1 protocol and has side effects of setting the
// RV blob for TO2 addresses.
func (*Client) TransferOwnership1(ctx context.Context, priv crypto.Signer) error {
	panic("unimplemented")
}

// TransferOwnership2 runs the TO2 protocol and has side effects of performing
// FSIMs.
func (*Client) TransferOwnership2(ctx context.Context, priv crypto.Signer) error {
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
