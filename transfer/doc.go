// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

// Package transfer implements the Voucher Transfer Protocol for FIDO Device
// Onboard (FDO), including both push and pull models.
//
// Both push and pull models use the FDOKeyAuth protocol, a cryptographic
// challenge-response handshake that allows a Caller to authenticate to a
// Server by proving possession of an enrolled key (Owner Key for pull,
// Supplier Key for push). This protocol uses CBOR encoding for all
// authentication messages and COSE_Sign1 for signatures, consistent with
// the FDO protocol itself.
//
// The pull model provides authenticated voucher listing and download.
// The push model provides authenticated HTTP-based voucher upload.
//
// Both models are unified through common interfaces, allowing services
// to participate in voucher transfer as either side of either model.
package transfer
