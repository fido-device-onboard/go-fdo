// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

// Package transfer implements the Voucher Transfer Protocol for FIDO Device
// Onboard (FDO), including both push and pull models.
//
// The pull model includes the PullAuth protocol, a cryptographic
// challenge-response handshake that allows a Voucher Recipient to authenticate
// to a Voucher Holder by proving possession of an Owner Key (or authorized
// Delegate Key). This protocol uses CBOR encoding for all authentication
// messages and COSE_Sign1 for signatures, consistent with the FDO protocol
// itself.
//
// The push model provides HTTP-based voucher upload from a sender to a
// receiver.
//
// Both models are unified through the Transceiver interface, allowing services
// to participate in voucher transfer as either side of either model.
package transfer
