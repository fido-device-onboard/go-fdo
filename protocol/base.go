// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package protocol

// GUID is implemented as a 128-bit cryptographically strong random number.
//
// The GUID type identifies a Device during onboarding, and is replaced each
// time onboarding is successful in the Transfer Ownership 2 (TO2) protocol.
type GUID [16]byte

// Nonce is a byte array with length (16 bytes) 128-bit Random number.
//
// Nonces are used within FIDO Device Onboard to ensure that signatures are
// create on demand and not replayed (i.e., to ensure the "freshness" of
// signatures). When asymmetric digital signatures are used to prove ownership
// of a private key, as in FIDO Device Onboard, an attacker may try to replay
// previously signed messages, to impersonate the true key owner. A secure
// protocol can detect and thwart a replay attack by attaching a unique value
// to the signed data. In this case, we use a nonce, which is a
// cryptographically secure random number chosen by the other party in the
// connection. Since FIDO Device Onboard contains several signatures, more than
// one nonce is used. The reader may use the number of the nonce type to track
// when a nonce is offered and then subsequently returned.
type Nonce [16]byte
