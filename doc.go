// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package fdo implements [FDO 1.1] protocol.
//
// Many of the protocol types and values are located in the protocol
// subpackage. This domain package includes the core "entrypoint" types.
//
// For client devices, [DI] is called, using an HMAC and private key, to
// generate a credential. After this, [TO1] (unless using rendezvous bypass)
// and [TO2] are called successively. When calling [TO2], service info modules
// that the device is capable of performing are provided.
//
// Device secrets (HMAC and private key) use interfaces from the Go standard
// library so there are many ways to generate and provide them. Two
// implementations are included in the library. [blob.DeviceCredential] stores
// secrets in a binary-encoded file and [tpm.DeviceCredential] uses
// unexportable keys secured inside a TPM 2.0.
//
// For owner services, message handling [protocol.Responder] implementations
// are provided: [DIServer], [TO0Server], [TO1Server], and [TO2Server]. These
// require state management.
//
// There are a handful of state management interfaces to allow for combining
// backends. A practical example of this is that one may wish to store some
// state inside a JWT/CWT cookie, while more persistent state (lasts beyond a
// session) is stored in a SQL database. As an example implementation,
// [sqlite.DB] is provided in a separate, optional module, which runs SQLite
// inside a WASM runtime running as part of the same process.
//
// The other type in this package is [Voucher], which represents an FDO
// ownership voucher. It is not the direct input or output of either device or
// owner service protocols, since it is loaded/stored via the persistence
// interfaces. However, it is included for symmetry with [DeviceCredential], as
// the anchor of trust (combined with the associated private key - same as
// device credential) on the opposite end of the device onboarding handshake.
//
// [FDO 1.1]: https://fidoalliance.org/specs/FDO/fido-device-onboard-v1.0-ps-20210323/fido-device-onboard-v1.0-ps-20210323.html
package fdo
