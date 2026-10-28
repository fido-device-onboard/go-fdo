// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

// Package did provides DID (Decentralized Identifier) minting, resolution,
// and serving capabilities for FDO Owner Keys.
//
// It supports:
//   - Generating owner key pairs and exporting them as DID Documents
//   - Serving DID Documents via HTTP (.well-known/did.json for did:web)
//   - Resolving did:web and did:key URIs to public keys and service endpoints
//   - Encoding FDO voucher recipient URLs in DID Document service entries
//
// This package has no external dependencies beyond the Go standard library
// and the go-fdo protocol package.
package did
