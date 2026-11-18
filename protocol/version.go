// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package protocol

import "context"

// Version represents an FDO protocol version.
type Version uint16

// Supported FDO protocol versions
const (
	Version101 Version = 101 // FDO 1.0/1.1
	Version200 Version = 200 // FDO 2.0
)

// String returns the version as a string (e.g., "101", "200").
func (v Version) String() string {
	switch v {
	case Version101:
		return "101"
	case Version200:
		return "200"
	default:
		return "unknown"
	}
}

// IsValid returns true if the version is a known FDO version.
func (v Version) IsValid() bool {
	return v == Version101 || v == Version200
}

// versionContextKey is the context key for FDO version.
type versionContextKey struct{}

// ContextWithVersion returns a new context with the FDO version set.
func ContextWithVersion(ctx context.Context, version Version) context.Context {
	return context.WithValue(ctx, versionContextKey{}, version)
}

// VersionFromContext returns the FDO version from the context.
// Returns Version101 as default if not set.
func VersionFromContext(ctx context.Context) Version {
	if v, ok := ctx.Value(versionContextKey{}).(Version); ok {
		return v
	}
	return Version101
}
