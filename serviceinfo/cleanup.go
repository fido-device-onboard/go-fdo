// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package serviceinfo

import "context"

// Cleanup is an optional interface that OwnerModule implementations may
// implement to clean up internal resources when TO2 completes or fails.
//
// This is useful for modules that hold private state such as temp files,
// open file handles, or channels that cannot be cleaned up externally.
//
// The error parameter indicates whether TO2 completed successfully (nil)
// or failed (non-nil). Implementations can use this to decide whether to
// keep or remove resources. For example, an upload module may delete its
// temp file on failure but keep it on success.
type Cleanup interface {
	Cleanup(ctx context.Context, err error)
}
