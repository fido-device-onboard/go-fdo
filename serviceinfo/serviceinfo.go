// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package serviceinfo handles FDO Service Info and Service Info Modules
// (FSIMs).
package serviceinfo

// DefaultMTU for service info when Max(Owner|Device)ServiceInfoSz is null.
const DefaultMTU = 1300

// KV is a ServiceInfoKV structure.
type KV struct {
	Key string
	Val []byte
}
