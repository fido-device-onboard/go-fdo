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

// Size calculates the number of bytes once marshaled to CBOR.
func (kv *KV) Size() uint16 {
	size := 1 // header for overall KV structure
	size += headerLen([]byte(kv.Key))
	size += len(kv.Key)
	size += headerLen(kv.Val)
	size += len(kv.Val)
	return uint16(size)
}

func headerLen(bs []byte) int {
	if len(bs) > 65535 {
		panic("KV cannot have length > max uint16")
	}
	switch {
	case len(bs) < 24:
		return 1
	case len(bs) < 256:
		return 2
	default:
		return 3
	}
}
