// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package serviceinfo handles FDO Service Info and Service Info Modules
// (FSIMs).
package serviceinfo

import "fmt"

// DefaultMTU for service info when Max(Owner|Device)ServiceInfoSz is null.
const DefaultMTU = 1300

// KV is a ServiceInfoKV structure.
type KV struct {
	Key string
	Val []byte
}

func (kv *KV) String() string {
	return fmt.Sprintf("[Key=%q,Val=% x]", kv.Key, kv.Val)
}

// Size calculates the number of bytes once marshaled to CBOR.
func (kv *KV) Size() uint16 {
	size := 1 // header for overall KV structure
	size += cborEncodedLen([]byte(kv.Key))
	size += cborEncodedLen([]byte(kv.Val))
	return uint16(size)
}

func cborEncodedLen(b []byte) int {
	if len(b) > 65535 {
		panic("KV cannot have length > max uint16")
	}
	switch {
	case len(b) < 24:
		return 1 + len(b)
	case len(b) < 256:
		return 2 + len(b)
	default:
		return 3 + len(b)
	}
}
