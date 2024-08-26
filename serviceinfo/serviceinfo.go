// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package serviceinfo handles FDO Service Info and Service Info Modules.
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
	size := uint16(1) // header for overall KV structure
	size += cborEncodedLen([]byte(kv.Key))
	size += cborEncodedLen([]byte(kv.Val))
	return size
}

func cborEncodedLen(b []byte) uint16 {
	length := len(b)
	if length > 65535 {
		panic("KV cannot have length > max uint16")
	}
	switch {
	case length < 24:
		return 1 + uint16(length)
	case length < 256:
		return 2 + uint16(length)
	default:
		return 3 + uint16(length)
	}
}

// ArraySizeCBOR returns the size of the service info slice once marshaled to
// CBOR.
func ArraySizeCBOR(arr []*KV) int64 {
	if len(arr) > 65535 {
		panic("service info cannot contain > 65535 KVs")
	}

	arrayLengthSize := int64(3)
	switch {
	case len(arr) < 24:
		arrayLengthSize = 1
	case len(arr) < 256:
		arrayLengthSize = 2
	}

	var infoSize int64
	for _, info := range arr {
		infoSize += int64(info.Size())
	}
	return arrayLengthSize + infoSize
}
