// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cbor

import "bytes"

// ArrayShift returns the first element of a CBOR array type (not text or byte
// strings) as unparsed CBOR and the rest as a CBOR-encoded array of one fewer
// elements. Trailing data will be left intact.
//
// If the CBOR data is invalid or not an array, first will be zero length and
// remaining will be equal to the input data.
//
// This function only operates on array major types and not text strings or
// byte strings.
func ArrayShift(data []byte) (first, remaining []byte) {
	if len(data) == 0 {
		panic("data cannot be empty")
	}

	// Immediately return an empty array (with any trailing data)
	if data[0] == 0x80 {
		return nil, data
	}

	// Parse the type info
	highThreeBits, lowFiveBits := data[0]>>5, data[0]&fiveBitMask
	if highThreeBits != arrayMajorType {
		return nil, data
	}
	additional := data[1:]

	// Parse the array length
	var length uint64
	var items *bytes.Buffer
	switch {
	case lowFiveBits < oneByteAdditional:
		length = toU64([]byte{lowFiveBits})
		items = bytes.NewBuffer(additional)
	case lowFiveBits == oneByteAdditional && len(data) >= 1:
		length = toU64(additional[:1])
		items = bytes.NewBuffer(additional[1:])
	case lowFiveBits == twoBytesAdditional && len(data) >= 2:
		length = toU64(additional[:2])
		items = bytes.NewBuffer(additional[2:])
	case lowFiveBits == fourBytesAdditional && len(data) >= 4:
		length = toU64(additional[:4])
		items = bytes.NewBuffer(additional[4:])
	case lowFiveBits == eightBytesAdditional && len(data) >= 8:
		length = toU64(additional[:8])
		items = bytes.NewBuffer(additional[8:])
	default:
		return nil, data
	}

	// Parse the first item from the array contents
	first, err := NewDecoder(items).decodeRaw()
	if err != nil {
		return nil, data
	}

	// Return the first item's CBOR encoding and an array of the remaining data
	// (with length decremented by one)
	return first, append(
		additionalInfo(arrayMajorType, u64Bytes(length-1)),
		items.Bytes()...)
}
