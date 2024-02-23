// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Tests are partially adapted from https://github.com/r4gus/zbor/blob/0.12.2/src/cbor.zig
package cbor_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/blob"
	"github.com/fido-device-onboard/go-fdo/cbor"
)

func TestEncodeInt(t *testing.T) {
	t.Run("int", func(t *testing.T) {
		input := 999
		expect := []byte{0x19, 0x03, 0xe7}

		if got, err := cbor.Marshal(input); err != nil {
			t.Errorf("error marshaling %d: %v", input, err)
		} else if !bytes.Equal(got, expect) {
			t.Errorf("marshaling %d; expected % x, got % x", input, expect, got)
		}
	})

	t.Run("int8", func(t *testing.T) {
		for _, test := range []struct {
			expect []byte
			input  int8
		}{
			{expect: []byte{0x00}, input: 0},
			{expect: []byte{0x20}, input: -1},
			{expect: []byte{0x01}, input: 1},
			{expect: []byte{0x21}, input: -2},
			{expect: []byte{0x17}, input: 23},
			{expect: []byte{0x37}, input: -24},
			{expect: []byte{0x18, 0x18}, input: 24},
			{expect: []byte{0x38, 0x18}, input: -25},
			{expect: []byte{0x18, 0x64}, input: 100},
			{expect: []byte{0x38, 0x64}, input: -101},
		} {
			if got, err := cbor.Marshal(test.input); err != nil {
				t.Errorf("error marshaling %d: %v", test.input, err)
			} else if !bytes.Equal(got, test.expect) {
				t.Errorf("marshaling %d; expected % x, got % x", test.input, test.expect, got)
			}
		}
	})

	t.Run("int16", func(t *testing.T) {
		for _, test := range []struct {
			input  int16
			expect []byte
		}{
			{expect: []byte{0x00}, input: 0},
			{expect: []byte{0x20}, input: -1},
			{expect: []byte{0x01}, input: 1},
			{expect: []byte{0x21}, input: -2},
			{expect: []byte{0x17}, input: 23},
			{expect: []byte{0x37}, input: -24},
			{expect: []byte{0x18, 0x18}, input: 24},
			{expect: []byte{0x38, 0x18}, input: -25},
			{expect: []byte{0x18, 0x64}, input: 100},
			{expect: []byte{0x38, 0x64}, input: -101},
			{expect: []byte{0x19, 0x03, 0xe8}, input: 1000},
			{expect: []byte{0x39, 0x03, 0xe8}, input: -1001},
		} {
			if got, err := cbor.Marshal(test.input); err != nil {
				t.Errorf("error marshaling %d: %v", test.input, err)
			} else if !bytes.Equal(got, test.expect) {
				t.Errorf("marshaling %d; expected % x, got % x", test.input, test.expect, got)
			}
		}
	})

	t.Run("int32", func(t *testing.T) {
		for _, test := range []struct {
			input  int32
			expect []byte
		}{
			{expect: []byte{0x00}, input: 0},
			{expect: []byte{0x20}, input: -1},
			{expect: []byte{0x01}, input: 1},
			{expect: []byte{0x21}, input: -2},
			{expect: []byte{0x17}, input: 23},
			{expect: []byte{0x37}, input: -24},
			{expect: []byte{0x18, 0x18}, input: 24},
			{expect: []byte{0x38, 0x18}, input: -25},
			{expect: []byte{0x18, 0x64}, input: 100},
			{expect: []byte{0x38, 0x64}, input: -101},
			{expect: []byte{0x19, 0x03, 0xe8}, input: 1000},
			{expect: []byte{0x39, 0x03, 0xe8}, input: -1001},
			{expect: []byte{0x1a, 0x00, 0x0f, 0x42, 0x40}, input: 1000000},
			{expect: []byte{0x3a, 0x00, 0x0f, 0x42, 0x40}, input: -1000001},
		} {
			if got, err := cbor.Marshal(test.input); err != nil {
				t.Errorf("error marshaling %d: %v", test.input, err)
			} else if !bytes.Equal(got, test.expect) {
				t.Errorf("marshaling %d; expected % x, got % x", test.input, test.expect, got)
			}
		}
	})

	t.Run("int64", func(t *testing.T) {
		for _, test := range []struct {
			input  int64
			expect []byte
		}{
			{expect: []byte{0x00}, input: 0},
			{expect: []byte{0x20}, input: -1},
			{expect: []byte{0x01}, input: 1},
			{expect: []byte{0x21}, input: -2},
			{expect: []byte{0x17}, input: 23},
			{expect: []byte{0x37}, input: -24},
			{expect: []byte{0x18, 0x18}, input: 24},
			{expect: []byte{0x38, 0x18}, input: -25},
			{expect: []byte{0x18, 0x64}, input: 100},
			{expect: []byte{0x38, 0x64}, input: -101},
			{expect: []byte{0x19, 0x03, 0xe8}, input: 1000},
			{expect: []byte{0x39, 0x03, 0xe8}, input: -1001},
			{expect: []byte{0x1a, 0x00, 0x0f, 0x42, 0x40}, input: 1000000},
			{expect: []byte{0x3a, 0x00, 0x0f, 0x42, 0x40}, input: -1000001},
			{expect: []byte{0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00}, input: 1000000000000},
			{expect: []byte{0x3b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00}, input: -1000000000001},
		} {
			if got, err := cbor.Marshal(test.input); err != nil {
				t.Errorf("error marshaling %d: %v", test.input, err)
			} else if !bytes.Equal(got, test.expect) {
				t.Errorf("marshaling %d; expected % x, got % x", test.input, test.expect, got)
			}
		}
	})
}

func TestEncodeUint(t *testing.T) {
	t.Run("uint", func(t *testing.T) {
		input := uint(999)
		expect := []byte{0x19, 0x03, 0xe7}

		if got, err := cbor.Marshal(input); err != nil {
			t.Errorf("error marshaling %d: %v", input, err)
		} else if !bytes.Equal(got, expect) {
			t.Errorf("marshaling %d; expected % x, got % x", input, expect, got)
		}
	})

	t.Run("uint8", func(t *testing.T) {
		for _, test := range []struct {
			expect []byte
			input  uint8
		}{
			{expect: []byte{0x00}, input: 0},
			{expect: []byte{0x01}, input: 1},
			{expect: []byte{0x17}, input: 23},
			{expect: []byte{0x18, 0x18}, input: 24},
			{expect: []byte{0x18, 0x64}, input: 100},
		} {
			if got, err := cbor.Marshal(test.input); err != nil {
				t.Errorf("error marshaling %d: %v", test.input, err)
			} else if !bytes.Equal(got, test.expect) {
				t.Errorf("marshaling %d; expected % x, got % x", test.input, test.expect, got)
			}
		}
	})

	t.Run("uint16", func(t *testing.T) {
		for _, test := range []struct {
			input  uint16
			expect []byte
		}{
			{expect: []byte{0x00}, input: 0},
			{expect: []byte{0x01}, input: 1},
			{expect: []byte{0x17}, input: 23},
			{expect: []byte{0x18, 0x18}, input: 24},
			{expect: []byte{0x18, 0x64}, input: 100},
			{expect: []byte{0x19, 0x03, 0xe8}, input: 1000},
		} {
			if got, err := cbor.Marshal(test.input); err != nil {
				t.Errorf("error marshaling %d: %v", test.input, err)
			} else if !bytes.Equal(got, test.expect) {
				t.Errorf("marshaling %d; expected % x, got % x", test.input, test.expect, got)
			}
		}
	})

	t.Run("uint32", func(t *testing.T) {
		for _, test := range []struct {
			input  uint32
			expect []byte
		}{
			{expect: []byte{0x00}, input: 0},
			{expect: []byte{0x01}, input: 1},
			{expect: []byte{0x17}, input: 23},
			{expect: []byte{0x18, 0x18}, input: 24},
			{expect: []byte{0x18, 0x64}, input: 100},
			{expect: []byte{0x19, 0x03, 0xe8}, input: 1000},
			{expect: []byte{0x1a, 0x00, 0x0f, 0x42, 0x40}, input: 1000000},
		} {
			if got, err := cbor.Marshal(test.input); err != nil {
				t.Errorf("error marshaling %d: %v", test.input, err)
			} else if !bytes.Equal(got, test.expect) {
				t.Errorf("marshaling %d; expected % x, got % x", test.input, test.expect, got)
			}
		}
	})

	t.Run("uint64", func(t *testing.T) {
		for _, test := range []struct {
			input  uint64
			expect []byte
		}{
			{expect: []byte{0x00}, input: 0},
			{expect: []byte{0x01}, input: 1},
			{expect: []byte{0x17}, input: 23},
			{expect: []byte{0x18, 0x18}, input: 24},
			{expect: []byte{0x18, 0x64}, input: 100},
			{expect: []byte{0x19, 0x03, 0xe8}, input: 1000},
			{expect: []byte{0x1a, 0x00, 0x0f, 0x42, 0x40}, input: 1000000},
			{expect: []byte{0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00}, input: 1000000000000},
			{expect: []byte{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, input: 18446744073709551615},
		} {
			if got, err := cbor.Marshal(test.input); err != nil {
				t.Errorf("error marshaling %d: %v", test.input, err)
			} else if !bytes.Equal(got, test.expect) {
				t.Errorf("marshaling %d; expected % x, got % x", test.input, test.expect, got)
			}
		}
	})
}

func TestEncodeByteSlice(t *testing.T) {
	for _, test := range []struct {
		input  []byte
		expect []byte
	}{
		{expect: []byte{0x40}, input: []byte{}},
		{expect: []byte{0x44, 0x01, 0x02, 0x03, 0x04}, input: []byte{0x01, 0x02, 0x03, 0x04}},
	} {
		if got, err := cbor.Marshal(test.input); err != nil {
			t.Errorf("error marshaling % x: %v", test.input, err)
		} else if !bytes.Equal(got, test.expect) {
			t.Errorf("marshaling % x; expected % x, got % x", test.input, test.expect, got)
		}
	}
}

func TestEncodeByteSliceNewtype(t *testing.T) {
	type bstr []byte
	for _, test := range []struct {
		input  bstr
		expect []byte
	}{
		{expect: []byte{0x40}, input: bstr{}},
		{expect: []byte{0x44, 0x01, 0x02, 0x03, 0x04}, input: bstr{0x01, 0x02, 0x03, 0x04}},
	} {
		if got, err := cbor.Marshal(test.input); err != nil {
			t.Errorf("error marshaling % x: %v", test.input, err)
		} else if !bytes.Equal(got, test.expect) {
			t.Errorf("marshaling % x; expected % x, got % x", test.input, test.expect, got)
		}
	}
}

func TestEncodeString(t *testing.T) {
	for _, test := range []struct {
		input  string
		expect []byte
	}{
		{expect: []byte{0x60}, input: ""},
		{expect: []byte{0x61, 0x61}, input: "a"},
		{expect: []byte{0x64, 0x49, 0x45, 0x54, 0x46}, input: "IETF"},
		{expect: []byte{0x62, 0x22, 0x5c}, input: "\"\\"},
		{expect: []byte{0x62, 0xc3, 0xbc}, input: "ü"},
		{expect: []byte{0x63, 0xe6, 0xb0, 0xb4}, input: "水"},
	} {
		if got, err := cbor.Marshal(test.input); err != nil {
			t.Errorf("error marshaling %s: %v", test.input, err)
		} else if !bytes.Equal(got, test.expect) {
			t.Errorf("marshaling %s; expected % x, got % x", test.input, test.expect, got)
		}
	}
}

func TestEncodeArray(t *testing.T) {
	t.Run("homogeneous type", func(t *testing.T) {
		for _, test := range []struct {
			expect []byte
			input  any
		}{
			{input: []int(nil), expect: []byte{0x80}},
			{input: []int{}, expect: []byte{0x80}},
			{input: []int{1}, expect: []byte{0x81, 0x01}},
			{input: []int{1, 15}, expect: []byte{0x82, 0x01, 0x0f}},
			{input: []string{"IETF"}, expect: []byte{0x81, 0x64, 0x49, 0x45, 0x54, 0x46}},
		} {
			if got, err := cbor.Marshal(test.input); err != nil {
				t.Errorf("error marshaling %#v: %v", test.input, err)
			} else if !bytes.Equal(got, test.expect) {
				t.Errorf("marshaling %#v; expected % x, got % x", test.input, test.expect, got)
			}
		}
	})

	t.Run("tuples", func(t *testing.T) {
		type Embed struct {
			A int
			B int `cbor:"-"`
		}
		for _, test := range []struct {
			input  any
			expect []byte
		}{
			{input: struct{}{}, expect: []byte{0x80}},
			{input: struct{ A int }{A: 1}, expect: []byte{0x81, 0x01}},
			{input: struct{ a int }{a: 1}, expect: []byte{0x80}},
			{input: struct {
				A int `cbor:"-"`
			}{A: 1}, expect: []byte{0x80}},
			{input: struct {
				A int `cbor:",omitempty"`
			}{A: 0}, expect: []byte{0x80}},
			{input: struct {
				A int `cbor:",omitempty"`
			}{A: 1}, expect: []byte{0x81, 0x01}},
			{input: struct {
				A int
				B string
			}{A: 1, B: "IETF"}, expect: []byte{0x82, 0x01, 0x64, 0x49, 0x45, 0x54, 0x46}},
			{input: struct {
				A int `cbor:"1"`
				B string
			}{A: 1, B: "IETF"}, expect: []byte{0x82, 0x64, 0x49, 0x45, 0x54, 0x46, 0x01}},
			{input: struct {
				A int    `cbor:"2"`
				B string `cbor:"1"`
			}{A: 1, B: "IETF"}, expect: []byte{0x82, 0x64, 0x49, 0x45, 0x54, 0x46, 0x01}},
			{input: struct {
				Embed
				B string
			}{Embed: Embed{A: 1, B: 3}, B: "IETF"}, expect: []byte{0x82, 0x01, 0x64, 0x49, 0x45, 0x54, 0x46}},
		} {
			if got, err := cbor.Marshal(test.input); err != nil {
				t.Errorf("error marshaling % x: %v", test.input, err)
			} else if !bytes.Equal(got, test.expect) {
				t.Errorf("marshaling %#v; expected % x, got % x", test.input, test.expect, got)
			}
		}
	})
}

func TestEncodeMap(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var (
			expect = []byte{0xa0}
			input  = make(map[int]int)
		)
		got, err := cbor.Marshal(input)
		if err != nil {
			t.Errorf("error marshaling %+v: %v", input, err)
		}
		if !reflect.DeepEqual(got, expect) {
			t.Errorf("marshaling %+v; expected % x, got % x", input, expect, got)
		}
	})

	t.Run("int->int", func(t *testing.T) {
		var (
			expect = []byte{0xa2, 0x01, 0x02, 0x03, 0x04}
			input  = map[int]int{1: 2, 3: 4}
		)
		got, err := cbor.Marshal(input)
		if err != nil {
			t.Errorf("error marshaling %+v: %v", input, err)
		}
		if !reflect.DeepEqual(got, expect) {
			t.Errorf("marshaling %+v; expected % x, got % x", input, expect, got)
		}
	})

	t.Run("int->any", func(t *testing.T) {
		var (
			expect = []byte{0xa2, 0x01, 0x02, 0x03, 0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f}
			input  = map[int]any{1: 2, 3: "hello"}
		)
		got, err := cbor.Marshal(input)
		if err != nil {
			t.Errorf("error marshaling %+v: %v", input, err)
		}
		if !reflect.DeepEqual(got, expect) {
			t.Errorf("marshaling %+v; expected % x, got % x", input, expect, got)
		}
	})

	t.Run("int->struct{}", func(t *testing.T) {
		var (
			expect = []byte{0xa2, 0x01, 0x80, 0x03, 0x80}
			input  = map[int]struct{}{1: {}, 3: {}}
		)
		got, err := cbor.Marshal(input)
		if err != nil {
			t.Errorf("error marshaling %+v: %v", input, err)
		}
		if !reflect.DeepEqual(got, expect) {
			t.Errorf("marshaling %+v; expected % x, got % x", input, expect, got)
		}
	})

	t.Run("string->[]byte", func(t *testing.T) {
		var (
			expect = []byte{0xa1, 0x65, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x44, 0x01, 0x02, 0x03, 0x04}
			input  = map[string][]byte{"hello": {0x01, 0x02, 0x03, 0x04}}
		)
		got, err := cbor.Marshal(input)
		if err != nil {
			t.Errorf("error marshaling %+v: %v", input, err)
		}
		if !reflect.DeepEqual(got, expect) {
			t.Errorf("marshaling %+v; expected % x, got % x", input, expect, got)
		}
	})

	t.Run("string->map(string->string)", func(t *testing.T) {
		var (
			expect = []byte{0xa1, 0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0xa1, 0x65, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x61, 0x21}
			input  = map[string]map[string]string{"hello": {"world": "!"}}
		)
		got, err := cbor.Marshal(input)
		if err != nil {
			t.Errorf("error marshaling %+v: %v", input, err)
		}
		if !reflect.DeepEqual(got, expect) {
			t.Errorf("marshaling %+v; expected % x, got % x", input, expect, got)
		}
	})

	t.Run("core deterministic order", func(t *testing.T) {
		// 10, encoded as 0x0a.
		// 100, encoded as 0x1864.
		// -1, encoded as 0x20.
		// "z", encoded as 0x617a.
		// "aa", encoded as 0x626161.
		// [100], encoded as 0x811864.
		// [-1], encoded as 0x8120.
		// false, encoded as 0xf4.
		var (
			input = map[any]struct{}{
				10:          {},
				100:         {},
				-1:          {},
				"z":         {},
				"aa":        {},
				[1]int{100}: {},
				[1]int{-1}:  {},
				false:       {},
			}
			expect = []byte{0xa8,
				0x0a, 0x80,
				0x18, 0x64, 0x80,
				0x20, 0x80,
				0x61, 0x7a, 0x80,
				0x62, 0x61, 0x61, 0x80,
				0x81, 0x18, 0x64, 0x80,
				0x81, 0x20, 0x80,
				0xf4, 0x80,
			}
		)
		got, err := cbor.Marshal(input)
		if err != nil {
			t.Errorf("error marshaling %+v: %v", input, err)
		}
		if !reflect.DeepEqual(got, expect) {
			t.Errorf("marshaling %+v; expected % x, got % x", input, expect, got)
		}
	})
}

func TestEncodeTag(t *testing.T) {
	input := cbor.Tag[string]{Num: 42, Val: "Life"}
	expect := []byte{0xd8, 0x2a, 0x64, 0x4c, 0x69, 0x66, 0x65}
	if got, err := cbor.Marshal(input); err != nil {
		t.Errorf("error marshaling %+v: %v", input, err)
	} else if !bytes.Equal(got, expect) {
		t.Errorf("marshaling %+v; expected % x, got % x", input, expect, got)
	}
}

func TestEncodeBool(t *testing.T) {
	for _, test := range []struct {
		input  bool
		expect []byte
	}{
		{expect: []byte{0xf4}, input: false},
		{expect: []byte{0xf5}, input: true},
	} {
		if got, err := cbor.Marshal(test.input); err != nil {
			t.Errorf("error marshaling %v: %v", test.input, err)
		} else if !bytes.Equal(got, test.expect) {
			t.Errorf("marshaling %v; expected % x, got % x", test.input, test.expect, got)
		}
	}
}

func TestEncodeNull(t *testing.T) {
	var input *int
	expect := []byte{0xf6}
	if got, err := cbor.Marshal(input); err != nil {
		t.Errorf("error marshaling %+v: %v", input, err)
	} else if !bytes.Equal(got, expect) {
		t.Errorf("marshaling %+v; expected % x, got % x", input, expect, got)
	}
}

func TestEncodeUntypedNull(t *testing.T) {
	expect := []byte{0xf6}
	if got, err := cbor.Marshal(nil); err != nil {
		t.Errorf("error marshaling nil: %v", err)
	} else if !bytes.Equal(got, expect) {
		t.Errorf("marshaling nil; expected % x, got % x", expect, got)
	}
}

func TestEncodeUndefined(_ *testing.T) {
	// No way to encode undefined
}

func TestDecodeAny(t *testing.T) {
	t.Run("unsigned", func(t *testing.T) {
		input := []byte{0x19, 0x03, 0xe7}
		expect := int64(999)

		var got any
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if got.(int64) != expect {
			t.Errorf("unmarshaling % x; expected %d, got %d", input, expect, got)
		}
	})

	t.Run("negative", func(t *testing.T) {
		input := []byte{0x20}
		expect := int64(-1)

		var got any
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if got.(int64) != expect {
			t.Errorf("unmarshaling % x; expected %d, got %d", input, expect, got)
		}
	})

	t.Run("byte string", func(t *testing.T) {
		input := []byte{0x45, 0x68, 0x65, 0x6c, 0x6c, 0x6f}
		expect := []byte("hello")

		var got any
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if !bytes.Equal(got.([]byte), expect) {
			t.Errorf("unmarshaling % x; expected % x, got % x", input, expect, got)
		}
	})

	t.Run("byte string - newtype", func(t *testing.T) {
		type bstr []byte
		input := bstr{0x45, 0x68, 0x65, 0x6c, 0x6c, 0x6f}
		expect := []byte("hello")

		var got any
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if !bytes.Equal(got.([]byte), expect) {
			t.Errorf("unmarshaling % x; expected % x, got % x", input, expect, got)
		}
	})

	t.Run("text string", func(t *testing.T) {
		input := []byte{0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f}
		expect := "hello"

		var got any
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if got.(string) != expect {
			t.Errorf("unmarshaling % x; expected %s, got %s", input, expect, got)
		}
	})

	t.Run("array", func(t *testing.T) {
		input := []byte{0x82, 0x01, 0x64, 0x49, 0x45, 0x54, 0x46}
		expect := []any{int64(1), "IETF"}

		var got any
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if !reflect.DeepEqual(got.([]any), expect) {
			t.Errorf("unmarshaling % x; expected %s, got %s", input, expect, got)
		}
	})

	t.Run("map", func(t *testing.T) {
		var (
			input = []byte{0xa2,
				0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x02,
				0x03, 0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
			}
			expect = map[any]any{"hello": int64(2), int64(3): "hello"}
		)
		var got any
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if !reflect.DeepEqual(got.(map[any]any), expect) {
			t.Errorf("unmarshaling % x; expected %v, got %v", input, expect, got)
		}
	})

	t.Run("tag", func(t *testing.T) {
		for _, test := range []struct {
			input     []byte
			expectNum uint64
			expectVal any
		}{
			{
				input:     []byte{0xd8, 0x2a, 0x07},
				expectNum: 42,
				expectVal: 7,
			},
			{
				input:     []byte{0xd8, 0x2a, 0x22},
				expectNum: 42,
				expectVal: -3,
			},
			{
				input:     []byte{0xc7, 0xf5},
				expectNum: 7,
				expectVal: true,
			},
			{
				input:     []byte{0xc1, 0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f},
				expectNum: 1,
				expectVal: "hello",
			},
			{
				input:     []byte{0xc1, 0x44, 0x01, 0x02, 0x03, 0x04},
				expectNum: 1,
				expectVal: []byte{0x01, 0x02, 0x03, 0x04},
			},
			{
				input:     []byte{0xc3, 0x84, 0x01, 0x02, 0x03, 0x04},
				expectNum: 3,
				expectVal: []int{1, 2, 3, 4},
			},
			{
				input:     []byte{0xc3, 0x82, 0x01, 0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f},
				expectNum: 3,
				expectVal: struct {
					A int
					B string
				}{A: 1, B: "hello"},
			},
			{
				input:     []byte{0xc4, 0xa1, 0x65, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x44, 0x01, 0x02, 0x03, 0x04},
				expectNum: 4,
				expectVal: map[string][]byte{"hello": {0x01, 0x02, 0x03, 0x04}},
			},
			{
				input:     []byte{0xc5, 0xc4, 0x03},
				expectNum: 5,
				expectVal: cbor.Tag[int]{Num: 4, Val: 3},
			},
		} {
			var tag any
			if err := cbor.Unmarshal(test.input, &tag); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
			} else if n := tag.(cbor.TagData).Number(); n != test.expectNum {
				t.Errorf("unmarshaling % x; expected tag number %d, got %d", test.input, test.expectNum, n)
				continue
			}

			valAddr := reflect.New(reflect.TypeOf(test.expectVal)).Interface()
			if err := cbor.Unmarshal(tag.(cbor.Tag[cbor.RawBytes]).Val, valAddr); err != nil {
				t.Errorf("error unmarshaling tagged value % x: %v", tag.(cbor.Tag[cbor.RawBytes]).Val, err)
				continue
			}
			val := reflect.ValueOf(valAddr).Elem().Interface()
			if !reflect.DeepEqual(val, test.expectVal) {
				t.Errorf("unmarshaling % x; expected %#v, got %#v", tag.(cbor.Tag[cbor.RawBytes]).Val, test.expectVal, val)
			}
		}
	})

	t.Run("bool", func(t *testing.T) {
		var got any
		for _, test := range []struct {
			input  []byte
			expect bool
		}{
			{input: []byte{0xf4}, expect: false},
			{input: []byte{0xf5}, expect: true},
		} {
			if err := cbor.Unmarshal(test.input, &got); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
			} else if got.(bool) != test.expect {
				t.Errorf("unmarshaling % x; expected %v, got %v", test.input, test.expect, got)
			}
		}
	})

	t.Run("simple", func(t *testing.T) {
		var got any
		for _, test := range []struct {
			input  []byte
			expect int64
		}{
			{input: []byte{0xe1}, expect: 1},
			{input: []byte{0xe5}, expect: 5},
		} {
			if err := cbor.Unmarshal(test.input, &got); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
			} else if got.(int64) != test.expect {
				t.Errorf("unmarshaling % x; expected %v, got %v", test.input, test.expect, got)
			}
		}
	})
}

func TestDecodeInt(t *testing.T) {
	t.Run("int", func(t *testing.T) {
		input := []byte{0x19, 0x03, 0xe7}
		expect := 999

		var got int
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if got != expect {
			t.Errorf("unmarshaling % x; expected %d, got %d", input, expect, got)
		}
	})

	t.Run("int8", func(t *testing.T) {
		var got int8
		for _, test := range []struct {
			input  []byte
			expect int8
		}{
			{input: []byte{0x00}, expect: 0},
			{input: []byte{0x20}, expect: -1},
			{input: []byte{0x01}, expect: 1},
			{input: []byte{0x21}, expect: -2},
			{input: []byte{0x17}, expect: 23},
			{input: []byte{0x37}, expect: -24},
			{input: []byte{0x18, 0x18}, expect: 24},
			{input: []byte{0x38, 0x18}, expect: -25},
			{input: []byte{0x18, 0x64}, expect: 100},
			{input: []byte{0x38, 0x64}, expect: -101},
		} {
			if err := cbor.Unmarshal(test.input, &got); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
			} else if got != test.expect {
				t.Errorf("unmarshaling % x; expected %d, got %d", test.input, test.expect, got)
			}
		}
	})

	t.Run("int16", func(t *testing.T) {
		var got int16
		for _, test := range []struct {
			input  []byte
			expect int16
		}{
			{input: []byte{0x00}, expect: 0},
			{input: []byte{0x20}, expect: -1},
			{input: []byte{0x01}, expect: 1},
			{input: []byte{0x21}, expect: -2},
			{input: []byte{0x17}, expect: 23},
			{input: []byte{0x37}, expect: -24},
			{input: []byte{0x18, 0x18}, expect: 24},
			{input: []byte{0x38, 0x18}, expect: -25},
			{input: []byte{0x18, 0x64}, expect: 100},
			{input: []byte{0x38, 0x64}, expect: -101},
			{input: []byte{0x19, 0x03, 0xe8}, expect: 1000},
			{input: []byte{0x39, 0x03, 0xe8}, expect: -1001},
		} {
			if err := cbor.Unmarshal(test.input, &got); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
			} else if got != test.expect {
				t.Errorf("unmarshaling % x; expected %d, got %d", test.input, test.expect, got)
			}
		}
	})

	t.Run("int32", func(t *testing.T) {
		var got int32
		for _, test := range []struct {
			input  []byte
			expect int32
		}{
			{input: []byte{0x00}, expect: 0},
			{input: []byte{0x20}, expect: -1},
			{input: []byte{0x01}, expect: 1},
			{input: []byte{0x21}, expect: -2},
			{input: []byte{0x17}, expect: 23},
			{input: []byte{0x37}, expect: -24},
			{input: []byte{0x18, 0x18}, expect: 24},
			{input: []byte{0x38, 0x18}, expect: -25},
			{input: []byte{0x18, 0x64}, expect: 100},
			{input: []byte{0x38, 0x64}, expect: -101},
			{input: []byte{0x19, 0x03, 0xe8}, expect: 1000},
			{input: []byte{0x39, 0x03, 0xe8}, expect: -1001},
			{input: []byte{0x1a, 0x00, 0x0f, 0x42, 0x40}, expect: 1000000},
			{input: []byte{0x3a, 0x00, 0x0f, 0x42, 0x40}, expect: -1000001},
		} {
			if err := cbor.Unmarshal(test.input, &got); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
			} else if got != test.expect {
				t.Errorf("unmarshaling % x; expected %d, got %d", test.input, test.expect, got)
			}
		}
	})

	t.Run("int64", func(t *testing.T) {
		var got int64
		for _, test := range []struct {
			input  []byte
			expect int64
		}{
			{input: []byte{0x00}, expect: 0},
			{input: []byte{0x20}, expect: -1},
			{input: []byte{0x01}, expect: 1},
			{input: []byte{0x21}, expect: -2},
			{input: []byte{0x17}, expect: 23},
			{input: []byte{0x37}, expect: -24},
			{input: []byte{0x18, 0x18}, expect: 24},
			{input: []byte{0x38, 0x18}, expect: -25},
			{input: []byte{0x18, 0x64}, expect: 100},
			{input: []byte{0x38, 0x64}, expect: -101},
			{input: []byte{0x19, 0x03, 0xe8}, expect: 1000},
			{input: []byte{0x39, 0x03, 0xe8}, expect: -1001},
			{input: []byte{0x1a, 0x00, 0x0f, 0x42, 0x40}, expect: 1000000},
			{input: []byte{0x3a, 0x00, 0x0f, 0x42, 0x40}, expect: -1000001},
			{input: []byte{0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00}, expect: 1000000000000},
			{input: []byte{0x3b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00}, expect: -1000000000001},
		} {
			if err := cbor.Unmarshal(test.input, &got); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
			} else if got != test.expect {
				t.Errorf("unmarshaling % x; expected %d, got %d", test.input, test.expect, got)
			}
		}
	})
}

func TestDecodeUint(t *testing.T) {
	t.Run("uint", func(t *testing.T) {
		input := []byte{0x19, 0x03, 0xe7}
		expect := uint(999)

		var got uint
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if got != expect {
			t.Errorf("unmarshaling % x; expected %d, got %d", input, expect, got)
		}
	})
	t.Run("uint8", func(t *testing.T) {
		var got uint8
		for _, test := range []struct {
			input  []byte
			expect uint8
		}{
			{input: []byte{0x00}, expect: 0},
			{input: []byte{0x01}, expect: 1},
			{input: []byte{0x17}, expect: 23},
			{input: []byte{0x18, 0x18}, expect: 24},
			{input: []byte{0x18, 0x64}, expect: 100},
		} {
			if err := cbor.Unmarshal(test.input, &got); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
			} else if got != test.expect {
				t.Errorf("unmarshaling % x; expected %d, got %d", test.input, test.expect, got)
			}
		}
	})

	t.Run("uint16", func(t *testing.T) {
		var got uint16
		for _, test := range []struct {
			input  []byte
			expect uint16
		}{
			{input: []byte{0x00}, expect: 0},
			{input: []byte{0x01}, expect: 1},
			{input: []byte{0x17}, expect: 23},
			{input: []byte{0x18, 0x18}, expect: 24},
			{input: []byte{0x18, 0x64}, expect: 100},
			{input: []byte{0x19, 0x03, 0xe8}, expect: 1000},
		} {
			if err := cbor.Unmarshal(test.input, &got); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
			} else if got != test.expect {
				t.Errorf("unmarshaling % x; expected %d, got %d", test.input, test.expect, got)
			}
		}
	})

	t.Run("uint32", func(t *testing.T) {
		var got uint32
		for _, test := range []struct {
			input  []byte
			expect uint32
		}{
			{input: []byte{0x00}, expect: 0},
			{input: []byte{0x01}, expect: 1},
			{input: []byte{0x17}, expect: 23},
			{input: []byte{0x18, 0x18}, expect: 24},
			{input: []byte{0x18, 0x64}, expect: 100},
			{input: []byte{0x19, 0x03, 0xe8}, expect: 1000},
			{input: []byte{0x1a, 0x00, 0x0f, 0x42, 0x40}, expect: 1000000},
		} {
			if err := cbor.Unmarshal(test.input, &got); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
			} else if got != test.expect {
				t.Errorf("unmarshaling % x; expected %d, got %d", test.input, test.expect, got)
			}
		}
	})

	t.Run("uint64", func(t *testing.T) {
		var got uint64
		for _, test := range []struct {
			input  []byte
			expect uint64
		}{
			{input: []byte{0x00}, expect: 0},
			{input: []byte{0x01}, expect: 1},
			{input: []byte{0x17}, expect: 23},
			{input: []byte{0x18, 0x18}, expect: 24},
			{input: []byte{0x18, 0x64}, expect: 100},
			{input: []byte{0x19, 0x03, 0xe8}, expect: 1000},
			{input: []byte{0x1a, 0x00, 0x0f, 0x42, 0x40}, expect: 1000000},
			{input: []byte{0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00}, expect: 1000000000000},
			{input: []byte{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, expect: 18446744073709551615},
		} {
			if err := cbor.Unmarshal(test.input, &got); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
			} else if got != test.expect {
				t.Errorf("unmarshaling % x; expected %d, got %d", test.input, test.expect, got)
			}
		}
	})
}

func TestDecodeByteSlice(t *testing.T) {
	var got []byte
	for _, test := range []struct {
		input  []byte
		expect []byte
	}{
		{input: []byte{0x40}, expect: []byte{}},
		{input: []byte{0x44, 0x01, 0x02, 0x03, 0x04}, expect: []byte{0x01, 0x02, 0x03, 0x04}},
	} {
		if err := cbor.Unmarshal(test.input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", test.input, err)
		} else if !bytes.Equal(got, test.expect) {
			t.Errorf("unmarshaling % x; expected % x, got % x", test.input, test.expect, got)
		}
	}
}

func TestDecodeByteSliceNewtype(t *testing.T) {
	type bstr blob.Hmac
	var got bstr
	for _, test := range []struct {
		input  []byte
		expect bstr
	}{
		{input: []byte{0x40}, expect: bstr{}},
		{input: []byte{0x44, 0x01, 0x02, 0x03, 0x04}, expect: bstr{0x01, 0x02, 0x03, 0x04}},
	} {
		if err := cbor.Unmarshal(test.input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", test.input, err)
		} else if !bytes.Equal(got, test.expect) {
			t.Errorf("unmarshaling % x; expected % x, got % x", test.input, test.expect, got)
		}
	}
}

func TestDecodeString(t *testing.T) {
	var got string
	for _, test := range []struct {
		input  []byte
		expect string
	}{
		{input: []byte{0x60}, expect: ""},
		{input: []byte{0x61, 0x61}, expect: "a"},
		{input: []byte{0x64, 0x49, 0x45, 0x54, 0x46}, expect: "IETF"},
		{input: []byte{0x62, 0x22, 0x5c}, expect: "\"\\"},
		{input: []byte{0x62, 0xc3, 0xbc}, expect: "ü"},
		{input: []byte{0x63, 0xe6, 0xb0, 0xb4}, expect: "水"},
	} {
		if err := cbor.Unmarshal(test.input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", test.input, err)
		} else if got != test.expect {
			t.Errorf("unmarshaling % x; expected %s, got %s", test.input, test.expect, got)
		}
	}
}

func TestDecodeStringNewtype(t *testing.T) {
	type newstring string
	var got newstring
	for _, test := range []struct {
		input  []byte
		expect newstring
	}{
		{input: []byte{0x60}, expect: ""},
		{input: []byte{0x61, 0x61}, expect: "a"},
		{input: []byte{0x64, 0x49, 0x45, 0x54, 0x46}, expect: "IETF"},
		{input: []byte{0x62, 0x22, 0x5c}, expect: "\"\\"},
		{input: []byte{0x62, 0xc3, 0xbc}, expect: "ü"},
		{input: []byte{0x63, 0xe6, 0xb0, 0xb4}, expect: "水"},
	} {
		if err := cbor.Unmarshal(test.input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", test.input, err)
		} else if got != test.expect {
			t.Errorf("unmarshaling % x; expected %s, got %s", test.input, test.expect, got)
		}
	}
}

func TestDecodeArray(t *testing.T) {
	t.Run("homogeneous type", func(t *testing.T) {
		for _, test := range []struct {
			input  []byte
			expect any
		}{
			{expect: []int{}, input: []byte{0x80}},
			{expect: []int{1}, input: []byte{0x81, 0x01}},
			{expect: []int{1, 15}, input: []byte{0x82, 0x01, 0x0f}},
			{expect: []string{"IETF"}, input: []byte{0x81, 0x64, 0x49, 0x45, 0x54, 0x46}},
			{expect: []any{int64(1), "IETF"}, input: []byte{0x82, 0x01, 0x64, 0x49, 0x45, 0x54, 0x46}},
		} {
			gotAddr := reflect.New(reflect.TypeOf(test.expect)).Interface()
			if err := cbor.Unmarshal(test.input, gotAddr); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
				continue
			}
			got := reflect.ValueOf(gotAddr).Elem().Interface()
			if !reflect.DeepEqual(got, test.expect) {
				t.Errorf("unmarshaling %#v; expected %#v, got %#v", test.input, test.expect, got)
			}
		}
	})

	t.Run("tuples", func(t *testing.T) {
		for _, test := range []struct {
			input  []byte
			expect any
		}{
			{expect: struct{}{}, input: []byte{0x80}},
			{expect: struct{ A int }{A: 1}, input: []byte{0x81, 0x01}},
			{expect: struct {
				A int `cbor:"-"`
				B int
			}{A: 0, B: 1}, input: []byte{0x81, 0x01}},
			{expect: struct {
				A int
				B string
			}{A: 1, B: "IETF"}, input: []byte{0x82, 0x01, 0x64, 0x49, 0x45, 0x54, 0x46}},
		} {
			gotAddr := reflect.New(reflect.TypeOf(test.expect)).Interface()
			if err := cbor.Unmarshal(test.input, gotAddr); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
				continue
			}
			got := reflect.ValueOf(gotAddr).Elem().Interface()
			if !reflect.DeepEqual(got, test.expect) {
				t.Errorf("unmarshaling % x; expected %#v, got %#v", test.input, test.expect, got)
			}
		}
	})
}

func TestDecodeMap(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var (
			input  = []byte{0xa0}
			got    = make(map[int]int)
			expect = map[int]int{}
		)
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if !reflect.DeepEqual(got, expect) {
			t.Errorf("unmarshaling % x; expected %v, got %v", input, expect, got)
		}
	})

	t.Run("int->int", func(t *testing.T) {
		var (
			input  = []byte{0xa2, 0x01, 0x02, 0x03, 0x04}
			got    = make(map[int]int)
			expect = map[int]int{1: 2, 3: 4}
		)
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if !reflect.DeepEqual(got, expect) {
			t.Errorf("unmarshaling % x; expected %v, got %v", input, expect, got)
		}
	})

	t.Run("any->any", func(t *testing.T) {
		var (
			input = []byte{0xa2,
				0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x02,
				0x03, 0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
			}
			got    = make(map[any]any)
			expect = map[any]any{"hello": int64(2), int64(3): "hello"}
		)
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if !reflect.DeepEqual(got, expect) {
			t.Errorf("unmarshaling % x; expected %v, got %v", input, expect, got)
		}
	})

	t.Run("int->struct{}", func(t *testing.T) {
		var (
			input  = []byte{0xa2, 0x01, 0x80, 0x03, 0x80}
			got    = make(map[int]struct{})
			expect = map[int]struct{}{1: {}, 3: {}}
		)
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if !reflect.DeepEqual(got, expect) {
			t.Errorf("unmarshaling % x; expected %v, got %v", input, expect, got)
		}
	})

	t.Run("string->[]byte", func(t *testing.T) {
		var (
			input  = []byte{0xa1, 0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x44, 0x01, 0x02, 0x03, 0x04}
			got    = make(map[string][]byte)
			expect = map[string][]byte{"hello": {0x01, 0x02, 0x03, 0x04}}
		)
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if !reflect.DeepEqual(got, expect) {
			t.Errorf("unmarshaling % x; expected %v, got %v", input, expect, got)
		}
	})

	t.Run("string->map(string->string)", func(t *testing.T) {
		var (
			input  = []byte{0xa1, 0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0xa1, 0x65, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x61, 0x21}
			got    = make(map[string]map[string]string)
			expect = map[string]map[string]string{"hello": {"world": "!"}}
		)
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if !reflect.DeepEqual(got, expect) {
			t.Errorf("unmarshaling % x; expected %v, got %v", input, expect, got)
		}
	})
}

func TestDecodeTag(t *testing.T) {
	for _, test := range []struct {
		input     []byte
		expectNum uint64
		expectVal any
	}{
		{
			input:     []byte{0xd8, 0x2a, 0x07},
			expectNum: 42,
			expectVal: 7,
		},
		{
			input:     []byte{0xd8, 0x2a, 0x22},
			expectNum: 42,
			expectVal: -3,
		},
		{
			input:     []byte{0xc7, 0xf5},
			expectNum: 7,
			expectVal: true,
		},
		{
			input:     []byte{0xc1, 0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f},
			expectNum: 1,
			expectVal: "hello",
		},
		{
			input:     []byte{0xc1, 0x44, 0x01, 0x02, 0x03, 0x04},
			expectNum: 1,
			expectVal: []byte{0x01, 0x02, 0x03, 0x04},
		},
		{
			input:     []byte{0xc3, 0x84, 0x01, 0x02, 0x03, 0x04},
			expectNum: 3,
			expectVal: []int{1, 2, 3, 4},
		},
		{
			input:     []byte{0xc3, 0x82, 0x01, 0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f},
			expectNum: 3,
			expectVal: struct {
				A int
				B string
			}{A: 1, B: "hello"},
		},
		{
			input:     []byte{0xc4, 0xa1, 0x65, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x44, 0x01, 0x02, 0x03, 0x04},
			expectNum: 4,
			expectVal: map[string][]byte{"hello": {0x01, 0x02, 0x03, 0x04}},
		},
		{
			input:     []byte{0xc5, 0xc4, 0x03},
			expectNum: 5,
			expectVal: cbor.Tag[int]{Num: 4, Val: 3},
		},
	} {
		var tag cbor.Tag[cbor.RawBytes]
		if err := cbor.Unmarshal(test.input, &tag); err != nil {
			t.Errorf("error unmarshaling % x: %v", test.input, err)
		} else if tag.Num != test.expectNum {
			t.Errorf("unmarshaling % x; expected tag number %d, got %d", test.input, test.expectNum, tag.Num)
			continue
		}

		valAddr := reflect.New(reflect.TypeOf(test.expectVal)).Interface()
		if err := cbor.Unmarshal(tag.Val, valAddr); err != nil {
			t.Errorf("error unmarshaling tagged value % x: %v", tag.Val, err)
			continue
		}
		val := reflect.ValueOf(valAddr).Elem().Interface()
		if !reflect.DeepEqual(val, test.expectVal) {
			t.Errorf("unmarshaling % x; expected %#v, got %#v", tag.Val, test.expectVal, val)
		}
	}
}

func TestDecodeBool(t *testing.T) {
	var got bool
	for _, test := range []struct {
		input  []byte
		expect bool
	}{
		{input: []byte{0xf4}, expect: false},
		{input: []byte{0xf5}, expect: true},
	} {
		if err := cbor.Unmarshal(test.input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", test.input, err)
		} else if got != test.expect {
			t.Errorf("unmarshaling % x; expected %v, got %v", test.input, test.expect, got)
		}
	}
}

func TestDecodeNull(t *testing.T) {
	t.Run("pointer (initialized)", func(t *testing.T) {
		var (
			got    = new(int)
			input  = []byte{0xf6}
			expect = (*int)(nil)
		)
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if got != expect {
			t.Errorf("unmarshaling % x; expected %+v, got %+v", input, expect, got)
		}
	})

	t.Run("pointer (uninitialized)", func(t *testing.T) {
		var (
			got    *int
			input  = []byte{0xf6}
			expect = (*int)(nil)
		)
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if got != expect {
			t.Errorf("unmarshaling % x; expected %+v, got %+v", input, expect, got)
		}
	})

	t.Run("non-pointer", func(t *testing.T) {
		var (
			got    int
			input  = []byte{0xf6}
			expect = cbor.ErrUnsupportedType{}
		)
		if err := cbor.Unmarshal(input, &got); !errors.As(err, &expect) {
			t.Errorf("expected %#v error unmarshaling % x, got %#v", expect, input, err)
		}
	})
}

func TestDecodeUndefined(t *testing.T) {
	t.Run("pointer (initialized)", func(t *testing.T) {
		var (
			got    = new(int)
			input  = []byte{0xf7}
			expect = (*int)(nil)
		)
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if got != expect {
			t.Errorf("unmarshaling % x; expected %+v, got %+v", input, expect, got)
		}
	})

	t.Run("pointer (uninitialized)", func(t *testing.T) {
		var (
			got    *int
			input  = []byte{0xf7}
			expect = (*int)(nil)
		)
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if got != expect {
			t.Errorf("unmarshaling % x; expected %+v, got %+v", input, expect, got)
		}
	})

	t.Run("non-pointer", func(t *testing.T) {
		var (
			got    int
			input  = []byte{0xf7}
			expect = cbor.ErrUnsupportedType{}
		)
		if err := cbor.Unmarshal(input, &got); !errors.As(err, &expect) {
			t.Errorf("expected %#v error unmarshaling % x, got %#v", expect, input, err)
		}
	})
}

func TestDecodePointer(t *testing.T) {
	t.Run("initialized primitive", func(t *testing.T) {
		var (
			got    = new(int)
			input  = []byte{0x20}
			expect = -1
		)
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if !reflect.DeepEqual(got, &expect) {
			t.Errorf("unmarshaling % x; expected %+v, got %+v", input, expect, *got)
		}
	})

	t.Run("uninitialized primitive", func(t *testing.T) {
		var (
			got    *int
			input  = []byte{0x20}
			expect = -1
		)
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if !reflect.DeepEqual(got, &expect) {
			t.Errorf("unmarshaling % x; expected %+v, got %+v", input, expect, *got)
		}
	})

	t.Run("initialized bytes", func(t *testing.T) {
		var (
			bs     = make([]byte, 0)
			got    = &bs
			input  = []byte{0x44, 0x49, 0x45, 0x54, 0x46}
			expect = []byte("IETF")
		)
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if !reflect.DeepEqual(got, &expect) {
			t.Errorf("unmarshaling % x; expected %+v, got %+v", input, expect, *got)
		}
	})

	t.Run("uninitialized bytes", func(t *testing.T) {
		var (
			got    = new([]byte)
			input  = []byte{0x44, 0x49, 0x45, 0x54, 0x46}
			expect = []byte("IETF")
		)
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if !reflect.DeepEqual(got, &expect) {
			t.Errorf("unmarshaling % x; expected %+v, got %+v", input, expect, *got)
		}
	})

	t.Run("initialized map", func(t *testing.T) {
		var (
			m      = make(map[int]int, 0)
			got    = &m
			input  = []byte{0xa2, 0x01, 0x02, 0x03, 0x04}
			expect = map[int]int{1: 2, 3: 4}
		)
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if !reflect.DeepEqual(got, &expect) {
			t.Errorf("unmarshaling % x; expected %+v, got %+v", input, expect, *got)
		}
	})

	t.Run("uninitialized map", func(t *testing.T) {
		var (
			got    = new(map[int]int)
			input  = []byte{0xa2, 0x01, 0x02, 0x03, 0x04}
			expect = map[int]int{1: 2, 3: 4}
		)
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
		} else if !reflect.DeepEqual(got, &expect) {
			t.Errorf("unmarshaling % x; expected %+v, got %+v", input, expect, *got)
		}
	})
}

func TestEncodeBstr(t *testing.T) {
	t.Run("non-pointer field", func(t *testing.T) {
		type a struct {
			A int
			B cbor.Bstr[[]byte]
		}
		var (
			input  = a{A: 1, B: cbor.Bstr[[]byte]{Val: []byte("IETF")}}
			expect = []byte{0x82, 0x01, 0x45, 0x44, 0x49, 0x45, 0x54, 0x46}
		)
		if got, err := cbor.Marshal(input); err != nil {
			t.Errorf("error marshaling %#v: %v", input, err)
		} else if !bytes.Equal(got, expect) {
			t.Errorf("marshaling %#v; expected % x, got % x", input, expect, got)
		}
	})

	t.Run("pointer field", func(t *testing.T) {
		type a struct {
			A int
			B *cbor.Bstr[any]
		}
		tests := []struct {
			input  a
			expect []byte
		}{
			{
				input:  a{A: 1, B: &cbor.Bstr[any]{Val: []byte("IETF")}},
				expect: []byte{0x82, 0x01, 0x45, 0x44, 0x49, 0x45, 0x54, 0x46},
			},
			{
				input:  a{A: 1, B: nil},
				expect: []byte{0x82, 0x01, 0xf6},
			},
		}
		for _, test := range tests {
			if got, err := cbor.Marshal(test.input); err != nil {
				t.Errorf("error marshaling %#v: %v", test.input, err)
			} else if !bytes.Equal(got, test.expect) {
				t.Errorf("marshaling %#v; expected % x, got % x", test.input, test.expect, got)
			}
		}
	})
}

func TestDecodeBstr(t *testing.T) {
	t.Run("non-pointer field", func(t *testing.T) {
		type a struct {
			A int
			B cbor.Bstr[any]
		}
		var (
			input  = []byte{0x82, 0x01, 0x45, 0x44, 0x49, 0x45, 0x54, 0x46}
			expect = a{A: 1, B: cbor.Bstr[any]{Val: []byte("IETF")}}
		)
		var got a
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Errorf("error unmarshaling % x: %v", input, err)
			return
		}
		if !reflect.DeepEqual(got, expect) {
			t.Errorf("unmarshaling % x; expected %#v, got %#v", input, expect, got)
		}
	})

	t.Run("pointer field", func(t *testing.T) {
		type a struct {
			A int
			B *cbor.Bstr[any]
		}
		tests := []struct {
			input  []byte
			expect a
		}{
			{
				input:  []byte{0x82, 0x01, 0x45, 0x44, 0x49, 0x45, 0x54, 0x46},
				expect: a{A: 1, B: &cbor.Bstr[any]{Val: []byte("IETF")}},
			},
			{
				input:  []byte{0x82, 0x01, 0xf6},
				expect: a{A: 1, B: nil},
			},
		}
		for _, test := range tests {
			var got a
			if err := cbor.Unmarshal(test.input, &got); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
				return
			}
			if !reflect.DeepEqual(got, test.expect) {
				t.Errorf("unmarshaling % x; expected %#v, got %#v", test.input, test.expect, got)
			}
		}
	})
}

func TestEncodeFixedArray(t *testing.T) {
	t.Run("byte array", func(t *testing.T) {
		for _, test := range []struct {
			input  [4]byte
			expect []byte
		}{
			{expect: []byte{0x44, 0x01, 0x02, 0x03, 0x04}, input: [4]byte{0x01, 0x02, 0x03, 0x04}},
			{expect: []byte{0x44, 0x49, 0x45, 0x54, 0x46}, input: [4]byte{0x49, 0x45, 0x54, 0x46}},
		} {
			if got, err := cbor.Marshal(test.input); err != nil {
				t.Errorf("error marshaling % x: %v", test.input, err)
			} else if !bytes.Equal(got[:], test.expect[:]) {
				t.Errorf("marshaling % x; expected % x, got % x", test.input, test.expect, got)
			}
		}
	})

	t.Run("int array", func(t *testing.T) {
		for _, test := range []struct {
			input  [4]int
			expect []byte
		}{
			{expect: []byte{0x84, 0x01, 0x02, 0x03, 0x04}, input: [4]int{1, 2, 3, 4}},
		} {
			if got, err := cbor.Marshal(test.input); err != nil {
				t.Errorf("error marshaling % x: %v", test.input, err)
			} else if !reflect.DeepEqual(got[:], test.expect[:]) {
				t.Errorf("marshaling % x; expected % x, got % x", test.input, test.expect, got)
			}
		}
	})

	t.Run("pointer array", func(t *testing.T) {
		var (
			one   = 1
			two   = 2
			three = 3
			four  = 4
		)
		for _, test := range []struct {
			input  [4]*int
			expect []byte
		}{
			{expect: []byte{0x84, 0x01, 0x02, 0x03, 0x04}, input: [4]*int{&one, &two, &three, &four}},
		} {
			if got, err := cbor.Marshal(test.input); err != nil {
				t.Errorf("error marshaling % x: %v", test.input, err)
			} else if !reflect.DeepEqual(got[:], test.expect[:]) {
				t.Errorf("marshaling % x; expected % x, got % x", test.input, test.expect, got)
			}
		}
	})
}

func TestDecodeFixedArray(t *testing.T) {
	t.Run("byte array", func(t *testing.T) {
		for _, test := range []struct {
			input  []byte
			expect [4]byte
		}{
			{input: []byte{0x40}, expect: [4]byte{0x00, 0x00, 0x00, 0x00}},
			{input: []byte{0x42, 0x01, 0x02}, expect: [4]byte{0x01, 0x02, 0x00, 0x00}},
			{input: []byte{0x44, 0x01, 0x02, 0x03, 0x04}, expect: [4]byte{0x01, 0x02, 0x03, 0x04}},
		} {
			got := [4]byte{0x01, 0x01, 0x01, 0x01}
			if err := cbor.Unmarshal(test.input, &got); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
			} else if !bytes.Equal(got[:], test.expect[:]) {
				t.Errorf("unmarshaling % x; expected % x, got % x", test.input, test.expect, got)
			}
		}
	})

	t.Run("int array", func(t *testing.T) {
		for _, test := range []struct {
			input  []byte
			expect [4]int
		}{
			{input: []byte{0x80}, expect: [4]int{0, 0, 0, 0}},
			{input: []byte{0x82, 0x01, 0x02}, expect: [4]int{1, 2, 0, 0}},
			{input: []byte{0x84, 0x01, 0x02, 0x03, 0x04}, expect: [4]int{1, 2, 3, 4}},
		} {
			got := [4]int{4, 3, 2, 1}
			if err := cbor.Unmarshal(test.input, &got); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
			} else if !reflect.DeepEqual(got[:], test.expect[:]) {
				t.Errorf("unmarshaling % x; expected % x, got % x", test.input, test.expect, got)
			}
		}
	})

	t.Run("pointer array", func(t *testing.T) {
		var (
			one   = 1
			two   = 2
			three = 3
			four  = 4
		)
		for _, test := range []struct {
			input  []byte
			expect [4]*int
		}{
			{input: []byte{0x80}, expect: [4]*int{nil, nil, nil, nil}},
			{input: []byte{0x82, 0x01, 0x02}, expect: [4]*int{&one, &two, nil, nil}},
			{input: []byte{0x84, 0x01, 0x02, 0x03, 0x04}, expect: [4]*int{&one, &two, &three, &four}},
		} {
			got := [4]*int{nil, nil, nil, nil}
			if err := cbor.Unmarshal(test.input, &got); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
			} else if !reflect.DeepEqual(got[:], test.expect[:]) {
				t.Errorf("unmarshaling % x; expected % x, got % x", test.input, test.expect, got)
			}
		}
	})
}

func TestDecodeNewtype(t *testing.T) {
	t.Run("uint newtype", func(t *testing.T) {
		type myUint uint
		for _, test := range []struct {
			input  []byte
			expect myUint
		}{
			{
				input:  []byte{0x19, 0x03, 0xe7},
				expect: myUint(999),
			},
		} {
			var got myUint
			if err := cbor.Unmarshal(test.input, &got); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
			} else if got != test.expect {
				t.Errorf("unmarshaling % x; expected %d, got %d", test.input, test.expect, got)
			}
		}
	})

	t.Run("int newtype", func(t *testing.T) {
		type myInt int
		for _, test := range []struct {
			input  []byte
			expect myInt
		}{
			{
				input:  []byte{0x19, 0x03, 0xe7},
				expect: myInt(999),
			},
			{
				input:  []byte{0x38, 0x64},
				expect: myInt(-101),
			},
		} {
			var got myInt
			if err := cbor.Unmarshal(test.input, &got); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
			} else if got != test.expect {
				t.Errorf("unmarshaling % x; expected %d, got %d", test.input, test.expect, got)
			}
		}
	})

	// TODO: Newtypes for each major
}

func TestEncodeArrayOfArray(t *testing.T) {
	t.Run("[][]int", func(t *testing.T) {
		for _, test := range []struct {
			input  [][]int
			expect []byte
		}{
			{input: [][]int{}, expect: []byte{0x80}},
			{input: [][]int{{}}, expect: []byte{0x81, 0x80}},
			{input: [][]int{{1}}, expect: []byte{0x81, 0x81, 0x01}},
			{input: [][]int{{1, 15}, {2}}, expect: []byte{0x82, 0x82, 0x01, 0x0f, 0x81, 0x02}},
		} {
			got, err := cbor.Marshal(test.input)
			if err != nil {
				t.Errorf("error marshaling %v: %v", test.input, err)
				continue
			}
			if !reflect.DeepEqual(got, test.expect) {
				t.Errorf("marshaling %#v; expected % x, got % x", test.input, test.expect, got)
			}
		}
	})

	t.Run("[][]struct", func(t *testing.T) {
		type s struct {
			A int
			B string
		}
		for _, test := range []struct {
			input  [][]s
			expect []byte
		}{
			{input: [][]s{}, expect: []byte{0x80}},
			{input: [][]s{{{A: 1, B: "A"}}}, expect: []byte{0x81, 0x81, 0x82, 0x01, 0x61, 0x41}},
		} {
			got, err := cbor.Marshal(test.input)
			if err != nil {
				t.Errorf("error marshaling %v: %v", test.input, err)
				continue
			}
			if !reflect.DeepEqual(got, test.expect) {
				t.Errorf("marshaling %#v; expected % x, got % x", test.input, test.expect, got)
			}
		}
	})

	t.Run("struct([][]struct)", func(t *testing.T) {
		type ss struct {
			A int
			B string
		}
		type s struct {
			S [][]ss
		}
		for _, test := range []struct {
			input  s
			expect []byte
		}{
			{input: s{S: [][]ss{{{A: 1, B: "A"}}}}, expect: []byte{0x81, 0x81, 0x81, 0x82, 0x01, 0x61, 0x41}},
		} {
			got, err := cbor.Marshal(test.input)
			if err != nil {
				t.Errorf("error marshaling %v: %v", test.input, err)
				continue
			}
			if !reflect.DeepEqual(got, test.expect) {
				t.Errorf("marshaling %#v; expected % x, got % x", test.input, test.expect, got)
			}
		}
	})
}

func TestDecodeArrayOfArray(t *testing.T) {
	t.Run("[][]int", func(t *testing.T) {
		for _, test := range []struct {
			input  []byte
			expect [][]int
		}{
			{expect: [][]int{}, input: []byte{0x80}},
			{expect: [][]int{{}}, input: []byte{0x81, 0x80}},
			{expect: [][]int{{1}}, input: []byte{0x81, 0x81, 0x01}},
			{expect: [][]int{{1, 15}, {2}}, input: []byte{0x82, 0x82, 0x01, 0x0f, 0x81, 0x02}},
		} {
			var got [][]int
			if err := cbor.Unmarshal(test.input, &got); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
				continue
			}
			if !reflect.DeepEqual(got, test.expect) {
				t.Errorf("unmarshaling %#v; expected %#v, got %#v", test.input, test.expect, got)
			}
		}
	})

	t.Run("[][N]byte", func(t *testing.T) {
		for _, test := range []struct {
			input  []byte
			expect [][2]byte
		}{
			{expect: [][2]byte{}, input: []byte{0x80}},
			{expect: [][2]byte{{0x01, 0x02}}, input: []byte{0x81, 0x82, 0x01, 0x02}},
			{expect: [][2]byte{{0x01, 0x02}, {0x03, 0x04}}, input: []byte{0x82, 0x82, 0x01, 0x02, 0x82, 0x03, 0x04}},
		} {
			var got [][2]byte
			if err := cbor.Unmarshal(test.input, &got); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
				continue
			}
			if !reflect.DeepEqual(got, test.expect) {
				t.Errorf("unmarshaling %#v; expected %#v, got %#v", test.input, test.expect, got)
			}
		}
	})

	t.Run("[N][N]byte", func(t *testing.T) {
		for _, test := range []struct {
			input  []byte
			expect [1][2]byte
		}{
			{expect: [1][2]byte{{0x01, 0x02}}, input: []byte{0x81, 0x82, 0x01, 0x02}},
		} {
			var got [1][2]byte
			if err := cbor.Unmarshal(test.input, &got); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
				continue
			}
			if !reflect.DeepEqual(got, test.expect) {
				t.Errorf("unmarshaling %#v; expected %#v, got %#v", test.input, test.expect, got)
			}
		}
	})

	t.Run("[][]struct", func(t *testing.T) {
		type s struct {
			A int
			B string
		}
		for _, test := range []struct {
			input  []byte
			expect [][]s
		}{
			{expect: [][]s{}, input: []byte{0x80}},
			{expect: [][]s{{{A: 1, B: "A"}}}, input: []byte{0x81, 0x81, 0x82, 0x01, 0x61, 0x41}},
		} {
			var got [][]s
			if err := cbor.Unmarshal(test.input, &got); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
				continue
			}
			if !reflect.DeepEqual(got, test.expect) {
				t.Errorf("unmarshaling %#v; expected %#v, got %#v", test.input, test.expect, got)
			}
		}
	})
}

func TestDecodeStream(t *testing.T) {
	for _, test := range [][]any{
		{},
		{int64(1)},
		{"a", "b"},
	} {
		var buf bytes.Buffer
		for _, obj := range test {
			if err := cbor.NewEncoder(&buf).Encode(obj); err != nil {
				t.Fatal(err)
			}
		}
		got := []any{}
		objsInStream := 0
		for ; ; objsInStream++ {
			var obj any
			if err := cbor.NewDecoder(&buf).Decode(&obj); errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			got = append(got, obj)
		}
		if objsInStream != len(test) {
			t.Errorf("expected to decode %d objects, got %d", len(test), objsInStream)
		}
		if !reflect.DeepEqual(got, test) {
			t.Errorf("expected %#v, got %#v", test, got)
		}
	}
}

func TestDecodeOVHeaderX5Chain(t *testing.T) {
	body, err := hex.DecodeString("861865501C0282BE2AAF453396261E1EFD36E4EB818482055574686F73742E646F636B65722E696E7465726E616C820343191F90820C4101820443191F90653132333435830102815902D6308202D2308201BAA0030201020208446783815695490B300D06092A864886F70D01010B050030173115301306035504030C0C46646F456E746974792043413020170D3233303930353230343635365A180F32303533303333313230343635365A30173115301306035504030C0C46646F456E7469747920434130820122300D06092A864886F70D01010105000382010F003082010A0282010100C07036212B6A05C285F04B7485B3D0EFEA9EFB8C960F554FEB65A1914F9C1970D9288C762B6E37BA7FFE288C78078597DA6B6B10C4D61F6AFF1B6F85F45AE153E2084BEBE09F366ABD66D409DA6ED1BBD07375A1C506A2F1A5F1E90FD3689904FDCEC5D6CC81071A51C32A02FE2E15CD681884E97C1107FA579DC48F30E8FB25F6BA24187CCFF6CBFF9CD4B956D7747BC018C85BEA95CE9348CB5487B0608338E519E279B68062215940ECC996CEF7D24806E63D2FC69E7C06631A2C3305F6F32397F0AF7B15A876AF092256C5384A8353488FAB807969AFF06F1D0310CED956949AD67FC5AAC2A7A176AE2DB605CC1990E14C500267596799679BE3DC337BC70203010001A320301E300F0603551D130101FF040530030101FF300B0603551D0F040403020186300D06092A864886F70D01010B0500038201010067746B8BB923FCAFF0A96ECB2FDF0624508117C32DC3F8CD08BB22D34A2186F9C1FA419EDCC55AA00B46CBCDF4AF32538053551CA31DC9C7582DF75C11D478DEB76B3E6AE37CED3799ACEA0FAFB9890AE06D21F664A50B27051D95BF5E8E80CCCA141175D5FB9EE070AB0FBB595B842B7F27362CB38A3D1CC4F8A282444D06CA27D9110B6041B0F64A2D6F6C2DBCA02BC6E7F28AAD0967781707F2270BEB9910309BBF78E6B2B583BA62D9DE05191A3F144ABD8D5C471A680616FC00F5F802560D7282F036D3A4C6800C3FECF5E2C6C6C8F345A16AE4AC40C2425D0FD603959FBECFA644D1473373FF4DD14762229EE53E7306C7920D5A5567537CDCEEB63EFBF6")
	if err != nil {
		t.Fatal(err)
	}
	var ovh fdo.VoucherHeader
	if err := cbor.Unmarshal(body, &ovh); err != nil {
		t.Fatal(err)
	}
	t.Logf("Header: %+v", ovh)
}

type Flatten struct {
	B string
	C []byte
}

var _ cbor.FlatMarshaler = (*Flatten)(nil)
var _ cbor.FlatUnmarshaler = (*Flatten)(nil)

func (f Flatten) FlatMarshalCBOR(w io.Writer) error {
	// Note the extra rune!
	if err := cbor.NewEncoder(w).Encode(f.B + "!"); err != nil {
		return err
	}
	return cbor.NewEncoder(w).Encode(f.C)
}

func (f *Flatten) FlatUnmarshalCBOR(r io.Reader) error {
	if err := cbor.NewDecoder(r).Decode(&f.B); err != nil {
		return err
	}
	return cbor.NewDecoder(r).Decode(&f.C)
}

func TestFlatMarshal(t *testing.T) {
	type st struct {
		A int
		Z Flatten `cbor:",flat2"`
	}
	s := st{
		A: 1,
		Z: Flatten{B: "hello", C: []byte{0x02, 0x01, 0x00}},
	}

	expect := []byte{0x83, 0x01, 0x66, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x43, 0x02, 0x01, 0x00}

	got, err := cbor.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expect, got) {
		t.Errorf("expected % x, got % x", expect, got)
	}

	expectS := s
	expectS.Z.B += "!" // added in FlatMarshalCBOR

	var gotS st
	if err := cbor.Unmarshal(got, &gotS); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expectS, gotS) {
		t.Errorf("expected %+v, got %+v", expectS, gotS)
	}
}

func TestFlatMarshalEmbedded(t *testing.T) {
	type st struct {
		A       int
		Flatten `cbor:",flat2"`
	}
	s := st{
		A:       1,
		Flatten: Flatten{B: "hello", C: []byte{0x02, 0x01, 0x00}},
	}

	expect := []byte{0x83, 0x01, 0x66, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0x43, 0x02, 0x01, 0x00}

	got, err := cbor.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expect, got) {
		t.Errorf("expected % x, got % x", expect, got)
	}

	expectS := s
	expectS.B += "!" // added in FlatMarshalCBOR

	var gotS st
	if err := cbor.Unmarshal(got, &gotS); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expectS, gotS) {
		t.Errorf("expected %+v, got %+v", expectS, gotS)
	}
}

func TestMarshalEmbeddedPointer(t *testing.T) {
	type E struct {
		B string
	}
	type st struct {
		A int
		*E
	}

	t.Run("marshal nil", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("the code did not panic")
			}
		}()

		input := st{A: 1}
		_, _ = cbor.Marshal(input)
	})

	t.Run("marshal non-nil", func(t *testing.T) {
		input := st{
			A: 1,
			E: &E{B: "hello"},
		}
		expect := []byte{0x82, 0x01, 0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f}

		got, err := cbor.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(expect, got) {
			t.Errorf("expected % x, got % x", expect, got)
		}
	})

	t.Run("unmarshal", func(t *testing.T) {
		input := []byte{0x82, 0x01, 0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f}
		expect := st{
			A: 1,
			E: &E{B: "hello"},
		}

		var got st
		if err := cbor.Unmarshal(input, &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(expect, got) {
			t.Errorf("expected %+v, got %+v", expect, got)
		}
	})
}
