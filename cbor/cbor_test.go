// Tests are partially adapted from https://github.com/r4gus/zbor/blob/0.12.2/src/cbor.zig
package cbor_test

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

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
	input := cbor.Tag{Number: 42, EncodeVal: "Life"}
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

func TestEncodeUndefined(t *testing.T) {
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
		} else if !reflect.DeepEqual(got.([]interface{}), expect) {
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
				expectVal: cbor.Tag{Number: 4, DecodedVal: []byte{0x03}},
			},
		} {
			var tag any
			if err := cbor.Unmarshal(test.input, &tag); err != nil {
				t.Errorf("error unmarshaling % x: %v", test.input, err)
			} else if tag.(cbor.Tag).Number != test.expectNum {
				t.Errorf("unmarshaling % x; expected tag number %d, got %d", test.input, test.expectNum, tag.(cbor.Tag).Number)
				continue
			}

			valAddr := reflect.New(reflect.TypeOf(test.expectVal)).Interface()
			if err := cbor.Unmarshal([]byte(tag.(cbor.Tag).DecodedVal), valAddr); err != nil {
				t.Errorf("error unmarshaling tagged value % x: %v", tag.(cbor.Tag).DecodedVal, err)
				continue
			}
			val := reflect.ValueOf(valAddr).Elem().Interface()
			if !reflect.DeepEqual(val, test.expectVal) {
				t.Errorf("unmarshaling % x; expected %#v, got %#v", tag.(cbor.Tag).DecodedVal, test.expectVal, val)
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
	type bstr []byte
	var got []byte
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
			expectVal: cbor.Tag{Number: 4, DecodedVal: []byte{0x03}},
		},
	} {
		var tag cbor.Tag
		if err := cbor.Unmarshal(test.input, &tag); err != nil {
			t.Errorf("error unmarshaling % x: %v", test.input, err)
		} else if tag.Number != test.expectNum {
			t.Errorf("unmarshaling % x; expected tag number %d, got %d", test.input, test.expectNum, tag.Number)
			continue
		}

		valAddr := reflect.New(reflect.TypeOf(test.expectVal)).Interface()
		if err := cbor.Unmarshal([]byte(tag.DecodedVal), valAddr); err != nil {
			t.Errorf("error unmarshaling tagged value % x: %v", tag.DecodedVal, err)
			continue
		}
		val := reflect.ValueOf(valAddr).Elem().Interface()
		if !reflect.DeepEqual(val, test.expectVal) {
			t.Errorf("unmarshaling % x; expected %#v, got %#v", tag.DecodedVal, test.expectVal, val)
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
	t.Run("pointer", func(t *testing.T) {
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
	t.Run("pointer", func(t *testing.T) {
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
