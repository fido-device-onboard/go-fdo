// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package cdn_test

import (
	"encoding/hex"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor/cdn"
)

func TestEncodeText(t *testing.T) {
	t.Run("EncodeText", func(t *testing.T) {
		want := "\"hello\""
		b, err := hex.DecodeString("6568656c6c6f")
		if err != nil {
			t.Errorf("UnMarshalCbor: %v", err)
		}

		got, err := cdn.FromCBOR(b)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestEncodeTrue(t *testing.T) {
	t.Run("EncodeTrue", func(t *testing.T) {
		want := "true"
		b, err := hex.DecodeString("f5")
		if err != nil {
			t.Errorf("UnMarshalCbor: %v", err)
		}

		got, err := cdn.FromCBOR(b)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestEncodeFalse(t *testing.T) {
	t.Run("EncodeFalse", func(t *testing.T) {
		want := "false"
		b, err := hex.DecodeString("f4")
		if err != nil {
			t.Errorf("UnMarshalCbor: %v", err)
		}

		got, err := cdn.FromCBOR(b)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestEncodeNull(t *testing.T) {
	t.Run("EncodeNull", func(t *testing.T) {
		want := "null"
		b, err := hex.DecodeString("f6")
		if err != nil {
			t.Errorf("UnMarshalCbor: %v", err)
		}

		got, err := cdn.FromCBOR(b)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestEncodeUnsinged(t *testing.T) {
	t.Run("EncodeUnsigned", func(t *testing.T) {
		want := "0"
		b, err := hex.DecodeString("00")
		if err != nil {
			t.Errorf("UnMarshalCbor: %v", err)
		}

		got, err := cdn.FromCBOR(b)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestEncodeSigned(t *testing.T) {
	t.Run("EncodeSigned", func(t *testing.T) {
		want := "-1"
		b, err := hex.DecodeString("20")
		if err != nil {
			t.Errorf("UnMarshalCbor: %v", err)
		}

		got, err := cdn.FromCBOR(b)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestEncodeBinary(t *testing.T) {
	t.Run("EncodeBinary", func(t *testing.T) {
		want := "h'68656c6c6f'"
		b, err := hex.DecodeString("4568656c6c6f")
		if err != nil {
			t.Errorf("UnMarshalCbor: %v", err)
		}

		got, err := cdn.FromCBOR(b)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestEncodeArray(t *testing.T) {
	t.Run("EncodeArray", func(t *testing.T) {
		want := "[1, 2, 3]"
		b, err := hex.DecodeString("83010203")
		if err != nil {
			t.Errorf("UnMarshalCbor: %v", err)
		}

		got, err := cdn.FromCBOR(b)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestEncodeMap(t *testing.T) {
	t.Run("EncodeMap", func(t *testing.T) {
		want := "{1: 10, 2: -255}"
		b, err := hex.DecodeString("a2010a0238fe")
		if err != nil {
			t.Errorf("UnMarshalCbor: %v", err)
		}

		got, err := cdn.FromCBOR(b)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestEncodeTag(t *testing.T) {
	t.Run("EncodeTag", func(t *testing.T) {
		want := "32(\"https://google.com\")"
		b, err := hex.DecodeString("d8207268747470733a2f2f676f6f676c652e636f6d")
		if err != nil {
			t.Errorf("UnMarshalCbor: %v", err)
		}

		got, err := cdn.FromCBOR(b)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestDecodeBinary(t *testing.T) {
	t.Run("DecodeBinary", func(t *testing.T) {
		input := "h'68656c6c6f'"
		want := "4568656c6c6f"

		b, err := cdn.ToCBOR(input)
		if err != nil {
			t.Errorf("DecodeString: %v", err)
		}
		got := hex.EncodeToString(b)
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestDecodeText(t *testing.T) {
	t.Run("DecodeText", func(t *testing.T) {
		input := "\"hello\"'"
		want := "6568656c6c6f"

		b, err := cdn.ToCBOR(input)
		if err != nil {
			t.Errorf("DecodeString: %v", err)
		}
		got := hex.EncodeToString(b)
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestDecodeTrue(t *testing.T) {
	t.Run("DecodeTrue", func(t *testing.T) {
		input := "true"
		want := "f5"

		b, err := cdn.ToCBOR(input)
		if err != nil {
			t.Errorf("DecodeString: %v", err)
		}
		got := hex.EncodeToString(b)
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestDecodeFalse(t *testing.T) {
	t.Run("DecodeFalse", func(t *testing.T) {
		input := "false"
		want := "f4"

		b, err := cdn.ToCBOR(input)
		if err != nil {
			t.Errorf("DecodeString: %v", err)
		}
		got := hex.EncodeToString(b)
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestDecodeNull(t *testing.T) {
	t.Run("DecodeNull", func(t *testing.T) {
		input := "null"
		want := "f6"

		b, err := cdn.ToCBOR(input)
		if err != nil {
			t.Errorf("DecodeString: %v", err)
		}
		got := hex.EncodeToString(b)
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestDecodeSigned(t *testing.T) {
	t.Run("DecodeSigned", func(t *testing.T) {
		input := "-1"
		want := "20"

		b, err := cdn.ToCBOR(input)
		if err != nil {
			t.Errorf("DecodeString: %v", err)
		}
		got := hex.EncodeToString(b)
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestDecodeUnsigned(t *testing.T) {
	t.Run("DecodeUnsigned", func(t *testing.T) {
		input := "0"
		want := "00"

		b, err := cdn.ToCBOR(input)
		if err != nil {
			t.Errorf("DecodeString: %v", err)
		}
		got := hex.EncodeToString(b)
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestDecodeTag(t *testing.T) {
	t.Run("DecodeTag", func(t *testing.T) {
		input := "32(\"https://google.com\")"
		want := "d8207268747470733a2f2f676f6f676c652e636f6d"

		b, err := cdn.ToCBOR(input)
		if err != nil {
			t.Errorf("DecodeString: %v", err)
		}
		got := hex.EncodeToString(b)
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestDecodeArray(t *testing.T) {
	t.Run("DecodeArray", func(t *testing.T) {
		input := "[1, 2, 3]"
		want := "83010203"

		b, err := cdn.ToCBOR(input)
		if err != nil {
			t.Errorf("DecodeString: %v", err)
		}
		got := hex.EncodeToString(b)
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestDecodeMap(t *testing.T) {
	t.Run("DecodeMap", func(t *testing.T) {
		input := "{1: 10, 2: -255}"
		want := "a2010a0238fe"

		b, err := cdn.ToCBOR(input)
		if err != nil {
			t.Errorf("DecodeString: %v", err)
		}
		got := hex.EncodeToString(b)
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestDecodeEmptyMap(t *testing.T) {
	t.Run("DecodeEmptyMap", func(t *testing.T) {
		input := "{}"
		want := "a0"

		b, err := cdn.ToCBOR(input)
		if err != nil {
			t.Errorf("DecodeString: %v", err)
		}
		got := hex.EncodeToString(b)
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestDecodeEmptyArray(t *testing.T) {
	t.Run("DecodeEmptyArray", func(t *testing.T) {
		input := "[]"
		want := "80"

		b, err := cdn.ToCBOR(input)
		if err != nil {
			t.Errorf("DecodeString: %v", err)
		}
		got := hex.EncodeToString(b)
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func TestDecodeNestedArray(t *testing.T) {
	t.Run("DecodeNestedArray", func(t *testing.T) {
		input := "[1, [3, 4]]"
		want := "8201820304"

		b, err := cdn.ToCBOR(input)
		if err != nil {
			t.Errorf("DecodeString: %v", err)
		}
		got := hex.EncodeToString(b)
		if got != want {
			t.Errorf("got: %s want: %s", got, want)
		}
	})
}

func FuzzFromCBOR(f *testing.F) {
	mustDecodeHex := func(s string) []byte {
		h, err := hex.DecodeString(s)
		if err != nil {
			panic(err)
		}
		return h
	}

	f.Add(mustDecodeHex("4568656c6c6f"))
	f.Add(mustDecodeHex("6568656c6c6f"))
	f.Add(mustDecodeHex("f5"))
	f.Add(mustDecodeHex("f4"))
	f.Add(mustDecodeHex("f6"))
	f.Add(mustDecodeHex("20"))
	f.Add(mustDecodeHex("00"))
	f.Add(mustDecodeHex("d8207268747470733a2f2f676f6f676c652e636f6d"))
	f.Add(mustDecodeHex("83010203"))
	f.Add(mustDecodeHex("a2010a0238fe"))
	f.Add(mustDecodeHex("a0"))
	f.Add(mustDecodeHex("80"))
	f.Add(mustDecodeHex("8201820304"))

	f.Fuzz(func(t *testing.T, data []byte) {
		t.Logf("%x", data)
		_, _ = cdn.FromCBOR(data)
	})
}

func FuzzToCBOR(f *testing.F) {
	f.Add(`"hello"`)
	f.Add("true")
	f.Add("false")
	f.Add("null")
	f.Add("0")
	f.Add("-1")
	f.Add("h'68656c6c6f'")
	f.Add("[1, 2, 3]")
	f.Add("{1: 10, 2: -255}")
	f.Add(`32("https://google.com")`)
	f.Add("h'68656c6c6f'")
	f.Add("true")
	f.Add("{}")
	f.Add("[]")
	f.Add("[1, [3, 4]]")

	f.Fuzz(func(t *testing.T, data string) {
		t.Logf("%x", data)
		_, _ = cdn.ToCBOR(data)
	})
}
