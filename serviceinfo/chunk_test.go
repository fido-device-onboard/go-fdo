// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package serviceinfo_test

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

func TestChunkOut(t *testing.T) {
	t.Run("zero in, zero out", func(t *testing.T) {
		r, w := serviceinfo.NewChunkOutPipe(0)
		defer func() {
			if err := r.Close(); err != nil {
				t.Errorf("error closing reader: %v", err)
			}
		}()

		if err := w.Close(); err != nil {
			t.Errorf("unexpected error closing writer: %v", err)
		}

		if chunk, err := r.ReadChunk(1024); err == nil {
			t.Errorf("unxpected chunk read: %#v", chunk)
		} else if !errors.Is(err, io.EOF) {
			t.Errorf("unxpected error reading chunk: %v", err)
		}
	})

	t.Run("error in, error out", func(t *testing.T) {
		r, w := serviceinfo.NewChunkOutPipe(0)
		defer func() {
			if err := r.Close(); err != nil {
				t.Errorf("error closing reader: %v", err)
			}
		}()

		expectedErr := errors.New("uh oh")

		go func() {
			if err := w.NextServiceInfo("moduleA", "messageB"); err != nil {
				t.Errorf("unexpected error calling NextServiceInfo: %v", err)
			}
			if err := w.CloseWithError(expectedErr); err != nil {
				t.Errorf("unexpected error closing writer: %v", err)
			}
		}()

		if chunk, err := r.ReadChunk(1024); err == nil {
			t.Errorf("unxpected chunk read: %#v", chunk)
		} else if !errors.Is(err, expectedErr) {
			t.Errorf("unxpected error reading chunk: %v", err)
		}
	})

	t.Run("one in, one out", func(t *testing.T) {
		r, w := serviceinfo.NewChunkOutPipe(0)
		defer func() {
			if err := r.Close(); err != nil {
				t.Errorf("error closing reader: %v", err)
			}
		}()

		expect := serviceinfo.KV{
			Key: "moduleA:messageB",
			Val: []byte("Hello World!"),
		}

		go func() {
			if err := w.NextServiceInfo("moduleA", "messageB"); err != nil {
				t.Errorf("unexpected error calling NextServiceInfo: %v", err)
			}
			if _, err := w.Write(expect.Val); err != nil {
				t.Errorf("unexpected error writing value: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Errorf("unexpected error closing writer: %v", err)
			}
		}()

		chunk, err := r.ReadChunk(1024)
		if err != nil {
			t.Fatalf("unxpected error reading chunk: %v", err)
		}
		if !reflect.DeepEqual(*chunk, expect) {
			t.Errorf("chunk %#v did not match expected chunk: %#v", *chunk, expect)
		}

		if _, err := r.ReadChunk(1024); !errors.Is(err, io.EOF) {
			t.Fatalf("expected EOF upon reading second chunk, got: %v", err)
		}
	})

	t.Run("one in, two out", func(t *testing.T) {
		r, w := serviceinfo.NewChunkOutPipe(0)
		defer func() {
			if err := r.Close(); err != nil {
				t.Errorf("error closing reader: %v", err)
			}
		}()

		expect := serviceinfo.KV{
			Key: "moduleA:messageB",
			Val: bytes.Repeat([]byte("Hi"), 1000),
		}

		go func() {
			if err := w.NextServiceInfo("moduleA", "messageB"); err != nil {
				t.Errorf("unexpected error calling NextServiceInfo: %v", err)
			}
			if _, err := w.Write(expect.Val); err != nil {
				t.Errorf("unexpected error writing value: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Errorf("unexpected error closing writer: %v", err)
			}
		}()

		chunk1, err := r.ReadChunk(1024)
		if err != nil {
			t.Fatalf("unxpected error reading chunk: %v", err)
		}
		if chunk1.Key != expect.Key {
			t.Fatalf("chunk key %s did not match expected chunk key: %s", chunk1.Key, expect.Key)
		}
		if !bytes.Equal(chunk1.Val, expect.Val[:1003]) {
			t.Fatalf("chunk val [len=%d] did not match expected val", len(chunk1.Val))
		}

		chunk2, err := r.ReadChunk(1024)
		if err != nil {
			t.Fatalf("unxpected error reading chunk: %v", err)
		}
		if chunk2.Key != expect.Key {
			t.Fatalf("chunk key %s did not match expected chunk key: %s", chunk2.Key, expect.Key)
		}
		if !bytes.Equal(chunk2.Val, expect.Val[1003:]) {
			t.Fatalf("chunk val [len=%d] did not match expected val", len(chunk2.Val))
		}

		if _, err := r.ReadChunk(1024); !errors.Is(err, io.EOF) {
			t.Fatalf("expected EOF upon reading third chunk, got: %v", err)
		}
	})

	// two chunks of the same key should not be combined, as this allows the
	// sender to selectively use chunk sizes smaller than the MTU, which may be
	// required by the FSIM
	t.Run("two in (same), two out", func(t *testing.T) {
		r, w := serviceinfo.NewChunkOutPipe(0)
		defer func() {
			if err := r.Close(); err != nil {
				t.Errorf("error closing reader: %v", err)
			}
		}()

		expect := serviceinfo.KV{
			Key: "moduleA:messageB",
			Val: bytes.Repeat([]byte("Hi"), 100),
		}

		go func() {
			if err := w.NextServiceInfo("moduleA", "messageB"); err != nil {
				t.Errorf("unexpected error calling NextServiceInfo: %v", err)
			}
			if _, err := w.Write(expect.Val); err != nil {
				t.Errorf("unexpected error writing value: %v", err)
			}
			if err := w.NextServiceInfo("moduleA", "messageB"); err != nil {
				t.Errorf("unexpected error calling NextServiceInfo: %v", err)
			}
			if _, err := w.Write(expect.Val); err != nil {
				t.Errorf("unexpected error writing value: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Errorf("unexpected error closing writer: %v", err)
			}
		}()

		chunk1, err := r.ReadChunk(1024)
		if err != nil {
			t.Fatalf("unxpected error reading chunk: %v", err)
		}
		if chunk1.Key != expect.Key {
			t.Fatalf("chunk key %s did not match expected chunk key: %s", chunk1.Key, expect.Key)
		}
		if !bytes.Equal(chunk1.Val, expect.Val) {
			t.Fatalf("chunk val [len=%d] did not match expected val", len(chunk1.Val))
		}

		chunk2, err := r.ReadChunk(1024)
		if err != nil {
			t.Fatalf("unxpected error reading chunk: %v", err)
		}
		if chunk2.Key != expect.Key {
			t.Fatalf("chunk key %s did not match expected chunk key: %s", chunk2.Key, expect.Key)
		}
		if !bytes.Equal(chunk2.Val, expect.Val) {
			t.Fatalf("chunk val [len=%d] did not match expected val", len(chunk2.Val))
		}

		if _, err := r.ReadChunk(1024); !errors.Is(err, io.EOF) {
			t.Fatalf("expected EOF upon reading third chunk, got: %v", err)
		}
	})

	t.Run("two in (different), two out", func(t *testing.T) {
		r, w := serviceinfo.NewChunkOutPipe(0)
		defer func() {
			if err := r.Close(); err != nil {
				t.Errorf("error closing reader: %v", err)
			}
		}()

		expect1 := serviceinfo.KV{
			Key: "moduleA:messageB",
			Val: []byte("Hello World!"),
		}
		expect2 := serviceinfo.KV{
			Key: "moduleC:messageD",
			Val: []byte("Goodbye World!"),
		}

		go func() {
			if err := w.NextServiceInfo("moduleA", "messageB"); err != nil {
				t.Errorf("unexpected error calling NextServiceInfo: %v", err)
			}
			if _, err := w.Write(expect1.Val); err != nil {
				t.Errorf("unexpected error writing value: %v", err)
			}
			if err := w.NextServiceInfo("moduleC", "messageD"); err != nil {
				t.Errorf("unexpected error calling NextServiceInfo: %v", err)
			}
			if _, err := w.Write(expect2.Val); err != nil {
				t.Errorf("unexpected error writing value: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Errorf("unexpected error closing writer: %v", err)
			}
		}()

		chunk1, err := r.ReadChunk(1024)
		if err != nil {
			t.Fatalf("unxpected error reading chunk: %v", err)
		}
		if chunk1.Key != expect1.Key {
			t.Fatalf("chunk key %s did not match expected chunk key: %s", chunk1.Key, expect1.Key)
		}
		if !bytes.Equal(chunk1.Val, expect1.Val) {
			t.Fatalf("chunk val [len=%d] did not match expected val", len(chunk1.Val))
		}

		chunk2, err := r.ReadChunk(1024)
		if err != nil {
			t.Fatalf("unxpected error reading chunk: %v", err)
		}
		if chunk2.Key != expect2.Key {
			t.Fatalf("chunk key %s did not match expected chunk key: %s", chunk2.Key, expect2.Key)
		}
		if !bytes.Equal(chunk2.Val, expect2.Val) {
			t.Fatalf("chunk val [len=%d] did not match expected val", len(chunk2.Val))
		}

		if _, err := r.ReadChunk(1024); !errors.Is(err, io.EOF) {
			t.Fatalf("expected EOF upon reading third chunk, got: %v", err)
		}
	})
}

func TestChunkIn(t *testing.T) {
	t.Run("zero in", func(t *testing.T) {
		r, w := serviceinfo.NewChunkInPipe(0)
		if err := w.Close(); err != nil {
			t.Error(err)
		}
		if _, _, ok := r.NextServiceInfo(); ok {
			t.Error("expected NextServiceInfo ok=false")
		}
	})

	t.Run("error in", func(t *testing.T) {
		r, w := serviceinfo.NewChunkInPipe(0)

		expect := serviceinfo.KV{
			Key: "moduleA:messageB",
			Val: []byte("Hello World!"),
		}
		expectErr := errors.New("uh oh")

		go func() {
			if err := w.WriteChunk(&expect); err != nil {
				t.Errorf("error writing chunk: %v", err)
			}
			if err := w.CloseWithError(expectErr); err != nil {
				t.Errorf("error closing with error: %v", err)
			}
		}()
		key, rval, ok := r.NextServiceInfo()
		if !ok {
			t.Error("expected NextServiceInfo ok=true")
		}
		defer func() {
			if err := rval.Close(); err != nil {
				t.Error(err)
			}
		}()
		if key != expect.Key {
			t.Errorf("expected key %s, got %s", expect.Key, key)
		}
		val := make([]byte, 100)
		n, err := rval.Read(val)
		if err != nil {
			t.Errorf("unexpected error while reading unchunked data: %v", err)
		}
		if !bytes.Equal(val[:n], expect.Val) {
			t.Errorf("expected val %x, got %x", expect.Val, val[:n])
		}

		if _, err := rval.Read(val); err != expectErr {
			t.Errorf("expected err %v, got %v", expectErr, err)
		}
		if _, _, ok := r.NextServiceInfo(); ok {
			t.Error("expected NextServiceInfo ok=false")
		}
	})

	t.Run("one in", func(t *testing.T) {
		r, w := serviceinfo.NewChunkInPipe(0)

		expect := serviceinfo.KV{
			Key: "moduleA:messageB",
			Val: []byte("Hello World!"),
		}

		go func() {
			if err := w.WriteChunk(&expect); err != nil {
				t.Errorf("error writing chunk: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Errorf("error closing: %v", err)
			}
		}()
		key, rval, ok := r.NextServiceInfo()
		if !ok {
			t.Error("expected NextServiceInfo ok=true")
		}
		defer func() {
			if err := rval.Close(); err != nil {
				t.Error(err)
			}
		}()
		if key != expect.Key {
			t.Errorf("expected key %s, got %s", expect.Key, key)
		}
		val := make([]byte, 100)
		n, err := rval.Read(val)
		if err != nil {
			t.Errorf("unexpected error while reading unchunked data: %v", err)
		}
		if !bytes.Equal(val[:n], expect.Val) {
			t.Errorf("expected val %x, got %x", expect.Val, val[:n])
		}

		if _, err := rval.Read(val); err != io.EOF {
			t.Errorf("expected EOF, got %v", err)
		}
		if _, _, ok := r.NextServiceInfo(); ok {
			t.Error("expected NextServiceInfo ok=false")
		}
	})

	t.Run("two in (same)", func(t *testing.T) {
		r, w := serviceinfo.NewChunkInPipe(0)

		expectKey := "moduleA:messageB"
		expectVal := []byte("Hello World!")

		go func() {
			if err := w.WriteChunk(&serviceinfo.KV{
				Key: expectKey,
				Val: expectVal[:len(expectVal)/2],
			}); err != nil {
				t.Errorf("error writing chunk: %v", err)
			}
			if err := w.WriteChunk(&serviceinfo.KV{
				Key: expectKey,
				Val: expectVal[len(expectVal)/2:],
			}); err != nil {
				t.Errorf("error writing chunk: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Errorf("error closing: %v", err)
			}
		}()
		key, rval, ok := r.NextServiceInfo()
		if !ok {
			t.Error("expected NextServiceInfo ok=true")
		}
		defer func() {
			if err := rval.Close(); err != nil {
				t.Error(err)
			}
		}()

		if key != expectKey {
			t.Errorf("expected key %s, got %s", expectKey, key)
		}
		val, err := io.ReadAll(rval)
		if err != nil {
			t.Errorf("unexpected error while reading unchunked data: %v", err)
		}
		if !bytes.Equal(val, expectVal) {
			t.Errorf("expected val %s, got %s", expectVal, val)
		}

		if _, _, ok := r.NextServiceInfo(); ok {
			t.Error("expected NextServiceInfo ok=false")
		}
	})

	t.Run("two in (different)", func(t *testing.T) {
		r, w := serviceinfo.NewChunkInPipe(0)

		expect1 := serviceinfo.KV{
			Key: "moduleA:messageB",
			Val: []byte("Hello World!"),
		}
		expect2 := serviceinfo.KV{
			Key: "moduleC:messageD",
			Val: []byte("Goodbye World!"),
		}

		go func() {
			if err := w.WriteChunk(&expect1); err != nil {
				t.Errorf("error writing chunk: %v", err)
			}
			if err := w.WriteChunk(&expect2); err != nil {
				t.Errorf("error writing chunk: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Errorf("error closing: %v", err)
			}
		}()

		key1, rval1, ok := r.NextServiceInfo()
		if !ok {
			t.Error("expected NextServiceInfo ok=true")
		}
		defer func() {
			if err := rval1.Close(); err != nil {
				t.Error(err)
			}
		}()
		if key1 != expect1.Key {
			t.Errorf("expected key %s, got %s", expect1.Key, key1)
		}
		val1, err := io.ReadAll(rval1)
		if err != nil {
			t.Errorf("unexpected error while reading unchunked data: %v", err)
		}
		if !bytes.Equal(val1, expect1.Val) {
			t.Errorf("expected val %s, got %s", expect1.Val, val1)
		}

		key2, rval2, ok := r.NextServiceInfo()
		if !ok {
			t.Error("expected NextServiceInfo ok=true")
		}
		defer func() {
			if err := rval2.Close(); err != nil {
				t.Error(err)
			}
		}()
		if key2 != expect2.Key {
			t.Errorf("expected key %s, got %s", expect2.Key, key2)
		}
		val2, err := io.ReadAll(rval2)
		if err != nil {
			t.Errorf("unexpected error while reading unchunked data: %v", err)
		}
		if !bytes.Equal(val2, expect2.Val) {
			t.Errorf("expected val %s, got %s", expect2.Val, val2)
		}

		if _, _, ok := r.NextServiceInfo(); ok {
			t.Error("expected NextServiceInfo ok=false")
		}
	})
}

func TestForceNewMessage(t *testing.T) {
	r, w := serviceinfo.NewChunkOutPipe(0)
	defer func() {
		if err := r.Close(); err != nil {
			t.Errorf("error closing reader: %v", err)
		}
	}()

	expect := serviceinfo.KV{
		Key: "moduleA:messageB",
		Val: bytes.Repeat([]byte("Hi"), 100),
	}

	go func() {
		if err := w.NextServiceInfo("moduleA", "messageB"); err != nil {
			t.Errorf("unexpected error calling NextServiceInfo: %v", err)
		}
		if _, err := w.Write(expect.Val); err != nil {
			t.Errorf("unexpected error writing value: %v", err)
		}
		if err := w.ForceNewMessage(); err != nil {
			t.Errorf("unexpected error forcing new message: %v", err)
		}
		if err := w.NextServiceInfo("moduleA", "messageB"); err != nil {
			t.Errorf("unexpected error calling NextServiceInfo: %v", err)
		}
		if _, err := w.Write(expect.Val); err != nil {
			t.Errorf("unexpected error writing value: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Errorf("unexpected error closing writer: %v", err)
		}
	}()

	chunk1, err := r.ReadChunk(1024)
	if err != nil {
		t.Fatalf("unxpected error reading chunk: %v", err)
	}
	if chunk1.Key != expect.Key {
		t.Fatalf("chunk key %s did not match expected chunk key: %s", chunk1.Key, expect.Key)
	}
	if !bytes.Equal(chunk1.Val, expect.Val) {
		t.Fatalf("chunk val [len=%d] did not match expected val", len(chunk1.Val))
	}

	if _, err := r.ReadChunk(1024); !errors.Is(err, serviceinfo.ErrSizeTooSmall) {
		t.Fatalf("unxpected error reading chunk: %v", err)
	}

	chunk2, err := r.ReadChunk(1024)
	if err != nil {
		t.Fatalf("unxpected error reading chunk: %v", err)
	}
	if chunk2.Key != expect.Key {
		t.Fatalf("chunk key %s did not match expected chunk key: %s", chunk2.Key, expect.Key)
	}
	if !bytes.Equal(chunk2.Val, expect.Val) {
		t.Fatalf("chunk val [len=%d] did not match expected val", len(chunk2.Val))
	}

	if _, err := r.ReadChunk(1024); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF upon reading third chunk, got: %v", err)
	}
}

func TestChunkOutBuffered(t *testing.T) {
	t.Run("zero in, zero out", func(t *testing.T) {
		r, w := serviceinfo.NewChunkOutPipe(10)
		defer func() {
			if err := r.Close(); err != nil {
				t.Errorf("error closing reader: %v", err)
			}
		}()

		if err := w.Close(); err != nil {
			t.Errorf("unexpected error closing writer: %v", err)
		}

		if chunk, err := r.ReadChunk(1024); err == nil {
			t.Errorf("unxpected chunk read: %#v", chunk)
		} else if !errors.Is(err, io.EOF) {
			t.Errorf("unxpected error reading chunk: %v", err)
		}
	})

	t.Run("error in, error out", func(t *testing.T) {
		r, w := serviceinfo.NewChunkOutPipe(10)
		defer func() {
			if err := r.Close(); err != nil {
				t.Errorf("error closing reader: %v", err)
			}
		}()

		expectedErr := errors.New("uh oh")

		// No longer a goroutine
		if err := w.NextServiceInfo("moduleA", "messageB"); err != nil {
			t.Fatalf("unexpected error calling NextServiceInfo: %v", err)
		}
		if err := w.CloseWithError(expectedErr); err != nil {
			t.Fatalf("unexpected error closing writer: %v", err)
		}

		if chunk, err := r.ReadChunk(1024); err == nil {
			t.Errorf("unxpected chunk read: %#v", chunk)
		} else if !errors.Is(err, expectedErr) {
			t.Errorf("unxpected error reading chunk: %v", err)
		}
	})

	t.Run("one in, one out", func(t *testing.T) {
		r, w := serviceinfo.NewChunkOutPipe(10)
		defer func() {
			if err := r.Close(); err != nil {
				t.Errorf("error closing reader: %v", err)
			}
		}()

		expect := serviceinfo.KV{
			Key: "moduleA:messageB",
			Val: []byte("Hello World!"),
		}

		// No longer a goroutine
		if err := w.NextServiceInfo("moduleA", "messageB"); err != nil {
			t.Errorf("unexpected error calling NextServiceInfo: %v", err)
		}
		if _, err := w.Write(expect.Val); err != nil {
			t.Errorf("unexpected error writing value: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Errorf("unexpected error closing writer: %v", err)
		}

		chunk, err := r.ReadChunk(1024)
		if err != nil {
			t.Fatalf("unxpected error reading chunk: %v", err)
		}
		if !reflect.DeepEqual(*chunk, expect) {
			t.Errorf("chunk %#v did not match expected chunk: %#v", *chunk, expect)
		}

		if _, err := r.ReadChunk(1024); !errors.Is(err, io.EOF) {
			t.Fatalf("expected EOF upon reading second chunk, got: %v", err)
		}
	})

	t.Run("one in, two out", func(t *testing.T) {
		r, w := serviceinfo.NewChunkOutPipe(10)
		defer func() {
			if err := r.Close(); err != nil {
				t.Errorf("error closing reader: %v", err)
			}
		}()

		expect := serviceinfo.KV{
			Key: "moduleA:messageB",
			Val: bytes.Repeat([]byte("Hi"), 1000),
		}

		// No longer a goroutine
		if err := w.NextServiceInfo("moduleA", "messageB"); err != nil {
			t.Errorf("unexpected error calling NextServiceInfo: %v", err)
		}
		if _, err := w.Write(expect.Val); err != nil {
			t.Errorf("unexpected error writing value: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Errorf("unexpected error closing writer: %v", err)
		}

		chunk1, err := r.ReadChunk(1024)
		if err != nil {
			t.Fatalf("unxpected error reading chunk: %v", err)
		}
		if chunk1.Key != expect.Key {
			t.Fatalf("chunk key %s did not match expected chunk key: %s", chunk1.Key, expect.Key)
		}
		if !bytes.Equal(chunk1.Val, expect.Val[:1003]) {
			t.Fatalf("chunk val [len=%d] did not match expected val", len(chunk1.Val))
		}

		chunk2, err := r.ReadChunk(1024)
		if err != nil {
			t.Fatalf("unxpected error reading chunk: %v", err)
		}
		if chunk2.Key != expect.Key {
			t.Fatalf("chunk key %s did not match expected chunk key: %s", chunk2.Key, expect.Key)
		}
		if !bytes.Equal(chunk2.Val, expect.Val[1003:]) {
			t.Fatalf("chunk val [len=%d] did not match expected val", len(chunk2.Val))
		}

		if _, err := r.ReadChunk(1024); !errors.Is(err, io.EOF) {
			t.Fatalf("expected EOF upon reading third chunk, got: %v", err)
		}
	})

	// two chunks of the same key should not be combined, as this allows the
	// sender to selectively use chunk sizes smaller than the MTU, which may be
	// required by the FSIM
	t.Run("two in (same), two out", func(t *testing.T) {
		r, w := serviceinfo.NewChunkOutPipe(10)
		defer func() {
			if err := r.Close(); err != nil {
				t.Errorf("error closing reader: %v", err)
			}
		}()

		expect := serviceinfo.KV{
			Key: "moduleA:messageB",
			Val: bytes.Repeat([]byte("Hi"), 100),
		}

		// No longer a goroutine
		if err := w.NextServiceInfo("moduleA", "messageB"); err != nil {
			t.Errorf("unexpected error calling NextServiceInfo: %v", err)
		}
		if _, err := w.Write(expect.Val); err != nil {
			t.Errorf("unexpected error writing value: %v", err)
		}
		if err := w.NextServiceInfo("moduleA", "messageB"); err != nil {
			t.Errorf("unexpected error calling NextServiceInfo: %v", err)
		}
		if _, err := w.Write(expect.Val); err != nil {
			t.Errorf("unexpected error writing value: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Errorf("unexpected error closing writer: %v", err)
		}

		chunk1, err := r.ReadChunk(1024)
		if err != nil {
			t.Fatalf("unxpected error reading chunk: %v", err)
		}
		if chunk1.Key != expect.Key {
			t.Fatalf("chunk key %s did not match expected chunk key: %s", chunk1.Key, expect.Key)
		}
		if !bytes.Equal(chunk1.Val, expect.Val) {
			t.Fatalf("chunk val [len=%d] did not match expected val", len(chunk1.Val))
		}

		chunk2, err := r.ReadChunk(1024)
		if err != nil {
			t.Fatalf("unxpected error reading chunk: %v", err)
		}
		if chunk2.Key != expect.Key {
			t.Fatalf("chunk key %s did not match expected chunk key: %s", chunk2.Key, expect.Key)
		}
		if !bytes.Equal(chunk2.Val, expect.Val) {
			t.Fatalf("chunk val [len=%d] did not match expected val", len(chunk2.Val))
		}

		if _, err := r.ReadChunk(1024); !errors.Is(err, io.EOF) {
			t.Fatalf("expected EOF upon reading third chunk, got: %v", err)
		}
	})

	t.Run("two in (different), two out", func(t *testing.T) {
		r, w := serviceinfo.NewChunkOutPipe(10)
		defer func() {
			if err := r.Close(); err != nil {
				t.Errorf("error closing reader: %v", err)
			}
		}()

		expect1 := serviceinfo.KV{
			Key: "moduleA:messageB",
			Val: []byte("Hello World!"),
		}
		expect2 := serviceinfo.KV{
			Key: "moduleC:messageD",
			Val: []byte("Goodbye World!"),
		}

		// No longer a goroutine
		if err := w.NextServiceInfo("moduleA", "messageB"); err != nil {
			t.Errorf("unexpected error calling NextServiceInfo: %v", err)
		}
		if _, err := w.Write(expect1.Val); err != nil {
			t.Errorf("unexpected error writing value: %v", err)
		}
		if err := w.NextServiceInfo("moduleC", "messageD"); err != nil {
			t.Errorf("unexpected error calling NextServiceInfo: %v", err)
		}
		if _, err := w.Write(expect2.Val); err != nil {
			t.Errorf("unexpected error writing value: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Errorf("unexpected error closing writer: %v", err)
		}

		chunk1, err := r.ReadChunk(1024)
		if err != nil {
			t.Fatalf("unxpected error reading chunk: %v", err)
		}
		if chunk1.Key != expect1.Key {
			t.Fatalf("chunk key %s did not match expected chunk key: %s", chunk1.Key, expect1.Key)
		}
		if !bytes.Equal(chunk1.Val, expect1.Val) {
			t.Fatalf("chunk val [len=%d] did not match expected val", len(chunk1.Val))
		}

		chunk2, err := r.ReadChunk(1024)
		if err != nil {
			t.Fatalf("unxpected error reading chunk: %v", err)
		}
		if chunk2.Key != expect2.Key {
			t.Fatalf("chunk key %s did not match expected chunk key: %s", chunk2.Key, expect2.Key)
		}
		if !bytes.Equal(chunk2.Val, expect2.Val) {
			t.Fatalf("chunk val [len=%d] did not match expected val", len(chunk2.Val))
		}

		if _, err := r.ReadChunk(1024); !errors.Is(err, io.EOF) {
			t.Fatalf("expected EOF upon reading third chunk, got: %v", err)
		}
	})
}

func TestChunkInBuffered(t *testing.T) {
	t.Run("zero in", func(t *testing.T) {
		r, w := serviceinfo.NewChunkInPipe(10)
		if err := w.Close(); err != nil {
			t.Error(err)
		}
		if _, _, ok := r.NextServiceInfo(); ok {
			t.Error("expected NextServiceInfo ok=false")
		}
	})

	t.Run("error in", func(t *testing.T) {
		r, w := serviceinfo.NewChunkInPipe(10)

		expect := serviceinfo.KV{
			Key: "moduleA:messageB",
			Val: []byte("Hello World!"),
		}
		expectErr := errors.New("uh oh")

		// No longer a goroutine
		if err := w.WriteChunk(&expect); err != nil {
			t.Errorf("error writing chunk: %v", err)
		}
		if err := w.CloseWithError(expectErr); err != nil {
			t.Errorf("error closing with error: %v", err)
		}

		key, rval, ok := r.NextServiceInfo()
		if !ok {
			t.Error("expected NextServiceInfo ok=true")
		}
		defer func() {
			if err := rval.Close(); err != nil {
				t.Error(err)
			}
		}()
		if key != expect.Key {
			t.Errorf("expected key %s, got %s", expect.Key, key)
		}
		val := make([]byte, 100)
		n, err := rval.Read(val)
		if err != nil {
			t.Errorf("unexpected error while reading unchunked data: %v", err)
		}
		if !bytes.Equal(val[:n], expect.Val) {
			t.Errorf("expected val %x, got %x", expect.Val, val[:n])
		}

		if _, err := rval.Read(val); err != expectErr {
			t.Errorf("expected err %v, got %v", expectErr, err)
		}
		if _, _, ok := r.NextServiceInfo(); ok {
			t.Error("expected NextServiceInfo ok=false")
		}
	})

	t.Run("one in", func(t *testing.T) {
		r, w := serviceinfo.NewChunkInPipe(10)

		expect := serviceinfo.KV{
			Key: "moduleA:messageB",
			Val: []byte("Hello World!"),
		}

		// No longer a goroutine
		if err := w.WriteChunk(&expect); err != nil {
			t.Errorf("error writing chunk: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Errorf("error closing: %v", err)
		}

		key, rval, ok := r.NextServiceInfo()
		if !ok {
			t.Error("expected NextServiceInfo ok=true")
		}
		defer func() {
			if err := rval.Close(); err != nil {
				t.Error(err)
			}
		}()
		if key != expect.Key {
			t.Errorf("expected key %s, got %s", expect.Key, key)
		}
		val := make([]byte, 100)
		n, err := rval.Read(val)
		if err != nil {
			t.Errorf("unexpected error while reading unchunked data: %v", err)
		}
		if !bytes.Equal(val[:n], expect.Val) {
			t.Errorf("expected val %x, got %x", expect.Val, val[:n])
		}

		if _, err := rval.Read(val); err != io.EOF {
			t.Errorf("expected EOF, got %v", err)
		}
		if _, _, ok := r.NextServiceInfo(); ok {
			t.Error("expected NextServiceInfo ok=false")
		}
	})

	t.Run("two in (same)", func(t *testing.T) {
		r, w := serviceinfo.NewChunkInPipe(10)

		expectKey := "moduleA:messageB"
		expectVal := []byte("Hello World!")

		// No longer a goroutine
		if err := w.WriteChunk(&serviceinfo.KV{
			Key: expectKey,
			Val: expectVal[:len(expectVal)/2],
		}); err != nil {
			t.Errorf("error writing chunk: %v", err)
		}
		if err := w.WriteChunk(&serviceinfo.KV{
			Key: expectKey,
			Val: expectVal[len(expectVal)/2:],
		}); err != nil {
			t.Errorf("error writing chunk: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Errorf("error closing: %v", err)
		}

		key, rval, ok := r.NextServiceInfo()
		if !ok {
			t.Error("expected NextServiceInfo ok=true")
		}
		defer func() {
			if err := rval.Close(); err != nil {
				t.Error(err)
			}
		}()

		if key != expectKey {
			t.Errorf("expected key %s, got %s", expectKey, key)
		}
		val, err := io.ReadAll(rval)
		if err != nil {
			t.Errorf("unexpected error while reading unchunked data: %v", err)
		}
		if !bytes.Equal(val, expectVal) {
			t.Errorf("expected val %s, got %s", expectVal, val)
		}

		if _, _, ok := r.NextServiceInfo(); ok {
			t.Error("expected NextServiceInfo ok=false")
		}
	})

	t.Run("two in (different)", func(t *testing.T) {
		r, w := serviceinfo.NewChunkInPipe(10)

		expect1 := serviceinfo.KV{
			Key: "moduleA:messageB",
			Val: []byte("Hello World!"),
		}
		expect2 := serviceinfo.KV{
			Key: "moduleC:messageD",
			Val: []byte("Goodbye World!"),
		}

		// No longer a goroutine
		if err := w.WriteChunk(&expect1); err != nil {
			t.Errorf("error writing chunk: %v", err)
		}
		if err := w.WriteChunk(&expect2); err != nil {
			t.Errorf("error writing chunk: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Errorf("error closing: %v", err)
		}

		key1, rval1, ok := r.NextServiceInfo()
		if !ok {
			t.Error("expected NextServiceInfo ok=true")
		}
		defer func() {
			if err := rval1.Close(); err != nil {
				t.Error(err)
			}
		}()
		if key1 != expect1.Key {
			t.Errorf("expected key %s, got %s", expect1.Key, key1)
		}
		val1, err := io.ReadAll(rval1)
		if err != nil {
			t.Errorf("unexpected error while reading unchunked data: %v", err)
		}
		if !bytes.Equal(val1, expect1.Val) {
			t.Errorf("expected val %s, got %s", expect1.Val, val1)
		}

		key2, rval2, ok := r.NextServiceInfo()
		if !ok {
			t.Error("expected NextServiceInfo ok=true")
		}
		defer func() {
			if err := rval2.Close(); err != nil {
				t.Error(err)
			}
		}()
		if key2 != expect2.Key {
			t.Errorf("expected key %s, got %s", expect2.Key, key2)
		}
		val2, err := io.ReadAll(rval2)
		if err != nil {
			t.Errorf("unexpected error while reading unchunked data: %v", err)
		}
		if !bytes.Equal(val2, expect2.Val) {
			t.Errorf("expected val %s, got %s", expect2.Val, val2)
		}

		if _, _, ok := r.NextServiceInfo(); ok {
			t.Error("expected NextServiceInfo ok=false")
		}
	})
}

func TestForceNewMessageBuffered(t *testing.T) {
	r, w := serviceinfo.NewChunkOutPipe(10)
	defer func() {
		if err := r.Close(); err != nil {
			t.Errorf("error closing reader: %v", err)
		}
	}()

	expect := serviceinfo.KV{
		Key: "moduleA:messageB",
		Val: bytes.Repeat([]byte("Hi"), 100),
	}

	// No longer a goroutine
	if err := w.NextServiceInfo("moduleA", "messageB"); err != nil {
		t.Errorf("unexpected error calling NextServiceInfo: %v", err)
	}
	if _, err := w.Write(expect.Val); err != nil {
		t.Errorf("unexpected error writing value: %v", err)
	}
	if err := w.ForceNewMessage(); err != nil {
		t.Errorf("unexpected error forcing new message: %v", err)
	}
	if err := w.NextServiceInfo("moduleA", "messageB"); err != nil {
		t.Errorf("unexpected error calling NextServiceInfo: %v", err)
	}
	if _, err := w.Write(expect.Val); err != nil {
		t.Errorf("unexpected error writing value: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("unexpected error closing writer: %v", err)
	}

	chunk1, err := r.ReadChunk(1024)
	if err != nil {
		t.Fatalf("unxpected error reading chunk: %v", err)
	}
	if chunk1.Key != expect.Key {
		t.Fatalf("chunk key %s did not match expected chunk key: %s", chunk1.Key, expect.Key)
	}
	if !bytes.Equal(chunk1.Val, expect.Val) {
		t.Fatalf("chunk val [len=%d] did not match expected val", len(chunk1.Val))
	}

	if _, err := r.ReadChunk(1024); !errors.Is(err, serviceinfo.ErrSizeTooSmall) {
		t.Fatalf("unxpected error reading chunk: %v", err)
	}

	chunk2, err := r.ReadChunk(1024)
	if err != nil {
		t.Fatalf("unxpected error reading chunk: %v", err)
	}
	if chunk2.Key != expect.Key {
		t.Fatalf("chunk key %s did not match expected chunk key: %s", chunk2.Key, expect.Key)
	}
	if !bytes.Equal(chunk2.Val, expect.Val) {
		t.Fatalf("chunk val [len=%d] did not match expected val", len(chunk2.Val))
	}

	if _, err := r.ReadChunk(1024); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF upon reading third chunk, got: %v", err)
	}
}

func TestCloseDuringNextServiceInfo(t *testing.T) {
	_, ucw := serviceinfo.NewChunkOutPipe(0)

	errc := make(chan error)
	go func() { errc <- ucw.NextServiceInfo("mod", "msg") }()

	// Wait for channel to block
	time.Sleep(50 * time.Millisecond)
	if err := ucw.Close(); err != nil {
		t.Fatal(err)
	}

	if err := <-errc; !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("expected error from closed pipe, got: %v", err)
	}
}
