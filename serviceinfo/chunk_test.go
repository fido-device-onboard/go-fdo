// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package serviceinfo_test

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

func TestChunkOut(t *testing.T) {
	t.Run("zero in, zero out", func(t *testing.T) {
		r, w := serviceinfo.NewChunkOutPipe()
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
		r, w := serviceinfo.NewChunkOutPipe()
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
		r, w := serviceinfo.NewChunkOutPipe()
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
		r, w := serviceinfo.NewChunkOutPipe()
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
		r, w := serviceinfo.NewChunkOutPipe()
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
		r, w := serviceinfo.NewChunkOutPipe()
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
		r, w := serviceinfo.NewChunkInPipe()
		if err := w.Close(); err != nil {
			t.Error(err)
		}
		_, _, ok := r.NextServiceInfo()
		if ok {
			t.Error("expected NextServiceInfo ok=false")
		}
	})

	t.Run("error in", func(t *testing.T) {
		r, w := serviceinfo.NewChunkInPipe()

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
	})

	t.Run("one in", func(t *testing.T) {
		r, w := serviceinfo.NewChunkInPipe()

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
	})

	t.Run("two in (same)", func(t *testing.T) {
		// TODO: Add test
	})

	t.Run("two in (different)", func(t *testing.T) {
		// TODO: Add test
	})
}
