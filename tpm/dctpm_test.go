// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package tpm_test

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/tpm"
)

type testDCTPM struct {
	Magic uint32
	Note  string
}

func encodeDCTPM(t *testing.T, note string) []byte {
	t.Helper()
	b, err := cbor.Marshal(testDCTPM{Magic: tpm.DCTPMMagic, Note: note})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readDCTPM(t *testing.T, sim transport.TPM) (size uint16, got testDCTPM) {
	t.Helper()
	info, err := tpm.ReadNVCredentials(sim)
	if err != nil {
		t.Fatal(err)
	}
	if !info.HasDCTPM {
		t.Fatal("DCTPM not found")
	}
	if err := tpm.DecodeDCTPM(info.RawDCTPM, &got); err != nil {
		t.Fatalf("DecodeDCTPM: %v", err)
	}
	return info.DCTPMSize, got
}

func TestDecodeDCTPMIgnoresTrailingBytes(t *testing.T) {
	item, err := cbor.Marshal(testDCTPM{Magic: tpm.DCTPMMagic, Note: "x"})
	if err != nil {
		t.Fatal(err)
	}
	padded := append(bytes.Clone(item), make([]byte, 400)...)
	var got testDCTPM
	if err := tpm.DecodeDCTPM(padded, &got); err != nil || got.Note != "x" {
		t.Fatalf("DecodeDCTPM(padded) = %+v, %v", got, err)
	}
	// What readers did before: strict decode rejects the padding.
	if err := cbor.Unmarshal(padded, &got); err == nil {
		t.Fatal("cbor.Unmarshal accepted trailing bytes; test no longer shows the difference")
	}
}

// TestWriteDCTPMInPlace: the first write defines a 512-byte index; later
// writes of a different length go into the same index with one NV_Write.
// Shown with TPM2_NV_WriteLock: an in-place update must be refused while the
// index is locked, whereas undefine+redefine would silently replace it.
func TestWriteDCTPMInPlace(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("error opening TPM simulator: %v", err)
	}
	defer func() { _ = sim.Close() }()

	if err := tpm.WriteDCTPM(sim, encodeDCTPM(t, "first"), false); err != nil {
		t.Fatal(err)
	}
	size, got := readDCTPM(t, sim)
	if size != tpm.DCTPMDefaultSize || got.Note != "first" {
		t.Fatalf("after first write: size %d, %+v", size, got)
	}

	longer := encodeDCTPM(t, "second, and longer than the first")
	if err := tpm.WriteDCTPM(sim, longer, false); err != nil {
		t.Fatal(err)
	}
	size, got = readDCTPM(t, sim)
	if size != tpm.DCTPMDefaultSize || got.Note != "second, and longer than the first" {
		t.Fatalf("after second write: size %d, %+v", size, got)
	}

	// Shorter again: no leftovers from the longer write are decoded.
	if err := tpm.WriteDCTPM(sim, encodeDCTPM(t, "3"), false); err != nil {
		t.Fatal(err)
	}
	if _, got = readDCTPM(t, sim); got.Note != "3" {
		t.Fatalf("after third write: %+v", got)
	}

	rp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(tpm.DCTPMIndex)}.Execute(sim)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (tpm2.NVWriteLock{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(tpm.DCTPMIndex), Name: rp.NVName, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(tpm.DCTPMIndex), Name: rp.NVName},
	}).Execute(sim); err != nil {
		t.Fatal(err)
	}
	if err := tpm.WriteDCTPM(sim, encodeDCTPM(t, "while locked"), false); err == nil {
		t.Fatal("update succeeded on a write-locked DCTPM: the index was replaced, not written in place")
	}
	if _, got = readDCTPM(t, sim); got.Note != "3" {
		t.Fatalf("locked DCTPM changed: %+v", got)
	}
}

// TestWriteDCTPMGrowsLegacyIndex: an index defined at its exact content size
// by older code is redefined when the update does not fit.
func TestWriteDCTPMGrowsLegacyIndex(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("error opening TPM simulator: %v", err)
	}
	defer func() { _ = sim.Close() }()

	small := encodeDCTPM(t, "s")
	name, err := tpm.DefineNVSpace(sim, tpm.DCTPMIndex, uint16(len(small)), tpm.NVProfileDCTPM, false) //nolint:gosec // small test value
	if err != nil {
		t.Fatal(err)
	}
	if err := tpm.WriteNV(sim, tpm.DCTPMIndex, name, small, tpm.NVProfileDCTPM); err != nil {
		t.Fatal(err)
	}
	if err := tpm.WriteDCTPM(sim, encodeDCTPM(t, "does not fit in the old index"), false); err != nil {
		t.Fatal(err)
	}
	size, got := readDCTPM(t, sim)
	if size != tpm.DCTPMDefaultSize || got.Note != "does not fit in the old index" {
		t.Fatalf("size %d, %+v", size, got)
	}
}
