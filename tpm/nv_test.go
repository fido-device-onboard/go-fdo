// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package tpm_test

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/google/go-tpm/tpm2/transport/simulator"

	"github.com/fido-device-onboard/go-fdo/tpm"
)

func TestNV(t *testing.T) {
	pcrs := tpm.PCRList{
		crypto.SHA256: []int{1, 2, 3, 4},
	}
	const index = 0x0180000F

	t.Run("Read missing", func(t *testing.T) {
		sim, err := simulator.OpenSimulator()
		if err != nil {
			t.Fatalf("error opening opening TPM simulator: %v", err)
		}
		defer func() {
			if err := sim.Close(); err != nil {
				t.Error(err)
			}
		}()

		if _, err := tpm.ReadNV(sim, index, pcrs); err == nil {
			t.Error("expected error reading missing index")
		} else {
			t.Log(err)
		}
	})

	t.Run("Write then read", func(t *testing.T) {
		sim, err := simulator.OpenSimulator()
		if err != nil {
			t.Fatalf("error opening opening TPM simulator: %v", err)
		}
		defer func() {
			if err := sim.Close(); err != nil {
				t.Error(err)
			}
		}()

		expect := []byte("Hello world!")
		if err := tpm.WriteNV(sim, index, expect, pcrs); err != nil {
			t.Fatal(err)
		}
		got, err := tpm.ReadNV(sim, index, pcrs)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(expect, got) {
			t.Fatalf("expected %x, got %x", expect, got)
		}
	})

	t.Run("Write then overwrite then read", func(t *testing.T) {
		sim, err := simulator.OpenSimulator()
		if err != nil {
			t.Fatalf("error opening opening TPM simulator: %v", err)
		}
		defer func() {
			if err := sim.Close(); err != nil {
				t.Error(err)
			}
		}()

		expect := []byte("Hello world!")
		if err := tpm.WriteNV(sim, index, expect[:len(expect)-2], pcrs); err != nil {
			t.Fatal(err)
		}
		if err := tpm.WriteNV(sim, index, expect, pcrs); err != nil {
			t.Fatal(err)
		}
		got, err := tpm.ReadNV(sim, index, pcrs)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(expect, got) {
			t.Fatalf("expected %x, got %x", expect, got)
		}
	})

	t.Run("Write then read with bad policy", func(t *testing.T) {
		sim, err := simulator.OpenSimulator()
		if err != nil {
			t.Fatalf("error opening opening TPM simulator: %v", err)
		}
		defer func() {
			if err := sim.Close(); err != nil {
				t.Error(err)
			}
		}()

		expect := []byte("Hello world!")
		if err := tpm.WriteNV(sim, index, expect, pcrs); err != nil {
			t.Fatal(err)
		}
		if _, err := tpm.ReadNV(sim, index, tpm.PCRList{
			crypto.SHA256: []int{7},
		}); err == nil {
			t.Fatal("expected an error when reading with bad PCR selection")
		} else {
			t.Log(err)
		}
	})

	t.Run("Write then overwrite then read with bad policy", func(t *testing.T) {
		sim, err := simulator.OpenSimulator()
		if err != nil {
			t.Fatalf("error opening opening TPM simulator: %v", err)
		}
		defer func() {
			if err := sim.Close(); err != nil {
				t.Error(err)
			}
		}()

		expect := []byte("Hello world!")
		if err := tpm.WriteNV(sim, index, expect[:len(expect)-2], pcrs); err != nil {
			t.Fatal(err)
		}
		if err := tpm.WriteNV(sim, index, expect, tpm.PCRList{
			crypto.SHA256: []int{7},
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tpm.ReadNV(sim, index, pcrs); err == nil {
			t.Fatal("expected an error when reading with bad PCR selection")
		} else {
			t.Log(err)
		}
	})
}
