// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package tpm_test

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"

	"github.com/fido-device-onboard/go-fdo/tpm"
)

// TestDCTPMWriteLock checks spec Table 9 TPMA_NV_WRITE_STCLEAR on DCTPM: the
// index can be written normally, and after the optional TPM2_NV_WriteLock
// (by anyone, empty authValue) further writes are refused until the next
// TPM2_Startup(CLEAR).
func TestDCTPMWriteLock(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("error opening TPM simulator: %v", err)
	}
	defer func() { _ = sim.Close() }()

	name, err := tpm.DefineNVSpace(sim, tpm.DCTPMIndex, 32, tpm.NVProfileDCTPM, false)
	if err != nil {
		t.Fatal(err)
	}
	rp, err := tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(tpm.DCTPMIndex)}.Execute(sim)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := rp.NVPublic.Contents()
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Attributes.WriteSTClear {
		t.Fatalf("DCTPM WriteSTClear not set: %+v", pub.Attributes)
	}
	if pub.Attributes.PlatformCreate {
		t.Fatal("DCTPM must default to the Owner hierarchy (no PlatformCreate)")
	}

	if err := tpm.WriteNV(sim, tpm.DCTPMIndex, name, []byte("before-lock"), tpm.NVProfileDCTPM); err != nil {
		t.Fatalf("write before lock: %v", err)
	}
	if _, err := (tpm2.NVWriteLock{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(tpm.DCTPMIndex), Name: name, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: tpm2.TPMHandle(tpm.DCTPMIndex), Name: name},
	}).Execute(sim); err != nil {
		t.Fatalf("NV_WriteLock: %v", err)
	}
	// The index Name changes when WRITELOCKED is set; re-read it.
	rp, err = tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(tpm.DCTPMIndex)}.Execute(sim)
	if err != nil {
		t.Fatal(err)
	}
	if err := tpm.WriteNV(sim, tpm.DCTPMIndex, rp.NVName, []byte("after-lock"), tpm.NVProfileDCTPM); err == nil {
		t.Fatal("write after NV_WriteLock succeeded")
	}
}
