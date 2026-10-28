// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package tpm_test

import (
	"bytes"
	"crypto"
	"fmt"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"

	"github.com/fido-device-onboard/go-fdo/tpm"
)

func TestHmac(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("error opening opening TPM simulator: %v", err)
	}
	defer func() {
		if err := sim.Close(); err != nil {
			t.Error(err)
		}
	}()

	for _, alg := range []crypto.Hash{crypto.SHA256, crypto.SHA384} {
		msg := []byte("ThanksForAllTheFish\n")
		expected := tpmHMAC(t, sim, alg, msg)

		// Key is not exported so we compare the results by running the same calculation twice
		t.Run(alg.String(), func(t *testing.T) {
			got := tpmHMAC(t, sim, alg, msg)

			if !bytes.Equal(got, expected) {
				t.Errorf("got %x, expected %x", got, expected)
			}
		})

		t.Run(fmt.Sprintf("%s multi-write", alg), func(t *testing.T) {
			h, err := tpm.NewHmac(sim, alg)
			if err != nil {
				t.Fatalf("new hmac: %v", err)
			}
			defer func() {
				if err := h.Close(); err != nil {
					t.Errorf("close: %v", err)
				}
			}()

			// Multi-write sequence
			_, _ = h.Write(msg[0:3])
			if err := h.Err(); err != nil {
				t.Fatalf("hmac write (1/2): %v", err)
			}

			_, _ = h.Write(msg[3:])
			if err := h.Err(); err != nil {
				t.Fatalf("hmac write (2/2): %v", err)
			}

			got := h.Sum(nil)

			if !bytes.Equal(got, expected) {
				t.Errorf("got %x, expected %x", got, expected)
			}
		})

		t.Run(fmt.Sprintf("%s empty sum", alg), func(t *testing.T) {
			h, err := tpm.NewHmac(sim, alg)
			if err != nil {
				t.Fatalf("new hmac: %v", err)
			}
			defer func() {
				if err := h.Close(); err != nil {
					t.Errorf("close: %v", err)
				}
			}()

			got := h.Sum(nil)
			if err := h.Err(); err != nil {
				t.Errorf("hmac sum: %v", err)
			}

			if len(got) == 0 {
				t.Errorf("empty sum returned 0 bytes")
			}

		})

		t.Run(fmt.Sprintf("%s with reset", alg), func(t *testing.T) {
			h, err := tpm.NewHmac(sim, alg)
			if err != nil {
				t.Fatalf("new hmac: %v", err)
			}
			defer func() {
				if err := h.Close(); err != nil {
					t.Errorf("close: %v", err)
				}
			}()

			_ = h.Sum(nil)
			if err := h.Err(); err != nil {
				t.Fatalf("hmac sum: %v", err)
			}

			// Reset HMAC
			h.Reset()
			_, _ = h.Write(msg)
			if err := h.Err(); err != nil {
				t.Fatalf("write after reset: %v", err)
			}
			got := h.Sum(nil)

			if !bytes.Equal(got, expected) {
				t.Errorf("got %x, expected %x", got, expected)
			}
		})
	}

	t.Run("Multi-HMAC", func(t *testing.T) {
		h1, err := tpm.NewHmac(sim, crypto.SHA256)
		if err != nil {
			t.Fatalf("new hmac 1: %v", err)
		}
		defer func() {
			if err := h1.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
		}()

		h2, err := tpm.NewHmac(sim, crypto.SHA256)
		if err != nil {
			t.Fatalf("new hmac 2: %v", err)
		}
		defer func() {
			if err := h2.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
		}()

		_ = h1.Sum(nil)
		_ = h2.Sum(nil)

		if err := h1.Err(); err != nil {
			t.Fatalf("hmac first key: %v", err)
		}

		if err := h2.Err(); err != nil {
			t.Fatalf("hmac second key: %v", err)
		}
	})

	t.Run("Reset completed", func(t *testing.T) {
		h1, err := tpm.NewHmac(sim, crypto.SHA256)
		if err != nil {
			t.Fatalf("new hmac: %v", err)
		}
		defer func() {
			if err := h1.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
		}()

		_ = h1.Sum(nil)
		if err := h1.Err(); err != nil {
			t.Errorf("no error expected, got %v", err)
		}

		n, _ := h1.Write([]byte{42})
		if n > 0 || h1.Err() == nil {
			t.Errorf("expected write error for completed hmac")
		}

		_ = h1.Sum(nil)
		if h1.Err() == nil {
			t.Errorf("expected sum error for completed hmac")
		}
	})
}

func tpmHMAC(t *testing.T, sim tpm.Closer, alg crypto.Hash, msg []byte) []byte {
	h, err := tpm.NewHmac(sim, alg)
	if err != nil {
		t.Fatalf("new hmac: %v", err)
	}
	defer func() {
		if err := h.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	}()

	n, _ := h.Write(msg)
	if err := h.Err(); err != nil {
		t.Fatalf("hmac write: %v", err)
	}

	if n != len(msg) {
		t.Errorf("hmac write: expected %d bytes, got %d", len(msg), n)
	}

	sum := h.Sum(nil)
	if err := h.Err(); err != nil {
		t.Fatalf("hmac sum: %v", err)
	}

	return sum
}

// TestSpecHmacKeyHash: the FDO HMAC key's hash is fixed to its nameAlg,
// which matches the Device key (TPM spec Table 10). The persisted key computes
// that HMAC, and the TPM refuses the other one (so a Device uses only its own
// key's hash, whatever the Owner's key).
func TestSpecHmacKeyHash(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("error opening TPM simulator: %v", err)
	}
	defer func() { _ = sim.Close() }()

	msg := []byte("ThanksForAllTheFish\n")
	sum := func(alg crypto.Hash) ([]byte, error) {
		h, err := tpm.NewSpecHmac(sim, alg, tpm.HMACKeyHandle)
		if err != nil {
			return nil, err
		}
		defer func() { _ = h.Close() }()
		_, _ = h.Write(msg)
		s := h.Sum(nil)
		return s, h.Err()
	}

	for _, c := range []struct {
		nameAlg     tpm2.TPMAlgID
		own, other  crypto.Hash
		uniqueBytes int
	}{
		{tpm2.TPMAlgSHA256, crypto.SHA256, crypto.SHA384, 32},
		{tpm2.TPMAlgSHA384, crypto.SHA384, crypto.SHA256, 48},
	} {
		us := make([]byte, c.uniqueBytes)
		us[0] = 0x5a
		hk, err := tpm.GenerateSpecHMACKey(sim, c.nameAlg, us)
		if err != nil {
			t.Fatalf("GenerateSpecHMACKey(%v): %v", c.nameAlg, err)
		}
		_ = tpm.EvictPersistentHandle(sim, tpm.HMACKeyHandle)
		if err := tpm.PersistKey(sim, *hk, tpm.HMACKeyHandle); err != nil {
			t.Fatalf("persist: %v", err)
		}
		pub, err := (tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(tpm.HMACKeyHandle)}).Execute(sim)
		if err != nil {
			t.Fatal(err)
		}
		pt, _ := pub.OutPublic.Contents()
		kh, _ := pt.Parameters.KeyedHashDetail()
		d, err := kh.Scheme.Details.HMAC()
		if pt.NameAlg != c.nameAlg || kh.Scheme.Scheme != tpm2.TPMAlgHMAC || err != nil || d.HashAlg != c.nameAlg {
			t.Errorf("nameAlg %v: template nameAlg %v scheme %v hash %+v", c.nameAlg, pt.NameAlg, kh.Scheme.Scheme, d)
		}
		a, err := sum(c.own)
		if err != nil {
			t.Fatalf("nameAlg %v, HMAC %v: %v", c.nameAlg, c.own, err)
		}
		b, _ := sum(c.own)
		if len(a) != c.own.Size() || !bytes.Equal(a, b) {
			t.Errorf("nameAlg %v, HMAC %v: len %d, repeatable %v", c.nameAlg, c.own, len(a), bytes.Equal(a, b))
		}
		if _, err := sum(c.other); err == nil {
			t.Errorf("nameAlg %v key computed HMAC %v; expected the TPM to refuse", c.nameAlg, c.other)
		}
	}
}
