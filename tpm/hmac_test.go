// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package tpm_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
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

func openSimulator(t *testing.T) tpm.Closer {
	t.Helper()
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("error opening TPM simulator: %v", err)
	}
	t.Cleanup(func() {
		if err := sim.Close(); err != nil {
			t.Error(err)
		}
	})
	return sim
}

func TestHmacSaltedSession(t *testing.T) {
	sim := openSimulator(t)
	before := loadedHandles(t, sim)

	for _, alg := range []crypto.Hash{crypto.SHA256, crypto.SHA384} {
		t.Run(alg.String(), func(t *testing.T) {
			ft := newFaultTPM(sim)
			h, err := tpm.NewHmac(ft, alg)
			if err != nil {
				t.Fatalf("new hmac: %v", err)
			}

			// Construction creates the salting key, starts the session, and releases the salting key, leaving only the session loaded
			constructed := map[tpm2.TPMCC]int{
				tpm2.TPMCCCreatePrimary:    1,
				tpm2.TPMCCStartAuthSession: 1,
				tpm2.TPMCCFlushContext:     1,
			}
			if !maps.Equal(ft.sent, constructed) {
				t.Errorf("construction commands: expected %v, got %v", constructed, ft.sent)
			}
			if objects, sessions := newHandles(t, sim, before); len(objects) != 0 || len(sessions) != 1 {
				t.Errorf("expected only a session to be loaded, got objects %x, sessions %x", objects, sessions)
			}

			// The session authorizes the HMAC key without the salting key
			_, _ = h.Write([]byte("ThanksForAllTheFish\n"))
			if sum := h.Sum(nil); len(sum) != alg.Size() || h.Err() != nil {
				t.Fatalf("hmac: %v", h.Err())
			}
			if err := h.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}
			checkNoLeaks(t, sim, before)
			if ft.sent[tpm2.TPMCCStartAuthSession] != 1 || ft.sent[tpm2.TPMCCEvictControl] != 0 {
				t.Errorf("session restarted or EvictControl used: %v", ft.sent)
			}
		})
	}
}

func TestHmacLifecycle(t *testing.T) {
	sim := openSimulator(t)
	before := loadedHandles(t, sim)
	msg := []byte("ThanksForAllTheFish\n")

	t.Run("repeated construction", func(t *testing.T) {
		for i := range 50 {
			alg := []crypto.Hash{crypto.SHA256, crypto.SHA384}[i%2]
			h, err := tpm.NewHmac(sim, alg)
			if err != nil {
				t.Fatalf("new hmac %d: %v", i, err)
			}
			// Leave some unused, which must not create an HMAC key
			if i%3 != 0 {
				_, _ = h.Write(msg)
				if sum := h.Sum(nil); len(sum) != alg.Size() || h.Err() != nil {
					t.Fatalf("hmac %d: %v", i, h.Err())
				}
			}
			if err := h.Close(); err != nil {
				t.Fatalf("close %d: %v", i, err)
			}
		}
		checkNoLeaks(t, sim, before)
	})

	t.Run("reuse after salting key flush", func(t *testing.T) {
		h, err := tpm.NewHmac(sim, crypto.SHA256)
		if err != nil {
			t.Fatalf("new hmac: %v", err)
		}
		defer func() {
			if err := h.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
		}()
		var expected []byte
		for i := range 10 {
			// Alternate between resetting after a sum and resetting a
			// sequence in progress
			if i%2 == 1 {
				_, _ = h.Write(msg[:5])
				h.Reset()
			}
			_, _ = h.Write(msg)
			got := h.Sum(nil)
			if err := h.Err(); err != nil {
				t.Fatalf("cycle %d: %v", i, err)
			}
			if expected == nil {
				expected = got
			}
			if !bytes.Equal(got, expected) {
				t.Fatalf("cycle %d: got %x, expected %x", i, got, expected)
			}
			h.Reset()
		}
	})

	t.Run("client credential", func(t *testing.T) {
		h256, err := tpm.NewHmac(sim, crypto.SHA256)
		if err != nil {
			t.Fatalf("new hmac: %v", err)
		}
		h384, err := tpm.NewHmac(sim, crypto.SHA384)
		if err != nil {
			t.Fatalf("new hmac: %v", err)
		}
		key, err := tpm.GenerateECKey(sim, elliptic.P384())
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}

		// Without a resource manager, the simulator only has room for three
		// objects, so both HMAC keys, the device key, and an HMAC sequence
		// cannot be loaded at once
		sum := func(h tpm.Hmac) {
			h.Reset()
			_, _ = h.Write(msg)
			if sum := h.Sum(nil); len(sum) != h.Size() || h.Err() != nil {
				t.Errorf("hmac: %v", h.Err())
			}
		}
		sum(h256)
		digest := sha512.Sum384(msg)
		sig, err := key.Sign(nil, digest[:], crypto.SHA384)
		if err != nil {
			t.Errorf("sign: %v", err)
		} else if !ecdsa.VerifyASN1(key.Public().(*ecdsa.PublicKey), digest[:], sig) {
			t.Errorf("invalid signature")
		}
		sum(h256)
		if err := key.Close(); err != nil {
			t.Errorf("close key: %v", err)
		}
		sum(h384)
		sum(h256)
		for _, h := range []tpm.Hmac{h384, h256} {
			if err := h.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
		}
		checkNoLeaks(t, sim, before)
	})

	t.Run("object memory exhausted", func(t *testing.T) {
		objects := fill(t, tpm2.TPMRCObjectMemory, func() (tpm2.TPMHandle, error) {
			rsp, err := tpm2.CreatePrimary{
				PrimaryHandle: tpm2.TPMRHNull,
				InPublic:      tpm2.New2B(tpm2.ECCEKTemplate),
			}.Execute(sim)
			if err != nil {
				return 0, err
			}
			return rsp.ObjectHandle, nil
		})
		defer flush(t, sim, objects...)
		inUse := loadedHandles(t, sim)

		_, err := tpm.NewHmac(sim, crypto.SHA256)
		checkError(t, err, []error{tpm2.TPMRCObjectMemory}, "create ECC P-256 salting key")
		checkNoLeaks(t, sim, inUse)
	})

	t.Run("session memory exhausted", func(t *testing.T) {
		sessions := fill(t, tpm2.TPMRCSessionMemory, func() (tpm2.TPMHandle, error) {
			rsp, err := tpm2.StartAuthSession{
				TPMKey:      tpm2.TPMRHNull,
				Bind:        tpm2.TPMRHNull,
				NonceCaller: tpm2.TPM2BNonce{Buffer: make([]byte, 16)},
				SessionType: tpm2.TPMSEHMAC,
				Symmetric:   tpm2.TPMTSymDef{Algorithm: tpm2.TPMAlgNull},
				AuthHash:    tpm2.TPMAlgSHA256,
			}.Execute(sim)
			if err != nil {
				return 0, err
			}
			return rsp.SessionHandle, nil
		})
		defer flush(t, sim, sessions...)
		inUse := loadedHandles(t, sim)

		_, err := tpm.NewHmac(sim, crypto.SHA256)
		checkError(t, err, []error{tpm2.TPMRCSessionMemory}, "start salted session")
		checkNoLeaks(t, sim, inUse)
	})

	checkNoLeaks(t, sim, before)
}

var errTransport = errors.New("transport interrupted")

func TestHmacConstructionFailure(t *testing.T) {
	sim := openSimulator(t)
	before := loadedHandles(t, sim)

	t.Run("unsupported hash", func(t *testing.T) {
		ft := newFaultTPM(sim)
		for _, alg := range []crypto.Hash{crypto.SHA1, crypto.SHA512, 0} {
			h, err := tpm.NewHmac(ft, alg)
			checkError(t, err, nil, "unsupported hash algorithm")
			if h != nil {
				t.Errorf("%s: expected nil HMAC", alg)
			}
		}
		if len(ft.sent) != 0 {
			t.Errorf("expected no TPM commands, got %v", ft.sent)
		}
	})

	for _, test := range []struct {
		name     string
		faults   []fault
		is       []error
		contains []string
		// Faulted releases never reach the TPM, so the handles stay loaded
		leakSaltKey, leakSession bool
	}{
		{
			name:     "salting key creation TPM error",
			faults:   []fault{{cc: tpm2.TPMCCCreatePrimary, rc: tpm2.TPMRCObjectMemory}},
			is:       []error{tpm2.TPMRCObjectMemory},
			contains: []string{"create ECC P-256 salting key"},
		},
		{
			name:     "salting key creation transport error",
			faults:   []fault{{cc: tpm2.TPMCCCreatePrimary, err: errTransport}},
			is:       []error{errTransport},
			contains: []string{"create ECC P-256 salting key"},
		},
		{
			name:     "salting key unsupported",
			faults:   []fault{{cc: tpm2.TPMCCCreatePrimary, rc: tpm2.TPMRCCurve}},
			is:       []error{tpm2.TPMRCCurve},
			contains: []string{"create ECC P-256 salting key"},
		},
		{
			name:     "session start TPM error",
			faults:   []fault{{cc: tpm2.TPMCCStartAuthSession, rc: tpm2.TPMRCSessionMemory}},
			is:       []error{tpm2.TPMRCSessionMemory},
			contains: []string{"start salted session"},
		},
		{
			name:     "session start transport error",
			faults:   []fault{{cc: tpm2.TPMCCStartAuthSession, err: errTransport}},
			is:       []error{errTransport},
			contains: []string{"start salted session"},
		},
		{
			name: "session start and salting key release fail",
			faults: []fault{
				{cc: tpm2.TPMCCStartAuthSession, rc: tpm2.TPMRCSessionMemory},
				{cc: tpm2.TPMCCFlushContext, err: errTransport},
			},
			is:          []error{tpm2.TPMRCSessionMemory, errTransport},
			contains:    []string{"start salted session", "release salting key"},
			leakSaltKey: true,
		},
		{
			name:        "salting key release fails",
			faults:      []fault{{cc: tpm2.TPMCCFlushContext, rc: tpm2.TPMRCHandle}},
			is:          []error{tpm2.TPMRCHandle},
			contains:    []string{"release salting key"},
			leakSaltKey: true,
		},
		{
			name: "salting key and session release fail",
			faults: []fault{
				{cc: tpm2.TPMCCFlushContext, nth: 0, rc: tpm2.TPMRCHandle},
				{cc: tpm2.TPMCCFlushContext, nth: 1, err: errTransport},
			},
			is:          []error{tpm2.TPMRCHandle, errTransport},
			contains:    []string{"release salting key", "release session"},
			leakSaltKey: true,
			leakSession: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ft := newFaultTPM(sim, test.faults...)
			h, err := tpm.NewHmac(ft, crypto.SHA256)
			if err == nil {
				_ = h.Close()
			}
			checkError(t, err, test.is, append(test.contains, "create HMAC key authorization session")...)
			if ft.sent[tpm2.TPMCCEvictControl] != 0 {
				t.Errorf("EvictControl must not be used")
			}
			releaseLeaked(t, sim, before, test.leakSession)
		})
	}
}

func TestHmacOperationFailure(t *testing.T) {
	sim := openSimulator(t)
	before := loadedHandles(t, sim)
	msg := []byte("ThanksForAllTheFish\n")

	for _, test := range []struct {
		name     string
		fault    fault
		is       error
		contains string
	}{
		{
			// The first CreatePrimary creates the salting key
			name:     "HMAC key creation TPM error",
			fault:    fault{cc: tpm2.TPMCCCreatePrimary, nth: 1, rc: tpm2.TPMRCObjectMemory},
			is:       tpm2.TPMRCObjectMemory,
			contains: "create hmac key",
		},
		{
			name:     "HMAC key creation transport error",
			fault:    fault{cc: tpm2.TPMCCCreatePrimary, nth: 1, err: errTransport},
			is:       errTransport,
			contains: "create hmac key",
		},
		{
			name:     "HMAC start error",
			fault:    fault{cc: tpm2.TPMCCMACStart, rc: tpm2.TPMRCObjectMemory},
			is:       tpm2.TPMRCObjectMemory,
			contains: "HmacStart",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ft := newFaultTPM(sim, test.fault)
			h, err := tpm.NewHmac(ft, crypto.SHA256)
			if err != nil {
				t.Fatalf("new hmac: %v", err)
			}

			if n, _ := h.Write(msg); n != 0 {
				t.Errorf("expected failed write to return 0, got %d", n)
			}
			checkError(t, h.Err(), []error{test.is}, test.contains)

			// No further TPM commands are sent after the error
			faulted := maps.Clone(ft.sent)
			_, _ = h.Write(msg)
			if sum := h.Sum([]byte("prefix")); string(sum) != "prefix" {
				t.Errorf("expected failed sum to return its input, got %x", sum)
			}
			if h.Err() == nil {
				t.Errorf("expected error to persist")
			}
			if !maps.Equal(ft.sent, faulted) {
				t.Errorf("commands sent after failure: before %v, after %v", faulted, ft.sent)
			}

			if err := h.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
			releaseLeaked(t, sim, before, false)
		})
	}
}

func TestHmacCloseFailure(t *testing.T) {
	sim := openSimulator(t)
	before := loadedHandles(t, sim)

	// The first FlushContext releases the salting key during construction,
	// then Close releases the HMAC key and the session
	failKey := fault{cc: tpm2.TPMCCFlushContext, nth: 1, err: errTransport}
	failSession := fault{cc: tpm2.TPMCCFlushContext, nth: 2, rc: tpm2.TPMRCHandle}

	for _, test := range []struct {
		name                 string
		faults               []fault
		is                   []error
		contains             []string
		leakKey, leakSession bool
	}{
		{
			name:     "key release fails",
			faults:   []fault{failKey},
			is:       []error{errTransport},
			contains: []string{"release key failed"},
			leakKey:  true,
		},
		{
			name:        "session release fails",
			faults:      []fault{failSession},
			is:          []error{tpm2.TPMRCHandle},
			contains:    []string{"release auth failed"},
			leakSession: true,
		},
		{
			name:        "both releases fail",
			faults:      []fault{failKey, failSession},
			is:          []error{errTransport, tpm2.TPMRCHandle},
			contains:    []string{"release key failed", "release auth failed"},
			leakKey:     true,
			leakSession: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			ft := newFaultTPM(sim, test.faults...)
			h, err := tpm.NewHmac(ft, crypto.SHA256)
			if err != nil {
				t.Fatalf("new hmac: %v", err)
			}
			_ = h.Sum(nil)
			if err := h.Err(); err != nil {
				t.Fatalf("hmac: %v", err)
			}

			checkError(t, h.Close(), test.is, test.contains...)
			if got := ft.sent[tpm2.TPMCCFlushContext]; got != 3 {
				t.Errorf("expected both releases to be attempted, got %d FlushContext commands", got)
			}
			releaseLeaked(t, sim, before, test.leakSession)
		})
	}
}

// faultTPM wraps a TPM transport to fail selected commands and to count the
// commands sent, by command code.
type faultTPM struct {
	tpm.TPM

	faults []fault
	sent   map[tpm2.TPMCC]int
}

// fault fails the nth (zero-indexed) command with command code cc instead of
// sending it to the TPM. If rc is set, the TPM appears to return that response
// code, otherwise the transport returns err.
type fault struct {
	cc  tpm2.TPMCC
	nth int
	rc  tpm2.TPMRC
	err error
}

func newFaultTPM(t tpm.TPM, faults ...fault) *faultTPM {
	return &faultTPM{TPM: t, faults: faults, sent: make(map[tpm2.TPMCC]int)}
}

func (f *faultTPM) Send(cmd []byte) ([]byte, error) {
	cc := tpm2.TPMCC(binary.BigEndian.Uint32(cmd[6:10]))
	nth := f.sent[cc]
	f.sent[cc]++

	for _, flt := range f.faults {
		if flt.cc != cc || flt.nth != nth {
			continue
		}
		if flt.rc == 0 {
			return nil, flt.err
		}
		rsp := make([]byte, 10)
		binary.BigEndian.PutUint16(rsp[0:], uint16(tpm2.TPMSTNoSessions))
		binary.BigEndian.PutUint32(rsp[2:], uint32(len(rsp)))
		binary.BigEndian.PutUint32(rsp[6:], uint32(flt.rc))
		return rsp, nil
	}
	return f.TPM.Send(cmd)
}

// checkError fails the test unless err matches every target and contains every
// substring.
func checkError(t *testing.T, err error, targets []error, substrings ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
	for _, target := range targets {
		if !errors.Is(err, target) {
			t.Errorf("expected error matching %v, got %v", target, err)
		}
	}
	for _, s := range substrings {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("expected error containing %q, got %v", s, err)
		}
	}
}

// fill allocates TPM resources until the TPM responds with full, and returns
// their handles.
func fill(t *testing.T, full tpm2.TPMRC, alloc func() (tpm2.TPMHandle, error)) []tpm2.TPMHandle {
	t.Helper()
	var handles []tpm2.TPMHandle
	for len(handles) <= 64 {
		h, err := alloc()
		if errors.Is(err, full) {
			return handles
		}
		if err != nil {
			t.Fatalf("allocate: %v", err)
		}
		handles = append(handles, h)
	}
	t.Fatalf("TPM did not respond with %v", full)
	return nil
}

// loadedHandles returns all loaded transient objects and sessions.
func loadedHandles(t *testing.T, sim tpm.TPM) []tpm2.TPMHandle {
	t.Helper()
	var handles []tpm2.TPMHandle
	for _, ht := range []tpm2.TPMHT{tpm2.TPMHTTransient, tpm2.TPMHTHMACSession, tpm2.TPMHTPolicySession} {
		rsp, err := tpm2.GetCapability{
			Capability:    tpm2.TPMCapHandles,
			Property:      uint32(ht) << 24,
			PropertyCount: 64,
		}.Execute(sim)
		if err != nil {
			t.Fatalf("get loaded handles: %v", err)
		}
		list, err := rsp.CapabilityData.Data.Handles()
		if err != nil {
			t.Fatalf("get loaded handles: %v", err)
		}
		for _, h := range list.Handle {
			if h.HandleValue()>>24 == uint32(ht) {
				handles = append(handles, h)
			}
		}
	}
	slices.Sort(handles)
	return handles
}

// newHandles returns the loaded transient objects and sessions which were not
// loaded before.
func newHandles(t *testing.T, sim tpm.TPM, before []tpm2.TPMHandle) (objects, sessions []tpm2.TPMHandle) {
	t.Helper()
	for _, h := range loadedHandles(t, sim) {
		switch {
		case slices.Contains(before, h):
		case h.HandleValue()>>24 == uint32(tpm2.TPMHTTransient):
			objects = append(objects, h)
		default:
			sessions = append(sessions, h)
		}
	}
	return objects, sessions
}

// releaseLeaked checks that exactly one object and one session remain loaded
// since before, if expected, and releases them.
func releaseLeaked(t *testing.T, sim tpm.TPM, before []tpm2.TPMHandle, session bool) {
	t.Helper()
	objects, sessions := newHandles(t, sim, before)
	if (len(objects)) > 1 {
		t.Errorf("unexpected loaded objects %x", objects)
	}
	if (len(sessions) == 1) != session || len(sessions) > 1 {
		t.Errorf("unexpected loaded sessions %x", sessions)
	}
	flush(t, sim, append(objects, sessions...)...)
	checkNoLeaks(t, sim, before)
}

// checkNoLeaks fails the test if the loaded handles differ from before.
func checkNoLeaks(t *testing.T, sim tpm.TPM, before []tpm2.TPMHandle) {
	t.Helper()
	if after := loadedHandles(t, sim); !slices.Equal(before, after) {
		t.Errorf("loaded TPM handles changed: before %x, after %x", before, after)
	}
}

// flush releases handles which were leaked on purpose by a test.
func flush(t *testing.T, sim tpm.TPM, handles ...tpm2.TPMHandle) {
	t.Helper()
	for _, h := range handles {
		if _, err := (tpm2.FlushContext{FlushHandle: h}).Execute(sim); err != nil {
			t.Errorf("flush 0x%x: %v", h.HandleValue(), err)
		}
	}
}
