// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

//go:build tpmsim && !tinygo

package tpm

import (
	"io"
	"sync"

	simtools "github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Singleton simulator state.
//
// The MS TPM reference simulator (via go-tpm-tools) does a full manufacture
// reset on every Get() call, wiping all NV indices and persistent handles.
// To allow state to persist across DefaultOpen/Close cycles (enabling
// integration tests that do DI → Close → Reopen → Load), we keep a single
// simulator instance alive for the lifetime of the process.
var (
	simMu   sync.Mutex
	simInst *simtools.Simulator
)

// DefaultOpen opens a TPM software simulator with state persistence.
//
// The first call creates a fresh simulator via GetWithFixedSeedInsecure
// (deterministic hierarchy seeds for reproducibility). Subsequent calls
// return a new transport handle to the SAME simulator instance, so NV
// indices and persistent handles survive across Open/Close cycles.
//
// On reconnection, all stale HMAC sessions, policy sessions, and transient
// objects are flushed to avoid TPM_RC_SESSION_MEMORY errors.
//
// This build was compiled with -tags=tpmsim; it requires CGO.
func DefaultOpen() (Closer, error) {
	simMu.Lock()
	needsFlush := simInst != nil
	if simInst == nil {
		sim, err := simtools.GetWithFixedSeedInsecure(8086)
		if err != nil {
			simMu.Unlock()
			return nil, err
		}
		simInst = sim
	}
	simMu.Unlock()

	if needsFlush {
		// Flush stale sessions and transient objects from previous
		// connections. NV indices and persistent handles are preserved.
		t := transport.FromReadWriteCloser(&simConn{})
		flushVolatileHandles(t)
	}
	return transport.FromReadWriteCloser(&simConn{}), nil
}

// flushVolatileHandles flushes all loaded HMAC sessions, policy sessions,
// and transient objects from the TPM. This prevents TPM_RC_SESSION_MEMORY
// when a new connection reuses the singleton simulator.
func flushVolatileHandles(t TPM) {
	for _, firstHandle := range []tpm2.TPMHandle{
		tpm2.TPMHandle(0x02000000), // HMAC sessions
		tpm2.TPMHandle(0x03000000), // Policy sessions
		tpm2.TPMHandle(0x80000000), // Transient objects
	} {
		resp, err := (tpm2.GetCapability{
			Capability:    tpm2.TPMCapHandles,
			Property:      uint32(firstHandle),
			PropertyCount: 32,
		}).Execute(t)
		if err != nil {
			continue
		}
		handles, err := resp.CapabilityData.Data.Handles()
		if err != nil {
			continue
		}
		for _, h := range handles.Handle {
			_, _ = (tpm2.FlushContext{FlushHandle: h}).Execute(t)
		}
	}
}

// ResetSimulator closes the singleton simulator and releases resources.
// The next DefaultOpen call will create a fresh simulator instance.
// This is intended for test cleanup (e.g., TestMain) and the --tpm-clear
// CLI command when used with the simulator.
func ResetSimulator() {
	simMu.Lock()
	defer simMu.Unlock()

	if simInst != nil {
		_ = simInst.Close()
		simInst = nil
	}
}

// simConn wraps the singleton simulator for a single logical connection.
// Close() is a no-op — it does NOT destroy the underlying simulator,
// allowing NV state to persist across connections.
type simConn struct {
	closed bool
}

func (c *simConn) Read(p []byte) (int, error) {
	simMu.Lock()
	s := simInst
	simMu.Unlock()
	if s == nil || c.closed {
		return 0, io.ErrClosedPipe
	}
	return s.Read(p)
}

func (c *simConn) Write(p []byte) (int, error) {
	simMu.Lock()
	s := simInst
	simMu.Unlock()
	if s == nil || c.closed {
		return 0, io.ErrClosedPipe
	}
	return s.Write(p)
}

func (c *simConn) Close() error {
	c.closed = true
	return nil
}
