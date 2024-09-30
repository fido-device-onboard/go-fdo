// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package tpm

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"

	"github.com/google/go-tpm/tpm2"
)

// Hmac is a hash.Hash which may contain an error state and must be closed to avoid resource leaks.
type Hmac interface {
	hash.Hash
	Err() error
	io.Closer
}

// NewHmac returns an HMAC for either SHA256 or SHA384 (if supported by the TPM). To avoid a
// resource leak, the hash must always be closed.
func NewHmac(t TPM, h crypto.Hash) (Hmac, error) {
	auth, closeSession, err := tpm2.HMACSession(t, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, fmt.Errorf("create HMAC key authorization session: %w", err)
	}
	return &sessionCloser{
		hmac:         hmac{Device: t, Auth: auth, Hash: h},
		closeSession: closeSession,
	}, nil
}

type sessionCloser struct {
	hmac
	closeSession func() error
}

func (c *sessionCloser) Close() error {
	err := c.hmac.Close()
	if err2 := c.closeSession(); err2 != nil {
		if err != nil {
			return fmt.Errorf("%w (release auth failed: %w)", err, err2)
		}
		return fmt.Errorf("(release auth failed: %w)", err2)
	}
	return err
}

type hmac struct {
	Device TPM
	Auth   tpm2.Session
	Hash   crypto.Hash

	bufSize uint32

	inited    bool
	initErr   error
	keyHandle *tpm2.TPMHandle
	keyName   *tpm2.TPM2BName

	started    bool
	authHandle *tpm2.AuthHandle
	err        error
}

// Generate HMAC key
func (h *hmac) init() {
	if h.inited {
		return
	}

	var tpmAlg tpm2.TPMAlgID
	switch h.Hash {
	case crypto.SHA256:
		tpmAlg = tpm2.TPMAlgSHA256
	case crypto.SHA384:
		tpmAlg = tpm2.TPMAlgSHA384
	default:
		panic("unsupported hash algorithm: " + h.Hash.String())
	}

	// Generate HMAC key from template
	hmacKeyResp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   h.Auth,
		},
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				SignEncrypt:         true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
			},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
				&tpm2.TPMSKeyedHashParms{
					Scheme: tpm2.TPMTKeyedHashScheme{
						Scheme: tpm2.TPMAlgHMAC,
						Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC,
							&tpm2.TPMSSchemeHMAC{
								HashAlg: tpmAlg,
							}),
					},
				}),
		}),
	}.Execute(h.Device)
	if err != nil {
		h.initErr = fmt.Errorf("tpm: create hmac key: %w", err)
		return
	}
	slog.Debug("tpm: generated new HMAC key",
		"handle", fmt.Sprintf("0x%x", hmacKeyResp.ObjectHandle.HandleValue()),
		"name_bytes", len(hmacKeyResp.Name.Buffer),
		"handle_type", fmt.Sprintf("0x%x", hmacKeyResp.ObjectHandle.HandleValue()>>24),
	)
	h.keyHandle, h.keyName = &hmacKeyResp.ObjectHandle, &hmacKeyResp.Name
	h.inited = true
}

// Start a new HMAC sequence
func (h *hmac) start() {
	if h.started {
		return
	}

	// Start HMAC sequence
	sequenceAuth := make([]byte, 16)
	if _, err := rand.Read(sequenceAuth); err != nil {
		h.err = fmt.Errorf("generating auth buffer: %w", err)
		return
	}

	// Start HMAC sequence before first write
	hmacStartResp, err := tpm2.HmacStart{
		Handle: tpm2.AuthHandle{
			Handle: *h.keyHandle,
			Name:   *h.keyName,
			Auth:   h.Auth,
		},
		Auth: tpm2.TPM2BAuth{
			Buffer: sequenceAuth,
		},
		// Null HashAlg will use algorithm from key scheme; see Part 3, Commands, Section 17.2.1
		HashAlg: tpm2.TPMAlgNull,
	}.Execute(h.Device)
	if err != nil {
		h.err = fmt.Errorf("HmacStart: %w", err)
		return
	}
	slog.Debug("tpm: started new HMAC sequence",
		"handle", fmt.Sprintf("0x%x", hmacStartResp.SequenceHandle.HandleValue()),
		"handle_type", fmt.Sprintf("0x%x", h.keyHandle.HandleValue()>>24),
	)

	h.authHandle = &tpm2.AuthHandle{
		Handle: hmacStartResp.SequenceHandle,
		Auth:   tpm2.PasswordAuth(sequenceAuth),
	}
	h.started = true
}

// Write implements the hash.Hash interface and never returns an error.
//
// Caller should check Hash.Err() for underlying TPM sequence errors.
func (h *hmac) Write(p []byte) (int, error) {
	if h.authHandle == nil && h.started {
		h.err = fmt.Errorf("call to write after sum without reset")
		return 0, nil
	}

	h.init()
	h.start()
	if h.err != nil {
		return 0, nil
	}

	if h.authHandle == nil {
		h.err = fmt.Errorf("sequence completed, reset required")
		return 0, nil
	}

	r := bytes.NewBuffer(p)
	buf := make([]byte, h.BlockSize())
	for {
		n, err := io.ReadFull(r, buf)
		if errors.Is(err, io.EOF) {
			return len(p), nil
		}
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			h.err = fmt.Errorf("tpm: adding digest to HMAC: read failed: %w", err)
			return 0, nil
		}

		if _, err := (tpm2.SequenceUpdate{
			SequenceHandle: *h.authHandle,
			Buffer: tpm2.TPM2BMaxBuffer{
				Buffer: buf[:n],
			},
		}).Execute(h.Device); err != nil {
			h.err = fmt.Errorf("tpm: adding digest to HMAC: SequenceUpdated failed: %w", err)
			return 0, nil
		}
	}
}

// Sum implements the hash.Hash interface.
func (h *hmac) Sum(b []byte) []byte {
	if h.authHandle == nil && h.started {
		h.err = fmt.Errorf("multiple calls to sum")
		return b
	}

	h.init()
	h.start()
	if h.err != nil {
		return b
	}

	if h.authHandle == nil {
		h.err = fmt.Errorf("sequence completed, reset required")
		return b
	}

	sequenceCompleteRsp, err := tpm2.SequenceComplete{
		SequenceHandle: *h.authHandle,
		Hierarchy:      tpm2.TPMRHEndorsement,
	}.Execute(h.Device)
	if err != nil {
		h.err = fmt.Errorf("tpm: summing HMAC: SequenceComplete failed: %w", err)
		return b
	}

	// Handle is released after calling SequenceComplete and can no longer be used
	h.authHandle = nil

	return append(b, sequenceCompleteRsp.Result.Buffer...)
}

// Reset preserves the key but resets the digest to its initial state.
func (h *hmac) Reset() {
	if h.authHandle != nil {
		// Complete existing sequence, which will flush the sequenceHandle
		// object See Part 3 Commands Section 17.5.1
		_, err := tpm2.SequenceComplete{
			SequenceHandle: *h.authHandle,
			Hierarchy:      tpm2.TPMRHEndorsement,
		}.Execute(h.Device)
		if err != nil {
			h.err = fmt.Errorf("tpm: hash reset: completing sequence: %w", err)
			return
		}
	}

	// Reset state so that a new hmac sequence will be started on the first write
	h.authHandle = nil
	h.started = false
	h.err = nil
}

// Size implements the hash.Hash interface.
func (h *hmac) Size() int { return h.Hash.Size() }

// BlockSize implements the hash.Hash interface and returns the optimum block size for TPM HMAC
// write operations.
func (h *hmac) BlockSize() int {
	if h.bufSize == 0 {
		h.bufSize = getMaxInputBuffer(h.Device)
	}
	return int(h.bufSize)
}

// Err returns any errors that have occurred since the last reset.
func (h *hmac) Err() error {
	if h.initErr != nil {
		return h.initErr
	}
	return h.err
}

// Close releases all volatile TPM memory consumed for the HMAC.
func (h *hmac) Close() error {
	if h.keyHandle == nil {
		return nil
	}
	if _, err := (tpm2.FlushContext{FlushHandle: h.keyHandle}).Execute(h.Device); err != nil {
		return fmt.Errorf("release key failed: %w", err)
	}
	return nil
}

// defaultMaxDigestBuffer in Octets, Part 3, Commands 17.4.1, this minimum buffer size value is
// allowed. Use Property Tag INPUT_BUFFER for the actual maximum supported by the TPM, see
// GetMaxInputBuffer(t).
const defaultMaxDigestBuffer = 1024

// getMaxInputBuffer returns the TPM's maximum input buffer size parameter, usually a
// TPM2B_MAX_BUFFER; see Part 2, Structures, section 6.13.
func getMaxInputBuffer(t TPM) uint32 {
	capability, err := tpm2.GetCapability{Capability: tpm2.TPMCapTPMProperties}.Execute(t)
	if err != nil {
		slog.Warn("tpm: get capability failed", "error", err)
		return defaultMaxDigestBuffer
	}

	tpmProp, err := capability.CapabilityData.Data.TPMProperties()
	if err != nil {
		slog.Warn("tpm: get capability properties failed", "error", err)
		return defaultMaxDigestBuffer
	}

	for _, prop := range tpmProp.TPMProperty {
		if prop.Property == tpm2.TPMPTInputBuffer {
			return prop.Value
		}
	}

	slog.Info("tpm: max input buffer size undefined, using default", "size", defaultMaxDigestBuffer)
	return defaultMaxDigestBuffer
}
