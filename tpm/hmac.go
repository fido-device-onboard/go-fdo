// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package tpm

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Hmac implements hash.Hash using a TPM managed HMAC key.
//
// The Hmac creates a key object inside the TPM and must be unallocated when no
// longer needed.  Accordingly, you must always defer Hmac.Close() when allocating
// a new Hmac.
type Hmac struct {
	// HMAC Algorithm
	Alg crypto.Hash

	// TPM device
	TPM transport.TPMCloser

	authHandle        *tpm2.AuthHandle
	authSessionCloser func() error
	bufSize           uint32
	err               error
	hmacKeyResp       *tpm2.CreatePrimaryResponse
	once              sync.Once
	sas               tpm2.Session
}

// Generate HMAC key and start a new HMAC sequence
func (h *Hmac) init() {
	var err error

	var tpmAlg tpm2.TPMAlgID
	switch h.Alg {
	case crypto.SHA256:
		tpmAlg = tpm2.TPMAlgSHA256
	case crypto.SHA384:
		tpmAlg = tpm2.TPMAlgSHA3384
	default:
		slog.Warn("unsupported hash algorithm, default to SHA256", "alg", h.Alg.String())
		tpmAlg = tpm2.TPMAlgSHA256
	}

	// HMAC_Start requires and authorization session for the key handle
	h.sas, h.authSessionCloser, err = tpm2.HMACSession(h.TPM, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		h.err = fmt.Errorf("create HMAC key authorization session: %w", err)
		return
	}

	// Generate HMAC key from template
	h.hmacKeyResp, err = tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   h.sas,
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
	}.Execute(h.TPM)
	if err != nil {
		h.err = fmt.Errorf("tpm: create hmac key: %w", h.err)
		return
	}

	slog.Debug("tpm: generated new HMAC key",
		"handle", fmt.Sprintf("0x%x", h.hmacKeyResp.ObjectHandle.HandleValue()),
		"name_bytes", len(h.hmacKeyResp.Name.Buffer),
		"handle_type", fmt.Sprintf("0x%x", h.hmacKeyResp.ObjectHandle.HandleValue()>>24))

	h.authHandle, h.err = h.startHmac()
}

// Write implements the hash.Hash interface and never returns an error.
//
// Caller should check Hash.Err() for underlying TPM sequence errors.
func (h *Hmac) Write(p []byte) (int, error) {
	h.once.Do(h.init)

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
		}).Execute(h.TPM); err != nil {
			h.err = fmt.Errorf("tpm: adding digest to HMAC: SequenceUpdated failed: %w", err)
			return 0, nil
		}
	}
}

// Sum implements the hash.Hash interface.
func (h *Hmac) Sum(b []byte) []byte {
	h.once.Do(h.init)

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
	}.Execute(h.TPM)
	if err != nil {
		h.err = fmt.Errorf("tpm: summing HMAC: SequenceComplete failed: %w", err)
		return b
	}

	// Handle is released after calling SequenceComplete and can no longer be used
	h.authHandle = nil

	return append(b, sequenceCompleteRsp.Result.Buffer...)
}

// Reset preserves the key but resets the digest to its initial state.
func (h *Hmac) Reset() {

	if h.authHandle != nil {
		// Complete existing sequence, which will flush the sequenceHandle object
		// See Part 3 Commands Section 17.5.1
		_, err := tpm2.SequenceComplete{
			SequenceHandle: *h.authHandle,
			Hierarchy:      tpm2.TPMRHEndorsement,
		}.Execute(h.TPM)
		if err != nil {
			h.err = fmt.Errorf("tpm: hash reset: completing sequence: %w", err)
			return
		}
	}

	h.authHandle, h.err = h.startHmac()
}

// Size implements the hash.Hash interface.
func (h *Hmac) Size() int {
	return h.Alg.Size()
}

// BlockSize implements the hash.Hash interface and returns the optimum block
// size for TPM HMAC write operations.
func (h *Hmac) BlockSize() int {
	if h.bufSize == 0 {
		h.bufSize = getMaxInputBuffer(h.TPM)
	}

	return int(h.bufSize)
}

// Err returns any errors that have occurred since the last reset.
func (h *Hmac) Err() error { return h.err }

// Close releases all volatile TPM memory consumed for the HMAC
func (h *Hmac) Close() error {
	var (
		errKey  error
		errAuth error
	)

	if h.hmacKeyResp != nil {
		_, errKey = (tpm2.FlushContext{FlushHandle: h.hmacKeyResp.ObjectHandle}).Execute(h.TPM)
	}

	if h.authSessionCloser != nil {
		errAuth = h.authSessionCloser()
	}

	if errKey != nil && errAuth != nil {
		return fmt.Errorf("release key failed: %w (release auth failed: %w)", errKey, errAuth)
	}

	if errKey != nil {
		return fmt.Errorf("release key: %w", errKey)
	}

	if errAuth != nil {
		return fmt.Errorf("release auth: %w", errAuth)
	}

	return nil
}

func (h *Hmac) startHmac() (*tpm2.AuthHandle, error) {
	sequenceAuth := make([]byte, 16)
	if _, err := rand.Read(sequenceAuth); err != nil {
		return nil, fmt.Errorf("generating auth buffer: %w", err)
	}

	// Start HMAC sequence before first write
	hmacStartResp, err := tpm2.HmacStart{
		Handle: tpm2.AuthHandle{
			Handle: h.hmacKeyResp.ObjectHandle,
			Name:   h.hmacKeyResp.Name,
			Auth:   h.sas,
		},
		Auth: tpm2.TPM2BAuth{
			Buffer: sequenceAuth,
		},
		// Null HashAlg will use algorithm from key scheme; see Part 3, Commands, Section 17.2.1
		HashAlg: tpm2.TPMAlgNull,
	}.Execute(h.TPM)
	if err != nil {
		return nil, fmt.Errorf("HmacStart: %w", err)
	}

	slog.Debug("tpm: started new HMAC sequence",
		"handle", fmt.Sprintf("0x%x", hmacStartResp.SequenceHandle.HandleValue()),
		"handle_type", fmt.Sprintf("0x%x", h.hmacKeyResp.ObjectHandle.HandleValue()>>24))

	return &tpm2.AuthHandle{
		Handle: hmacStartResp.SequenceHandle,
		Name: tpm2.TPM2BName{
			// Bug in go-tpm AuthHandle.KnownName() will set this field to nil if []byte{},
			// but per spec the Name of a sequence object is an Empty Buffer, not nil
			// See part 1: Architecture, section 32.4.5
			//
			// TODO: Check behavior in real TPM (simulator does not report an error)
			Buffer: []byte("empty"),
		},
		Auth: tpm2.PasswordAuth(sequenceAuth),
	}, nil
}

// defaultMaxDigestBuffer in Octets, Part 3, Commands 17.4.1, this minimum
// buffer size value is allowed. Use Property Tag INPUT_BUFFER for the actual
// maximum supported by the TPM, see GetMaxInputBuffer(t).
const defaultMaxDigestBuffer = 1024

// getMaxInputBuffer returns the TPM's maximum input buffer size parameter,
// usually a TPM2B_MAX_BUFFER; see Part 2, Structures, section 6.13.
func getMaxInputBuffer(t transport.TPM) uint32 {
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
