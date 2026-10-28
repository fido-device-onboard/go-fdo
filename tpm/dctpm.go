// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package tpm

import (
	"bytes"
	"fmt"
	"log/slog"

	"github.com/google/go-tpm/tpm2"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// DCTPM.DeviceKeyType values (FDO TPM spec): which key DeviceKeyHandle
// references. go-fdo always provisions a DAK.
const (
	DeviceKeyTypeDAK    = 0 // purpose-built Device Attestation Key
	DeviceKeyTypeIDevID = 1 // TCG IDevID
	DeviceKeyTypeLDevID = 2 // TCG LDevID
)

// DCTPMDefaultSize is the size the DCTPM index is defined with when it is
// first created (FDO TPM spec, DCTPM sizing: minimum 384 bytes, 512
// RECOMMENDED). Later updates are written in place, so the index must leave
// room for credentials that grow (e.g. a longer RVInfo after TO2).
const DCTPMDefaultSize = 512

// DecodeDCTPM decodes the DCTPM structure from the raw contents of the DCTPM
// index. The structure is the first CBOR data item; any bytes after it are
// ignored (FDO TPM spec: the index MAY be larger than the structure).
func DecodeDCTPM(raw []byte, v any) error {
	return cbor.NewDecoder(bytes.NewReader(raw)).Decode(v)
}

// WriteDCTPM stores the encoded DCTPM structure. If the index exists and is
// large enough, it is updated in place with a single TPM2_NV_Write (padded
// with zeros to the index size when that fits the TPM's NV buffer), so an
// interruption leaves either the old or the new contents. Otherwise the index
// is defined with max(DCTPMDefaultSize, len(data)) bytes first.
//
// An existing index that is too small (defined at its exact content size by
// older code) has to be undefined and redefined, which is not atomic; this is
// logged. A Platform-created index cannot be undefined with Owner
// authorization, so that case returns an error.
func WriteDCTPM(t TPM, data []byte, usePlatform bool) error {
	bufMax, err := NVBufferMax(t)
	if err != nil {
		return err
	}
	if len(data) > bufMax {
		return fmt.Errorf("DCTPM is %d bytes, larger than TPM_PT_NV_BUFFER_MAX (%d): cannot be written atomically", len(data), bufMax)
	}

	if rp, err := (tpm2.NVReadPublic{NVIndex: tpm2.TPMHandle(DCTPMIndex)}).Execute(t); err == nil {
		pub, err := rp.NVPublic.Contents()
		if err != nil {
			return fmt.Errorf("DCTPM public area: %w", err)
		}
		if int(pub.DataSize) >= len(data) {
			return WriteNV(t, DCTPMIndex, rp.NVName, padDCTPM(data, int(pub.DataSize), bufMax), NVProfileDCTPM)
		}
		slog.Warn("tpm: DCTPM index too small for update; redefining (not atomic)",
			"size", pub.DataSize, "need", len(data))
		if err := UndefineNVSpace(t, DCTPMIndex); err != nil {
			return fmt.Errorf("DCTPM index is %d bytes, %d needed, and cannot be resized: %w", pub.DataSize, len(data), err)
		}
	}

	size := max(DCTPMDefaultSize, len(data))
	name, err := DefineNVSpace(t, DCTPMIndex, uint16(size), NVProfileDCTPM, usePlatform) //nolint:gosec // size <= bufMax checked above, or 512
	if err != nil {
		return err
	}
	return WriteNV(t, DCTPMIndex, name, padDCTPM(data, size, bufMax), NVProfileDCTPM)
}

// padDCTPM zero-fills data to the index size if that still fits one
// TPM2_NV_Write; otherwise only the structure itself is written.
func padDCTPM(data []byte, size, bufMax int) []byte {
	if size > bufMax || size <= len(data) {
		return data
	}
	out := make([]byte, size)
	copy(out, data)
	return out
}

// NVBufferMax returns TPM_PT_NV_BUFFER_MAX, the largest TPM2_NV_Read or
// TPM2_NV_Write the TPM accepts in one command.
func NVBufferMax(t TPM) (int, error) {
	resp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTNVBufferMax),
		PropertyCount: 1,
	}.Execute(t)
	if err != nil {
		return 0, fmt.Errorf("GetCapability(TPM_PT_NV_BUFFER_MAX): %w", err)
	}
	props, err := resp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, fmt.Errorf("GetCapability(TPM_PT_NV_BUFFER_MAX): %w", err)
	}
	for _, p := range props.TPMProperty {
		if p.Property == tpm2.TPMPTNVBufferMax {
			return int(p.Value), nil
		}
	}
	return 0, fmt.Errorf("TPM did not report TPM_PT_NV_BUFFER_MAX")
}
