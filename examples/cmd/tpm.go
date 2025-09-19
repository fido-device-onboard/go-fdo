// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

//go:build !tinygo

package main

import (
	"crypto"
	"crypto/elliptic"
	"flag"
	"fmt"
	"hash"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"

	"github.com/fido-device-onboard/go-fdo/tpm"
)

const tpmSimulatorPath = "simulator"

func tpmCred() (hash.Hash, hash.Hash, crypto.Signer, func() error, error) {
	var diKeyFlagSet bool
	clientFlags.Visit(func(flag *flag.Flag) {
		diKeyFlagSet = diKeyFlagSet || flag.Name == "di-key"
	})
	if !diKeyFlagSet {
		return nil, nil, nil, nil, fmt.Errorf("-di-key must be set explicitly when using a TPM")
	}

	tpmc, err := tpmOpen(tpmPath)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Use TPM keys for HMAC and Device Key
	h256, err := tpm.NewHmac(tpmc, crypto.SHA256)
	if err != nil {
		_ = tpmc.Close()
		return nil, nil, nil, nil, err
	}
	h384, err := tpm.NewHmac(tpmc, crypto.SHA384)
	if err != nil {
		_ = tpmc.Close()
		return nil, nil, nil, nil, err
	}
	var key tpm.Key
	switch diKey {
	case "ec256":
		key, err = tpm.GenerateECKey(tpmc, elliptic.P256())
	case "ec384":
		key, err = tpm.GenerateECKey(tpmc, elliptic.P384())
	case "rsa2048":
		key, err = tpm.GenerateRSAKey(tpmc, 2048)
	case "rsa3072":
		if tpmPath == tpmSimulatorPath {
			err = fmt.Errorf("TPM simulator does not support RSA3072")
		} else {
			key, err = tpm.GenerateRSAKey(tpmc, 3072)
		}
	default:
		err = fmt.Errorf("unsupported key type: %s", diKey)
	}
	if err != nil {
		_ = tpmc.Close()
		return nil, nil, nil, nil, err
	}

	return h256, h384, key, func() error {
		_ = h256.Close()
		_ = h384.Close()
		_ = key.Close()
		return tpmc.Close()
	}, nil
}

func tpmOpen(tpmPath string) (tpm.Closer, error) {
	if tpmPath == tpmSimulatorPath {
		sim, err := simulator.GetWithFixedSeedInsecure(8086)
		if err != nil {
			return nil, err
		}
		return transport.FromReadWriteCloser(sim), nil
	}
	return linuxtpm.Open(tpmPath)
}
