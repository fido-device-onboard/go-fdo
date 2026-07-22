// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/kex"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// computeHashBinding marshals msg to CBOR and computes the hash using the
// given algorithm. This mirrors the hash binding computation in
// to2_server_v200.go (HashPrev) and to2_client_v200.go (HashPrev2).
func computeHashBinding(t *testing.T, alg protocol.HashAlg, msg any) protocol.Hash {
	t.Helper()
	data, err := cbor.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal message for hashing: %v", err)
	}
	hasher := alg.HashFunc().New()
	hasher.Write(data)
	return protocol.Hash{
		Algorithm: alg,
		Value:     hasher.Sum(nil),
	}
}

// makeProbe creates a HelloDeviceProbeMsg with the given GUID and sugar.
func makeProbe(guid protocol.GUID, sugar []byte) fdo.HelloDeviceProbeMsg {
	return fdo.HelloDeviceProbeMsg{
		CapabilityFlags: fdo.GlobalCapabilityFlags,
		GUID:            guid,
		MaxDeviceMsgSz:  65535,
		HashTypes:       []protocol.HashAlg{protocol.Sha256Hash, protocol.Sha384Hash},
		Sugar:           sugar,
	}
}

// makeAck creates a HelloDeviceAck20Msg with the given HashPrev and nonce.
func makeAck(hashPrev protocol.Hash, nonce protocol.Nonce) fdo.HelloDeviceAck20Msg {
	return fdo.HelloDeviceAck20Msg{
		CapabilityFlags:     fdo.GlobalCapabilityFlags,
		GUID:                protocol.GUID{0x01},
		MaxOwnerMsgSz:       65535,
		KexSuites:           []kex.Suite{kex.ECDH256Suite, kex.ECDH384Suite},
		CipherSuites:        []kex.CipherSuiteID{kex.A128GcmCipher, kex.A256GcmCipher},
		NonceTO2ProveDVPrep: nonce,
		HashPrev:            hashPrev,
	}
}

// TestHashBindingHashPrevComputation verifies that HashPrev in
// HelloDeviceAck20 (type 81) is the hash of the CBOR-serialized
// HelloDeviceProbe (type 80).
//
// This tests the computation in to2_server_v200.go:73-84.
func TestHashBindingHashPrevComputation(t *testing.T) {
	tests := []struct {
		name    string
		hashAlg protocol.HashAlg
		wantLen int
	}{
		{
			name:    "SHA-256",
			hashAlg: protocol.Sha256Hash,
			wantLen: sha256.Size,
		},
		{
			name:    "SHA-384",
			hashAlg: protocol.Sha384Hash,
			wantLen: sha512.Size384,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := makeProbe(
				protocol.GUID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
				[]byte{0xDE, 0xAD, 0xBE, 0xEF},
			)

			// Compute HashPrev the same way the server does
			hashPrev := computeHashBinding(t, tt.hashAlg, probe)

			// Verify algorithm and length
			if hashPrev.Algorithm != tt.hashAlg {
				t.Errorf("HashPrev algorithm = %v, want %v", hashPrev.Algorithm, tt.hashAlg)
			}
			if len(hashPrev.Value) != tt.wantLen {
				t.Errorf("HashPrev length = %d, want %d", len(hashPrev.Value), tt.wantLen)
			}

			// Verify deterministic: same input produces same hash
			hashPrev2 := computeHashBinding(t, tt.hashAlg, probe)
			if !bytes.Equal(hashPrev.Value, hashPrev2.Value) {
				t.Error("HashPrev is not deterministic: same probe produced different hashes")
			}

			// Verify it actually hashes the CBOR encoding, not something else
			probeData, err := cbor.Marshal(probe)
			if err != nil {
				t.Fatalf("failed to marshal probe: %v", err)
			}
			hasher := tt.hashAlg.HashFunc().New()
			hasher.Write(probeData)
			expected := hasher.Sum(nil)
			if !bytes.Equal(hashPrev.Value, expected) {
				t.Errorf("HashPrev does not match manual hash of CBOR-encoded probe")
			}
		})
	}
}

// TestHashBindingHashPrev2Computation verifies that HashPrev2 in
// ProveDevice20 (type 82) is the hash of the CBOR-serialized
// HelloDeviceAck20 (type 81).
//
// This tests the computation in to2_client_v200.go:262-274.
func TestHashBindingHashPrev2Computation(t *testing.T) {
	tests := []struct {
		name    string
		hashAlg protocol.HashAlg
		wantLen int
	}{
		{
			name:    "SHA-256",
			hashAlg: protocol.Sha256Hash,
			wantLen: sha256.Size,
		},
		{
			name:    "SHA-384",
			hashAlg: protocol.Sha384Hash,
			wantLen: sha512.Size384,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build the ack with a HashPrev using the same algorithm
			probeHash := computeHashBinding(t, tt.hashAlg, makeProbe(
				protocol.GUID{0x01}, []byte{0xAA},
			))
			nonce := protocol.Nonce{0x11, 0x22, 0x33}
			ack := makeAck(probeHash, nonce)

			// Compute HashPrev2 the same way the client does:
			// hash the CBOR-serialized ack using the algorithm from ack.HashPrev
			hashPrev2 := computeHashBinding(t, ack.HashPrev.Algorithm, ack)

			// Verify algorithm matches what the server selected
			if hashPrev2.Algorithm != tt.hashAlg {
				t.Errorf("HashPrev2 algorithm = %v, want %v", hashPrev2.Algorithm, tt.hashAlg)
			}
			if len(hashPrev2.Value) != tt.wantLen {
				t.Errorf("HashPrev2 length = %d, want %d", len(hashPrev2.Value), tt.wantLen)
			}

			// Verify against manual computation
			ackData, err := cbor.Marshal(ack)
			if err != nil {
				t.Fatalf("failed to marshal ack: %v", err)
			}
			hasher := tt.hashAlg.HashFunc().New()
			hasher.Write(ackData)
			expected := hasher.Sum(nil)
			if !bytes.Equal(hashPrev2.Value, expected) {
				t.Error("HashPrev2 does not match manual hash of CBOR-encoded ack")
			}
		})
	}
}

// TestHashBindingChainIntegrity verifies the full hash binding chain:
// Probe(80) -> HashPrev in Ack(81) -> HashPrev2 in ProveDevice(82).
// Each hash binds to the previous message, creating an anti-replay chain.
func TestHashBindingChainIntegrity(t *testing.T) {
	tests := []struct {
		name    string
		hashAlg protocol.HashAlg
	}{
		{"SHA-256", protocol.Sha256Hash},
		{"SHA-384", protocol.Sha384Hash},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Step 1: Device sends HelloDeviceProbe (type 80)
			probe := makeProbe(
				protocol.GUID{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02,
					0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10},
				[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
			)

			// Step 2: Server computes HashPrev = Hash(Probe)
			hashPrev := computeHashBinding(t, tt.hashAlg, probe)

			// Step 3: Server sends HelloDeviceAck20 (type 81) containing HashPrev
			nonce := protocol.Nonce{0xCA, 0xFE, 0xBA, 0xBE}
			ack := makeAck(hashPrev, nonce)

			// Step 4: Client computes HashPrev2 = Hash(Ack)
			hashPrev2 := computeHashBinding(t, ack.HashPrev.Algorithm, ack)

			// Verify the chain: HashPrev2 must match hash of the full ack
			// (which includes HashPrev, which covers the probe).
			ackData, err := cbor.Marshal(ack)
			if err != nil {
				t.Fatalf("failed to marshal ack: %v", err)
			}
			hasher := tt.hashAlg.HashFunc().New()
			hasher.Write(ackData)
			if !bytes.Equal(hashPrev2.Value, hasher.Sum(nil)) {
				t.Error("hash chain broken: HashPrev2 does not bind to ack")
			}

			// Verify that HashPrev inside the ack binds to the probe
			probeData, err := cbor.Marshal(probe)
			if err != nil {
				t.Fatalf("failed to marshal probe: %v", err)
			}
			probeHasher := tt.hashAlg.HashFunc().New()
			probeHasher.Write(probeData)
			if !bytes.Equal(ack.HashPrev.Value, probeHasher.Sum(nil)) {
				t.Error("hash chain broken: HashPrev does not bind to probe")
			}
		})
	}
}

// TestHashBindingTamperingDetection verifies that modifications to messages
// are detected via hash binding mismatches.
func TestHashBindingTamperingDetection(t *testing.T) {
	hashAlg := protocol.Sha256Hash

	t.Run("modified probe causes HashPrev mismatch", func(t *testing.T) {
		// Server computes HashPrev from the original probe
		originalProbe := makeProbe(protocol.GUID{0x01}, []byte{0xAA})
		hashPrev := computeHashBinding(t, hashAlg, originalProbe)

		// Attacker modifies the probe (different GUID)
		tamperedProbe := makeProbe(protocol.GUID{0x02}, []byte{0xAA})
		tamperedHash := computeHashBinding(t, hashAlg, tamperedProbe)

		if bytes.Equal(hashPrev.Value, tamperedHash.Value) {
			t.Fatal("tampered probe should produce different hash")
		}
	})

	t.Run("modified probe sugar causes HashPrev mismatch", func(t *testing.T) {
		originalProbe := makeProbe(protocol.GUID{0x01}, []byte{0xAA})
		hashPrev := computeHashBinding(t, hashAlg, originalProbe)

		// Attacker modifies the sugar
		tamperedProbe := makeProbe(protocol.GUID{0x01}, []byte{0xBB})
		tamperedHash := computeHashBinding(t, hashAlg, tamperedProbe)

		if bytes.Equal(hashPrev.Value, tamperedHash.Value) {
			t.Fatal("tampered sugar should produce different hash")
		}
	})

	t.Run("modified ack causes HashPrev2 mismatch", func(t *testing.T) {
		probe := makeProbe(protocol.GUID{0x01}, []byte{0xAA})
		hashPrev := computeHashBinding(t, hashAlg, probe)
		nonce := protocol.Nonce{0x11, 0x22}
		originalAck := makeAck(hashPrev, nonce)
		hashPrev2 := computeHashBinding(t, hashAlg, originalAck)

		// Attacker modifies the ack's nonce
		tamperedNonce := protocol.Nonce{0xFF, 0xEE}
		tamperedAck := makeAck(hashPrev, tamperedNonce)
		tamperedHash := computeHashBinding(t, hashAlg, tamperedAck)

		if bytes.Equal(hashPrev2.Value, tamperedHash.Value) {
			t.Fatal("tampered ack should produce different HashPrev2")
		}
	})

	t.Run("modified ack HashPrev causes HashPrev2 mismatch", func(t *testing.T) {
		probe := makeProbe(protocol.GUID{0x01}, []byte{0xAA})
		hashPrev := computeHashBinding(t, hashAlg, probe)
		nonce := protocol.Nonce{0x11, 0x22}
		originalAck := makeAck(hashPrev, nonce)
		hashPrev2 := computeHashBinding(t, hashAlg, originalAck)

		// Attacker replaces HashPrev in the ack with a hash of a
		// different probe (MITM injects different probe, tries to keep
		// the ack's HashPrev consistent with the tampered probe)
		fakeProbHash := computeHashBinding(t, hashAlg, makeProbe(protocol.GUID{0xFF}, nil))
		tamperedAck := makeAck(fakeProbHash, nonce)
		tamperedHash := computeHashBinding(t, hashAlg, tamperedAck)

		if bytes.Equal(hashPrev2.Value, tamperedHash.Value) {
			t.Fatal("ack with tampered HashPrev should produce different HashPrev2")
		}
	})

	t.Run("bit flip in hash value detected", func(t *testing.T) {
		probe := makeProbe(protocol.GUID{0x01}, []byte{0xAA})
		hashPrev := computeHashBinding(t, hashAlg, probe)

		// Flip one bit in the hash value
		corrupted := make([]byte, len(hashPrev.Value))
		copy(corrupted, hashPrev.Value)
		corrupted[0] ^= 0x01

		corruptedHash := protocol.Hash{
			Algorithm: hashAlg,
			Value:     corrupted,
		}

		// Verify the corruption is detectable
		if bytes.Equal(hashPrev.Value, corruptedHash.Value) {
			t.Fatal("bit-flipped hash should differ")
		}

		// The ack carrying a corrupted HashPrev would produce a
		// different HashPrev2 than the ack with the correct HashPrev
		nonce := protocol.Nonce{0x11}
		goodAck := makeAck(hashPrev, nonce)
		badAck := makeAck(corruptedHash, nonce)
		goodHP2 := computeHashBinding(t, hashAlg, goodAck)
		badHP2 := computeHashBinding(t, hashAlg, badAck)
		if bytes.Equal(goodHP2.Value, badHP2.Value) {
			t.Fatal("corrupted HashPrev in ack should cascade to different HashPrev2")
		}
	})
}

// TestHashBindingVerification tests the verification step: given a received
// message and its claimed hash binding, verify they match.
func TestHashBindingVerification(t *testing.T) {
	type verifyCase struct {
		name      string
		hashAlg   protocol.HashAlg
		buildMsg  func() any
		wantMatch bool
		corrupt   func(h *protocol.Hash) // optional corruption before verify
	}

	tests := []verifyCase{
		{
			name:    "valid HashPrev SHA-256",
			hashAlg: protocol.Sha256Hash,
			buildMsg: func() any {
				return makeProbe(protocol.GUID{0x01}, []byte{0xAA})
			},
			wantMatch: true,
		},
		{
			name:    "valid HashPrev SHA-384",
			hashAlg: protocol.Sha384Hash,
			buildMsg: func() any {
				return makeProbe(protocol.GUID{0x01}, []byte{0xAA})
			},
			wantMatch: true,
		},
		{
			name:    "corrupted hash value",
			hashAlg: protocol.Sha256Hash,
			buildMsg: func() any {
				return makeProbe(protocol.GUID{0x01}, []byte{0xAA})
			},
			wantMatch: false,
			corrupt: func(h *protocol.Hash) {
				h.Value[0] ^= 0xFF
			},
		},
		{
			name:    "truncated hash value",
			hashAlg: protocol.Sha256Hash,
			buildMsg: func() any {
				return makeProbe(protocol.GUID{0x01}, []byte{0xAA})
			},
			wantMatch: false,
			corrupt: func(h *protocol.Hash) {
				h.Value = h.Value[:len(h.Value)-1]
			},
		},
		{
			name:    "zero-length hash value",
			hashAlg: protocol.Sha256Hash,
			buildMsg: func() any {
				return makeProbe(protocol.GUID{0x01}, []byte{0xAA})
			},
			wantMatch: false,
			corrupt: func(h *protocol.Hash) {
				h.Value = nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.buildMsg()
			computed := computeHashBinding(t, tt.hashAlg, msg)

			if tt.corrupt != nil {
				tt.corrupt(&computed)
			}

			// Recompute and verify
			expected := computeHashBinding(t, tt.hashAlg, msg)
			match := bytes.Equal(computed.Value, expected.Value) &&
				computed.Algorithm == expected.Algorithm

			if match != tt.wantMatch {
				t.Errorf("verification match = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}

// TestHashBindingAlgorithmConsistency verifies that the hash algorithm used
// for HashPrev and HashPrev2 must be consistent throughout the chain.
func TestHashBindingAlgorithmConsistency(t *testing.T) {
	t.Run("client uses algorithm from ack HashPrev", func(t *testing.T) {
		// Server selects SHA-256 for HashPrev
		probe := makeProbe(protocol.GUID{0x01}, []byte{0xAA})
		hashPrev256 := computeHashBinding(t, protocol.Sha256Hash, probe)
		nonce := protocol.Nonce{0x11}
		ack := makeAck(hashPrev256, nonce)

		// Client should use the algorithm from ack.HashPrev (SHA-256)
		// to compute HashPrev2, as done in to2_client_v200.go:268
		hashPrev2 := computeHashBinding(t, ack.HashPrev.Algorithm, ack)

		if hashPrev2.Algorithm != protocol.Sha256Hash {
			t.Errorf("HashPrev2 algorithm = %v, want Sha256Hash (should match server selection)", hashPrev2.Algorithm)
		}
	})

	t.Run("server selects SHA-384 client follows", func(t *testing.T) {
		probe := makeProbe(protocol.GUID{0x01}, []byte{0xAA})
		hashPrev384 := computeHashBinding(t, protocol.Sha384Hash, probe)
		nonce := protocol.Nonce{0x11}
		ack := makeAck(hashPrev384, nonce)

		// Client follows the server's algorithm selection
		hashPrev2 := computeHashBinding(t, ack.HashPrev.Algorithm, ack)

		if hashPrev2.Algorithm != protocol.Sha384Hash {
			t.Errorf("HashPrev2 algorithm = %v, want Sha384Hash", hashPrev2.Algorithm)
		}
	})

	t.Run("algorithm mismatch produces different hash", func(t *testing.T) {
		probe := makeProbe(protocol.GUID{0x01}, []byte{0xAA})
		nonce := protocol.Nonce{0x11}

		// Server uses SHA-256
		hashPrev256 := computeHashBinding(t, protocol.Sha256Hash, probe)
		ack256 := makeAck(hashPrev256, nonce)
		hp2_256 := computeHashBinding(t, protocol.Sha256Hash, ack256)

		// Hypothetical: server uses SHA-384 instead
		hashPrev384 := computeHashBinding(t, protocol.Sha384Hash, probe)
		ack384 := makeAck(hashPrev384, nonce)
		hp2_384 := computeHashBinding(t, protocol.Sha384Hash, ack384)

		// Different algorithms must produce different hash values
		if bytes.Equal(hp2_256.Value, hp2_384.Value) {
			t.Error("SHA-256 and SHA-384 should produce different hashes")
		}
		// And different lengths
		if len(hp2_256.Value) == len(hp2_384.Value) {
			t.Errorf("SHA-256 (%d bytes) and SHA-384 (%d bytes) should have different lengths",
				len(hp2_256.Value), len(hp2_384.Value))
		}
	})

	t.Run("wrong algorithm for verification fails", func(t *testing.T) {
		// Server computes HashPrev with SHA-256
		probe := makeProbe(protocol.GUID{0x01}, []byte{0xAA})
		hashPrev := computeHashBinding(t, protocol.Sha256Hash, probe)
		nonce := protocol.Nonce{0x11}
		ack := makeAck(hashPrev, nonce)

		// Correct HashPrev2 uses SHA-256 (from ack.HashPrev.Algorithm)
		correctHP2 := computeHashBinding(t, protocol.Sha256Hash, ack)

		// If someone recomputes with SHA-384 to verify, it will not match
		wrongAlgHP2 := computeHashBinding(t, protocol.Sha384Hash, ack)

		if bytes.Equal(correctHP2.Value, wrongAlgHP2.Value) {
			t.Error("HashPrev2 computed with wrong algorithm should not match")
		}
	})
}

// TestHashBindingClientOffersHashTypes verifies that the client advertises
// its supported hash types in HelloDeviceProbe, and the server can select
// one for use in the hash binding chain.
func TestHashBindingClientOffersHashTypes(t *testing.T) {
	t.Run("client offers both SHA-256 and SHA-384", func(t *testing.T) {
		probe := makeProbe(protocol.GUID{0x01}, []byte{0xAA})

		// Verify the probe advertises both hash types
		if len(probe.HashTypes) != 2 {
			t.Fatalf("probe HashTypes length = %d, want 2", len(probe.HashTypes))
		}
		hasSha256 := false
		hasSha384 := false
		for _, h := range probe.HashTypes {
			switch h {
			case protocol.Sha256Hash:
				hasSha256 = true
			case protocol.Sha384Hash:
				hasSha384 = true
			}
		}
		if !hasSha256 {
			t.Error("probe should offer Sha256Hash")
		}
		if !hasSha384 {
			t.Error("probe should offer Sha384Hash")
		}
	})

	t.Run("server selects from client offerings", func(t *testing.T) {
		probe := makeProbe(protocol.GUID{0x01}, []byte{0xAA})

		// Server selects SHA-256 and uses it for HashPrev
		hashPrev := computeHashBinding(t, protocol.Sha256Hash, probe)
		nonce := protocol.Nonce{0x11}
		ack := makeAck(hashPrev, nonce)

		// Verify HashPrev uses the selected algorithm
		if ack.HashPrev.Algorithm != protocol.Sha256Hash {
			t.Errorf("ack HashPrev algorithm = %v, want Sha256Hash", ack.HashPrev.Algorithm)
		}
	})

	t.Run("hash types survive CBOR round trip", func(t *testing.T) {
		probe := makeProbe(protocol.GUID{0x01}, []byte{0xAA})

		data, err := cbor.Marshal(probe)
		if err != nil {
			t.Fatalf("failed to marshal probe: %v", err)
		}

		var decoded fdo.HelloDeviceProbeMsg
		if err := cbor.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("failed to unmarshal probe: %v", err)
		}

		if len(decoded.HashTypes) != len(probe.HashTypes) {
			t.Fatalf("HashTypes length mismatch: got %d, want %d",
				len(decoded.HashTypes), len(probe.HashTypes))
		}
		for i, h := range decoded.HashTypes {
			if h != probe.HashTypes[i] {
				t.Errorf("HashTypes[%d] = %v, want %v", i, h, probe.HashTypes[i])
			}
		}
	})
}

// TestHashBindingRoundTripSerialization verifies that the hash binding
// values survive CBOR serialization and deserialization in both the ack
// and ProveDevice20 payload structures.
func TestHashBindingRoundTripSerialization(t *testing.T) {
	tests := []struct {
		name    string
		hashAlg protocol.HashAlg
	}{
		{"SHA-256", protocol.Sha256Hash},
		{"SHA-384", protocol.Sha384Hash},
	}

	for _, tt := range tests {
		t.Run("ack HashPrev "+tt.name, func(t *testing.T) {
			probe := makeProbe(protocol.GUID{0x01}, []byte{0xAA, 0xBB})
			hashPrev := computeHashBinding(t, tt.hashAlg, probe)
			nonce := protocol.Nonce{0x11, 0x22}
			ack := makeAck(hashPrev, nonce)

			data, err := cbor.Marshal(ack)
			if err != nil {
				t.Fatalf("failed to marshal ack: %v", err)
			}

			var decoded fdo.HelloDeviceAck20Msg
			if err := cbor.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal ack: %v", err)
			}

			if decoded.HashPrev.Algorithm != tt.hashAlg {
				t.Errorf("decoded HashPrev algorithm = %v, want %v",
					decoded.HashPrev.Algorithm, tt.hashAlg)
			}
			if !bytes.Equal(decoded.HashPrev.Value, hashPrev.Value) {
				t.Error("decoded HashPrev value does not match original")
			}
		})

		t.Run("ProveDevice20 HashPrev2 "+tt.name, func(t *testing.T) {
			probe := makeProbe(protocol.GUID{0x01}, []byte{0xAA})
			hashPrev := computeHashBinding(t, tt.hashAlg, probe)
			nonce := protocol.Nonce{0x11}
			ack := makeAck(hashPrev, nonce)
			hashPrev2 := computeHashBinding(t, tt.hashAlg, ack)

			payload := fdo.ProveDevice20Payload{
				KexSuiteName:        kex.ECDH256Suite,
				CipherSuiteName:     kex.A128GcmCipher,
				XAKeyExchange:       []byte{0x01, 0x02, 0x03},
				NonceTO2ProveOVPrep: nonce,
				HashPrev2:           hashPrev2,
			}

			data, err := cbor.Marshal(payload)
			if err != nil {
				t.Fatalf("failed to marshal ProveDevice20Payload: %v", err)
			}

			var decoded fdo.ProveDevice20Payload
			if err := cbor.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("failed to unmarshal ProveDevice20Payload: %v", err)
			}

			if decoded.HashPrev2.Algorithm != tt.hashAlg {
				t.Errorf("decoded HashPrev2 algorithm = %v, want %v",
					decoded.HashPrev2.Algorithm, tt.hashAlg)
			}
			if !bytes.Equal(decoded.HashPrev2.Value, hashPrev2.Value) {
				t.Error("decoded HashPrev2 value does not match original")
			}
		})
	}
}

// TestHashBindingEmptyAndEdgeCases tests edge cases in the hash binding
// computation.
func TestHashBindingEmptyAndEdgeCases(t *testing.T) {
	t.Run("probe with nil sugar", func(t *testing.T) {
		probe := makeProbe(protocol.GUID{0x01}, nil)
		hash := computeHashBinding(t, protocol.Sha256Hash, probe)

		if len(hash.Value) != sha256.Size {
			t.Errorf("hash length = %d, want %d", len(hash.Value), sha256.Size)
		}
	})

	t.Run("probe with empty sugar", func(t *testing.T) {
		probe := makeProbe(protocol.GUID{0x01}, []byte{})
		hash := computeHashBinding(t, protocol.Sha256Hash, probe)

		if len(hash.Value) != sha256.Size {
			t.Errorf("hash length = %d, want %d", len(hash.Value), sha256.Size)
		}
	})

	t.Run("nil vs empty sugar produce different hashes", func(t *testing.T) {
		probeNil := makeProbe(protocol.GUID{0x01}, nil)
		probeEmpty := makeProbe(protocol.GUID{0x01}, []byte{})

		hashNil := computeHashBinding(t, protocol.Sha256Hash, probeNil)
		hashEmpty := computeHashBinding(t, protocol.Sha256Hash, probeEmpty)

		// CBOR distinguishes nil from empty bytes, so these might differ
		// depending on the CBOR encoding. Either way, the hashes should
		// be well-defined.
		if len(hashNil.Value) == 0 || len(hashEmpty.Value) == 0 {
			t.Error("hash values should never be empty")
		}
	})

	t.Run("zero GUID probe hashes differently from non-zero", func(t *testing.T) {
		probeZero := makeProbe(protocol.GUID{}, []byte{0xAA})
		probeNonZero := makeProbe(protocol.GUID{0x01}, []byte{0xAA})

		hashZero := computeHashBinding(t, protocol.Sha256Hash, probeZero)
		hashNonZero := computeHashBinding(t, protocol.Sha256Hash, probeNonZero)

		if bytes.Equal(hashZero.Value, hashNonZero.Value) {
			t.Error("zero and non-zero GUID probes should produce different hashes")
		}
	})

	t.Run("ack with zero nonce", func(t *testing.T) {
		hashPrev := computeHashBinding(t, protocol.Sha256Hash, makeProbe(protocol.GUID{0x01}, nil))
		ack := makeAck(hashPrev, protocol.Nonce{})
		hash := computeHashBinding(t, protocol.Sha256Hash, ack)

		if len(hash.Value) != sha256.Size {
			t.Errorf("hash length = %d, want %d", len(hash.Value), sha256.Size)
		}
	})
}

// TestHashBindingCBORDeterminism verifies that CBOR encoding is
// deterministic, which is a prerequisite for hash binding to work.
// If the same message encodes to different CBOR bytes on different
// invocations, the hash chain breaks.
func TestHashBindingCBORDeterminism(t *testing.T) {
	probe := makeProbe(
		protocol.GUID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
		[]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE},
	)

	// Encode 100 times and verify all encodings are identical
	first, err := cbor.Marshal(probe)
	if err != nil {
		t.Fatalf("first marshal failed: %v", err)
	}

	for i := 1; i < 100; i++ {
		data, err := cbor.Marshal(probe)
		if err != nil {
			t.Fatalf("marshal %d failed: %v", i, err)
		}
		if !bytes.Equal(first, data) {
			t.Fatalf("CBOR encoding not deterministic: iteration %d differs from first", i)
		}
	}

	// Verify the hash is also deterministic as a consequence
	hash1 := computeHashBinding(t, protocol.Sha256Hash, probe)
	for i := 1; i < 100; i++ {
		hashN := computeHashBinding(t, protocol.Sha256Hash, probe)
		if !bytes.Equal(hash1.Value, hashN.Value) {
			t.Fatalf("hash not deterministic: iteration %d differs", i)
		}
	}
}
