// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/fsim/chunking"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// WiFiOwner implements the fdo.wifi FSIM for owner-side WiFi configuration.
// It follows the specification in fdo.wifi-setup.md and uses the generic chunking strategy.
type WiFiOwner struct {
	// Networks to configure on the device
	networks []*WiFiNetwork

	// Certificates and CA bundles to send
	certificates []WiFiCertificate
	caBundles    []WiFiCABundle

	// Internal state
	currentNetworkIndex int
	currentCertIndex    int
	currentCAIndex      int
	sentActive          bool
	waitingForCSR       bool
	sendingCert         bool
	certBeginSent       bool
	certCompleted       bool
	caBeginSent         bool

	// Chunking senders
	csrReceiver *chunking.ChunkReceiver
	certSender  *chunking.ChunkSender
	caSender    *chunking.ChunkSender

	// Results
	lastCSR     []byte
	lastCSRMeta map[string]any
	certResult  *chunking.ResultMessage
	caResult    *chunking.ResultMessage
}

// WiFiCertificate represents a certificate to send to the device.
type WiFiCertificate struct {
	NetworkID string         // Required: network_id (field -1)
	SSID      string         // Optional: ssid (field -2)
	CertRole  int            // Optional: cert_role (field -3): 0=client, 1=intermediate, 2=ca
	CertData  []byte         // Certificate data (DER or PEM)
	Metadata  map[string]any // Optional: metadata (field -4)
	HashAlg   string         // Optional: hash algorithm
}

// WiFiCABundle represents a CA bundle to send to the device.
type WiFiCABundle struct {
	NetworkID string         // Required: network_id (field -1)
	BundleID  string         // Optional: bundle_id (field -2)
	CAData    []byte         // CA certificate data (DER or PEM, possibly concatenated)
	Metadata  map[string]any // Optional: metadata (field -3)
	HashAlg   string         // Optional: hash algorithm
}

var _ serviceinfo.OwnerModule = (*WiFiOwner)(nil)

// HandleInfo implements serviceinfo.OwnerModule.
func (w *WiFiOwner) HandleInfo(ctx context.Context, messageName string, messageBody io.Reader) error {
	return w.receive(ctx, messageName, messageBody)
}

// ProduceInfo implements serviceinfo.OwnerModule.
func (w *WiFiOwner) ProduceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	return w.produceInfo(ctx, producer)
}

// Transition implements serviceinfo.OwnerModule.
func (w *WiFiOwner) Transition(active bool) error {
	if !active {
		w.reset()
	}
	return nil
}

// AddNetwork adds a network configuration to send to the device.
func (w *WiFiOwner) AddNetwork(network *WiFiNetwork) {
	w.networks = append(w.networks, network)
}

// AddCertificate adds a certificate to send to the device.
func (w *WiFiOwner) AddCertificate(cert WiFiCertificate) {
	if cert.HashAlg == "" {
		cert.HashAlg = "sha256"
	}
	w.certificates = append(w.certificates, cert)
}

// AddCABundle adds a CA bundle to send to the device.
func (w *WiFiOwner) AddCABundle(bundle WiFiCABundle) {
	if bundle.HashAlg == "" {
		bundle.HashAlg = "sha256"
	}
	w.caBundles = append(w.caBundles, bundle)
}

// reset clears the internal state.
func (w *WiFiOwner) reset() {
	w.currentNetworkIndex = 0
	w.sentActive = false
	w.csrReceiver = nil
	w.certSender = nil
	w.caSender = nil
	w.lastCSR = nil
	w.lastCSRMeta = nil
	w.certResult = nil
	w.caResult = nil
}

// produceInfo generates messages to send to the device.
func (w *WiFiOwner) produceInfo(ctx context.Context, producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	// Send active message first if we have networks to send
	if !w.sentActive && len(w.networks) > 0 {
		if err := producer.WriteChunk("active", []byte{0xf5}); err != nil { // CBOR true
			return false, false, fmt.Errorf("failed to send active: %w", err)
		}
		w.sentActive = true
		slog.Debug("fdo.wifi sent active=true")
		return false, false, nil
	}

	// If we're sending a certificate, continue that flow
	if w.sendingCert {
		return w.sendCertificate(producer)
	}

	// If we're waiting for CSR, block until we receive it
	if w.waitingForCSR {
		return true, false, nil // Block and wait for CSR
	}

	// Send networks one at a time
	if w.currentNetworkIndex < len(w.networks) {
		network := w.networks[w.currentNetworkIndex]

		// Encode network as CBOR map with integer keys
		networkMap := make(map[int]any)
		networkMap[0] = network.Version
		networkMap[1] = network.NetworkID
		networkMap[2] = network.SSID
		networkMap[3] = network.AuthType

		if len(network.Password) > 0 {
			networkMap[4] = network.Password
		}
		if len(network.CACerts) > 0 {
			certs := make([]any, len(network.CACerts))
			for i, cert := range network.CACerts {
				certs[i] = cert
			}
			networkMap[5] = certs
		}
		networkMap[6] = network.TrustLevel

		if network.FastRoaming != nil {
			networkMap[7] = network.FastRoaming
		}
		if network.Hotspot2 != nil {
			networkMap[8] = network.Hotspot2
		}
		if network.EAPUsername != "" {
			networkMap[9] = network.EAPUsername
		}
		if len(network.EAPPassword) > 0 {
			networkMap[10] = network.EAPPassword
		}

		// Encode and send
		var buf bytes.Buffer
		if err := cbor.NewEncoder(&buf).Encode(networkMap); err != nil {
			return false, false, fmt.Errorf("failed to encode network-add: %w", err)
		}

		if err := producer.WriteChunk("network-add", buf.Bytes()); err != nil {
			return false, false, fmt.Errorf("failed to send network-add: %w", err)
		}

		slog.Debug("fdo.wifi sent network-add",
			"network_id", network.NetworkID,
			"ssid", network.SSID)

		w.currentNetworkIndex++

		// If this is an enterprise network and we have certificates, set flag to wait for CSR
		// Don't block immediately - wait for next ProduceInfo call
		if network.AuthType == 3 && w.currentCertIndex < len(w.certificates) {
			w.waitingForCSR = true
			slog.Debug("fdo.wifi will wait for CSR from device on next call")
		}

		return false, false, nil
	}

	// All networks sent, we're done
	return false, true, nil
}

// sendCertificate sends a certificate and CA bundle using the chunking strategy.
// Both are sent in the same phase to avoid additional state machine complexity.
func (w *WiFiOwner) sendCertificate(producer *serviceinfo.Producer) (blockPeer, moduleDone bool, _ error) {
	if w.currentCertIndex >= len(w.certificates) {
		w.sendingCert = false
		return false, false, nil
	}

	// Initialize cert sender if needed
	if w.certSender == nil {
		cert := &w.certificates[w.currentCertIndex]
		w.certSender = chunking.NewChunkSender("cert", cert.CertData)
		w.certSender.BeginFields.FSIMFields = make(map[int]any)
		w.certSender.BeginFields.FSIMFields[-1] = cert.NetworkID
		if cert.SSID != "" {
			w.certSender.BeginFields.FSIMFields[-2] = cert.SSID
		}
		if cert.Metadata != nil {
			w.certSender.BeginFields.FSIMFields[-4] = cert.Metadata
		}
		w.certBeginSent = false
		w.certCompleted = false
		slog.Debug("fdo.wifi initialized cert sender", "network_id", cert.NetworkID)
	}

	// Send cert begin
	if !w.certBeginSent {
		if err := w.certSender.SendBegin(producer); err != nil {
			return false, false, fmt.Errorf("failed to send cert-begin: %w", err)
		}
		w.certBeginSent = true
		slog.Debug("fdo.wifi sent cert-begin")
		return false, false, nil
	}

	// Send cert chunks and end
	if !w.certCompleted {
		done, err := w.certSender.SendNextChunk(producer)
		if err != nil {
			return false, false, fmt.Errorf("failed to send cert chunk: %w", err)
		}
		if done {
			if err := w.certSender.SendEnd(producer); err != nil {
				return false, false, fmt.Errorf("failed to send cert-end: %w", err)
			}
			w.certCompleted = true
			slog.Debug("fdo.wifi sent cert-end")
			return false, false, nil // Don't block yet - send CA bundle next
		}
		return false, false, nil
	}

	// Certificate sent, now send CA bundle if available
	if w.currentCAIndex < len(w.caBundles) {
		// Initialize CA sender if needed
		if w.caSender == nil {
			ca := &w.caBundles[w.currentCAIndex]
			w.caSender = chunking.NewChunkSender("ca", ca.CAData)
			w.caSender.BeginFields.FSIMFields = make(map[int]any)
			w.caSender.BeginFields.FSIMFields[-1] = ca.NetworkID
			if ca.BundleID != "" {
				w.caSender.BeginFields.FSIMFields[-2] = ca.BundleID
			}
			if ca.Metadata != nil {
				w.caSender.BeginFields.FSIMFields[-3] = ca.Metadata
			}
			w.caBeginSent = false
			slog.Debug("fdo.wifi initialized CA sender", "network_id", ca.NetworkID, "bundle_id", ca.BundleID)
		}

		// Send CA begin
		if !w.caBeginSent {
			if err := w.caSender.SendBegin(producer); err != nil {
				return false, false, fmt.Errorf("failed to send ca-begin: %w", err)
			}
			w.caBeginSent = true
			slog.Debug("fdo.wifi sent ca-begin")
			return false, false, nil
		}

		// Send CA chunks and end
		if !w.caSender.IsCompleted() {
			done, err := w.caSender.SendNextChunk(producer)
			if err != nil {
				return false, false, fmt.Errorf("failed to send ca chunk: %w", err)
			}
			if done {
				if err := w.caSender.SendEnd(producer); err != nil {
					return false, false, fmt.Errorf("failed to send ca-end: %w", err)
				}
				slog.Debug("fdo.wifi sent ca-end")
				// Both cert and CA sent, now block and wait for results
				return true, false, nil
			}
			return false, false, nil
		}
	}

	// Both certificate and CA bundle sent, clean up and move to next
	w.certSender = nil
	w.caSender = nil
	w.currentCertIndex++
	w.currentCAIndex++
	w.sendingCert = false
	return false, false, nil
}

// receive processes messages from the device.
func (w *WiFiOwner) receive(ctx context.Context, messageName string, messageBody io.Reader) error {
	switch messageName {
	case "active":
		// Read and validate the active response from device
		var deviceActive bool
		if err := cbor.NewDecoder(messageBody).Decode(&deviceActive); err != nil {
			return fmt.Errorf("error decoding active message: %w", err)
		}
		if !deviceActive {
			return fmt.Errorf("device WiFi module is not active")
		}
		slog.Debug("fdo.wifi device confirmed active")
		return nil

	case "csr-begin", "csr-data-0", "csr-data-1", "csr-data-2", "csr-data-3", "csr-data-4",
		"csr-data-5", "csr-data-6", "csr-data-7", "csr-data-8", "csr-data-9", "csr-end":
		// Handle CSR chunked messages
		return w.handleCSR(messageName, messageBody)

	case "cert-result":
		// Handle certificate result
		var result chunking.ResultMessage
		data, err := io.ReadAll(messageBody)
		if err != nil {
			return fmt.Errorf("failed to read cert-result: %w", err)
		}
		if err := result.UnmarshalCBOR(data); err != nil {
			return fmt.Errorf("failed to decode cert-result: %w", err)
		}
		slog.Debug("fdo.wifi received cert-result", "status", result.StatusCode, "message", result.Message)
		w.certResult = &result
		return nil

	case "ca-result":
		// Handle CA bundle result
		var result chunking.ResultMessage
		data, err := io.ReadAll(messageBody)
		if err != nil {
			return fmt.Errorf("failed to read ca-result: %w", err)
		}
		if err := result.UnmarshalCBOR(data); err != nil {
			return fmt.Errorf("failed to decode ca-result: %w", err)
		}
		slog.Debug("fdo.wifi received ca-result", "status", result.StatusCode, "message", result.Message)
		w.caResult = &result
		return nil

	default:
		// Silently ignore unknown messages for protocol compatibility
		slog.Debug("fdo.wifi ignoring message from device", "key", messageName)
		return nil
	}
}

// handleCSR processes CSR messages from the device
func (w *WiFiOwner) handleCSR(messageName string, messageBody io.Reader) error {
	// Initialize receiver on first message
	if w.csrReceiver == nil {
		w.csrReceiver = &chunking.ChunkReceiver{
			PayloadName: "csr",
		}
	}

	// Handle the message
	if err := w.csrReceiver.HandleMessage(messageName, messageBody); err != nil {
		w.csrReceiver = nil
		return err
	}

	// After successful end, we have the CSR
	if messageName == "csr-end" && !w.csrReceiver.IsReceiving() {
		w.lastCSR = w.csrReceiver.GetBuffer()
		slog.Debug("fdo.wifi received CSR", "size", len(w.lastCSR))
		w.csrReceiver = nil
		w.waitingForCSR = false
		w.sendingCert = true // Start sending certificate
	}

	return nil
}
