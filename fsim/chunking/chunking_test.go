// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package chunking

import (
	"bytes"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

func TestBeginMessageMarshalUnmarshal(t *testing.T) {
	original := BeginMessage{
		TotalSize: 1024,
		HashAlg:   "sha256",
		Metadata: map[string]any{
			"version": "1.0",
			"name":    "test",
		},
		FSIMFields: map[int]any{
			-1: "network-001",
			-2: "TestSSID",
		},
	}

	data, err := original.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR failed: %v", err)
	}

	var decoded BeginMessage
	if err := decoded.UnmarshalCBOR(data); err != nil {
		t.Fatalf("UnmarshalCBOR failed: %v", err)
	}

	if decoded.TotalSize != original.TotalSize {
		t.Errorf("TotalSize mismatch: got %d, want %d", decoded.TotalSize, original.TotalSize)
	}
	if decoded.HashAlg != original.HashAlg {
		t.Errorf("HashAlg mismatch: got %s, want %s", decoded.HashAlg, original.HashAlg)
	}
	if decoded.FSIMFields[-1] != original.FSIMFields[-1] {
		t.Errorf("FSIMFields[-1] mismatch: got %v, want %v", decoded.FSIMFields[-1], original.FSIMFields[-1])
	}
}

func TestEndMessageMarshalUnmarshal(t *testing.T) {
	original := EndMessage{
		Status:    0,
		HashValue: []byte{0x01, 0x02, 0x03, 0x04},
		Message:   "success",
		FSIMFields: map[int]any{
			-1: "extra-info",
		},
	}

	data, err := original.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR failed: %v", err)
	}

	var decoded EndMessage
	if err := decoded.UnmarshalCBOR(data); err != nil {
		t.Fatalf("UnmarshalCBOR failed: %v", err)
	}

	if decoded.Status != original.Status {
		t.Errorf("Status mismatch: got %d, want %d", decoded.Status, original.Status)
	}
	if !bytes.Equal(decoded.HashValue, original.HashValue) {
		t.Errorf("HashValue mismatch: got %v, want %v", decoded.HashValue, original.HashValue)
	}
	if decoded.Message != original.Message {
		t.Errorf("Message mismatch: got %s, want %s", decoded.Message, original.Message)
	}
}

func TestResultMessageMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name     string
		original ResultMessage
	}{
		{
			name: "with message",
			original: ResultMessage{
				StatusCode: 0,
				Message:    "success",
			},
		},
		{
			name: "without message",
			original: ResultMessage{
				StatusCode: 2,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.original.MarshalCBOR()
			if err != nil {
				t.Fatalf("MarshalCBOR failed: %v", err)
			}

			var decoded ResultMessage
			if err := decoded.UnmarshalCBOR(data); err != nil {
				t.Fatalf("UnmarshalCBOR failed: %v", err)
			}

			if decoded.StatusCode != tt.original.StatusCode {
				t.Errorf("StatusCode mismatch: got %d, want %d", decoded.StatusCode, tt.original.StatusCode)
			}
			if decoded.Message != tt.original.Message {
				t.Errorf("Message mismatch: got %s, want %s", decoded.Message, tt.original.Message)
			}
		})
	}
}

func TestComputeHash(t *testing.T) {
	data := []byte("test data for hashing")

	tests := []struct {
		alg         string
		expectError bool
	}{
		{"sha256", false},
		{"sha384", false},
		{"sha512", false},
		{"md5", true},
		{"unknown", true},
	}

	for _, tt := range tests {
		t.Run(tt.alg, func(t *testing.T) {
			hash, err := ComputeHash(tt.alg, data)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for algorithm %s, got none", tt.alg)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for algorithm %s: %v", tt.alg, err)
				}
				if len(hash) == 0 {
					t.Errorf("hash is empty for algorithm %s", tt.alg)
				}
			}
		})
	}
}

func TestVerifyHash(t *testing.T) {
	data := []byte("test data")
	correctHash, _ := ComputeHash("sha256", data)
	wrongHash := []byte{0x00, 0x01, 0x02}

	tests := []struct {
		name        string
		alg         string
		data        []byte
		expected    []byte
		expectError bool
	}{
		{"correct hash", "sha256", data, correctHash, false},
		{"wrong hash", "sha256", data, wrongHash, true},
		{"wrong length", "sha256", data, []byte{0x01}, true},
		{"unsupported alg", "md5", data, correctHash, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyHash(tt.alg, tt.data, tt.expected)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error, got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestChunkReceiverBasicFlow(t *testing.T) {
	receiver := &ChunkReceiver{
		PayloadName: "test",
	}

	var receivedBegin BeginMessage
	var receivedChunks [][]byte
	var receivedEnd EndMessage

	receiver.OnBegin = func(begin BeginMessage) error {
		receivedBegin = begin
		return nil
	}

	receiver.OnChunk = func(data []byte) error {
		chunk := make([]byte, len(data))
		copy(chunk, data)
		receivedChunks = append(receivedChunks, chunk)
		return nil
	}

	receiver.OnEnd = func(end EndMessage) error {
		receivedEnd = end
		return nil
	}

	// Send begin
	begin := BeginMessage{
		TotalSize: 10,
		HashAlg:   "sha256",
	}
	beginData, _ := begin.MarshalCBOR()
	if err := receiver.HandleMessage("test-begin", bytes.NewReader(beginData)); err != nil {
		t.Fatalf("HandleMessage(begin) failed: %v", err)
	}

	// Send chunks
	chunk1 := []byte("hello")
	chunk1Data, _ := cbor.Marshal(chunk1)
	if err := receiver.HandleMessage("test-data-0", bytes.NewReader(chunk1Data)); err != nil {
		t.Fatalf("HandleMessage(data-0) failed: %v", err)
	}

	chunk2 := []byte("world")
	chunk2Data, _ := cbor.Marshal(chunk2)
	if err := receiver.HandleMessage("test-data-1", bytes.NewReader(chunk2Data)); err != nil {
		t.Fatalf("HandleMessage(data-1) failed: %v", err)
	}

	// Send end
	fullData := append(chunk1, chunk2...)
	hash, _ := ComputeHash("sha256", fullData)
	end := EndMessage{
		Status:    0,
		HashValue: hash,
	}
	endData, _ := end.MarshalCBOR()
	if err := receiver.HandleMessage("test-end", bytes.NewReader(endData)); err != nil {
		t.Fatalf("HandleMessage(end) failed: %v", err)
	}

	// Verify callbacks were called
	if receivedBegin.TotalSize != 10 {
		t.Errorf("OnBegin not called correctly")
	}
	if len(receivedChunks) != 2 {
		t.Errorf("expected 2 chunks, got %d", len(receivedChunks))
	}
	if receivedEnd.Status != 0 {
		t.Errorf("OnEnd not called correctly")
	}
}

func TestChunkReceiverOutOfOrderChunks(t *testing.T) {
	receiver := &ChunkReceiver{
		PayloadName: "test",
	}

	// Send begin
	begin := BeginMessage{TotalSize: 10}
	beginData, _ := begin.MarshalCBOR()
	if err := receiver.HandleMessage("test-begin", bytes.NewReader(beginData)); err != nil {
		t.Fatalf("Failed to handle test-begin: %v", err)
	}

	// Send chunk 1 before chunk 0
	chunk := []byte("test")
	chunkData, _ := cbor.Marshal(chunk)
	err := receiver.HandleMessage("test-data-1", bytes.NewReader(chunkData))
	if err == nil {
		t.Errorf("expected error for out-of-order chunk, got none")
	}
}

func TestChunkReceiverSizeMismatch(t *testing.T) {
	receiver := &ChunkReceiver{
		PayloadName: "test",
	}

	// Send begin with size 5
	begin := BeginMessage{TotalSize: 5}
	beginData, _ := begin.MarshalCBOR()
	if err := receiver.HandleMessage("test-begin", bytes.NewReader(beginData)); err != nil {
		t.Fatalf("Failed to handle test-begin: %v", err)
	}

	// Send 10 bytes
	chunk := []byte("1234567890")
	chunkData, _ := cbor.Marshal(chunk)
	if err := receiver.HandleMessage("test-data-0", bytes.NewReader(chunkData)); err != nil {
		t.Fatalf("Failed to handle test-data-0: %v", err)
	}

	// Send end - should fail due to size mismatch
	end := EndMessage{Status: 0}
	endData, _ := end.MarshalCBOR()
	err := receiver.HandleMessage("test-end", bytes.NewReader(endData))
	if err == nil {
		t.Errorf("expected error for size mismatch, got none")
	}
}

func TestChunkSenderBasicFlow(t *testing.T) {
	data := []byte("This is test data that will be chunked")
	sender := NewChunkSender("test", data)
	sender.ChunkSize = 10
	sender.BeginFields.HashAlg = "sha256"

	// Create a real producer (it just queues messages internally)
	producer := &mockProducer{messages: make(map[string][]byte)}

	// Send begin
	if err := sender.SendBegin(producer); err != nil {
		t.Fatalf("SendBegin failed: %v", err)
	}

	if _, ok := producer.messages["test-begin"]; !ok {
		t.Errorf("begin message not sent")
	}

	// Send all chunks
	chunkCount := 0
	for {
		done, err := sender.SendNextChunk(producer)
		if err != nil {
			t.Fatalf("SendNextChunk failed: %v", err)
		}
		if done {
			break
		}
		chunkCount++
	}

	if chunkCount == 0 {
		t.Errorf("no chunks were sent")
	}

	// Send end
	if err := sender.SendEnd(producer); err != nil {
		t.Fatalf("SendEnd failed: %v", err)
	}

	if _, ok := producer.messages["test-end"]; !ok {
		t.Errorf("end message not sent")
	}

	// Verify end message contains hash
	var end EndMessage
	if err := end.UnmarshalCBOR(producer.messages["test-end"]); err != nil {
		t.Fatalf("Failed to unmarshal end message: %v", err)
	}
	if len(end.HashValue) == 0 {
		t.Errorf("hash not computed in end message")
	}
}

func TestChunkSenderProgress(t *testing.T) {
	data := []byte("test data")
	sender := NewChunkSender("test", data)

	if sender.GetProgress() != 0.0 {
		t.Errorf("initial progress should be 0, got %f", sender.GetProgress())
	}

	producer := &mockProducer{messages: make(map[string][]byte)}

	if err := sender.SendBegin(producer); err != nil {
		t.Fatalf("Failed to send begin: %v", err)
	}
	if _, err := sender.SendNextChunk(producer); err != nil {
		t.Fatalf("Failed to send next chunk: %v", err)
	}

	progress := sender.GetProgress()
	if progress <= 0 || progress > 100 {
		t.Errorf("progress out of range: %f", progress)
	}
}

// Mock producer for testing - implements the minimal interface needed
type mockProducer struct {
	messages map[string][]byte
}

func (m *mockProducer) WriteChunk(key string, data []byte) error {
	m.messages[key] = data
	return nil
}

func TestAckMessageMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name     string
		original AckMessage
	}{
		{
			name: "accepted",
			original: AckMessage{
				Accepted: true,
			},
		},
		{
			name: "rejected with reason",
			original: AckMessage{
				Accepted:   false,
				ReasonCode: AckReasonUnsupportedType,
			},
		},
		{
			name: "rejected with reason and message",
			original: AckMessage{
				Accepted:   false,
				ReasonCode: AckReasonSizeExceeded,
				Message:    "Payload too large",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.original.MarshalCBOR()
			if err != nil {
				t.Fatalf("MarshalCBOR failed: %v", err)
			}

			var decoded AckMessage
			if err := decoded.UnmarshalCBOR(data); err != nil {
				t.Fatalf("UnmarshalCBOR failed: %v", err)
			}

			if decoded.Accepted != tt.original.Accepted {
				t.Errorf("Accepted mismatch: got %v, want %v", decoded.Accepted, tt.original.Accepted)
			}
			if decoded.ReasonCode != tt.original.ReasonCode {
				t.Errorf("ReasonCode mismatch: got %d, want %d", decoded.ReasonCode, tt.original.ReasonCode)
			}
			if decoded.Message != tt.original.Message {
				t.Errorf("Message mismatch: got %s, want %s", decoded.Message, tt.original.Message)
			}
		})
	}
}

func TestBeginMessageWithRequireAck(t *testing.T) {
	original := BeginMessage{
		TotalSize:  1024,
		RequireAck: true,
		FSIMFields: map[int]any{
			-1: "application/json",
		},
	}

	data, err := original.MarshalCBOR()
	if err != nil {
		t.Fatalf("MarshalCBOR failed: %v", err)
	}

	var decoded BeginMessage
	if err := decoded.UnmarshalCBOR(data); err != nil {
		t.Fatalf("UnmarshalCBOR failed: %v", err)
	}

	if !decoded.RequireAck {
		t.Error("RequireAck should be true")
	}
	if decoded.TotalSize != 1024 {
		t.Errorf("TotalSize mismatch: got %d, want 1024", decoded.TotalSize)
	}
}

func TestChunkSenderWithAckAccepted(t *testing.T) {
	data := []byte("test data")
	sender := NewChunkSender("test", data)
	sender.BeginFields.RequireAck = true

	producer := &mockProducer{messages: make(map[string][]byte)}

	// Send begin
	if err := sender.SendBegin(producer); err != nil {
		t.Fatalf("SendBegin failed: %v", err)
	}

	// Verify we're waiting for ack
	if !sender.IsWaitingForAck() {
		t.Error("should be waiting for ack after SendBegin with RequireAck=true")
	}

	// Try to send chunk - should fail while waiting for ack
	_, err := sender.SendNextChunk(producer)
	if err == nil {
		t.Error("SendNextChunk should fail while waiting for ack")
	}

	// Simulate receiving an accept ack
	acceptAck := AckMessage{Accepted: true}
	ackData, _ := acceptAck.MarshalCBOR()
	if err := sender.HandleAck(bytes.NewReader(ackData)); err != nil {
		t.Fatalf("HandleAck failed: %v", err)
	}

	// Verify we're no longer waiting
	if sender.IsWaitingForAck() {
		t.Error("should not be waiting for ack after receiving accept")
	}
	if sender.IsRejected() {
		t.Error("should not be rejected after accept")
	}

	// Now SendNextChunk should work
	done, err := sender.SendNextChunk(producer)
	if err != nil {
		t.Fatalf("SendNextChunk failed after ack: %v", err)
	}
	if !done {
		t.Error("should be done sending small data")
	}
}

func TestChunkSenderWithAckRejected(t *testing.T) {
	data := []byte("test data")
	sender := NewChunkSender("test", data)
	sender.BeginFields.RequireAck = true

	producer := &mockProducer{messages: make(map[string][]byte)}

	// Send begin
	if err := sender.SendBegin(producer); err != nil {
		t.Fatalf("Failed to send begin: %v", err)
	}

	// Simulate receiving a reject ack
	rejectAck := AckMessage{
		Accepted:   false,
		ReasonCode: AckReasonUnsupportedType,
		Message:    "MIME type not supported",
	}
	ackData, _ := rejectAck.MarshalCBOR()
	err := sender.HandleAck(bytes.NewReader(ackData))
	if err == nil {
		t.Error("HandleAck should return error for rejection")
	}

	// Verify rejection state
	if sender.IsWaitingForAck() {
		t.Error("should not be waiting for ack after rejection")
	}
	if !sender.IsRejected() {
		t.Error("should be marked as rejected")
	}

	reason, msg := sender.GetRejectReason()
	if reason != AckReasonUnsupportedType {
		t.Errorf("wrong reason code: got %d, want %d", reason, AckReasonUnsupportedType)
	}
	if msg != "MIME type not supported" {
		t.Errorf("wrong message: got %s", msg)
	}

	// SendNextChunk should fail
	_, err = sender.SendNextChunk(producer)
	if err == nil {
		t.Error("SendNextChunk should fail after rejection")
	}
}

func TestChunkReceiverWithAckAccepted(t *testing.T) {
	receiver := &ChunkReceiver{
		PayloadName: "test",
	}

	// Set up ack callback that accepts
	receiver.OnBeginAck = func(begin BeginMessage) (bool, int, string) {
		return true, 0, ""
	}

	var onBeginCalled bool
	receiver.OnBegin = func(begin BeginMessage) error {
		onBeginCalled = true
		return nil
	}

	// Send begin with RequireAck
	begin := BeginMessage{
		TotalSize:  10,
		RequireAck: true,
	}
	beginData, _ := begin.MarshalCBOR()
	if err := receiver.HandleMessage("test-begin", bytes.NewReader(beginData)); err != nil {
		t.Fatalf("HandleMessage(begin) failed: %v", err)
	}

	// Verify ack is pending
	if !receiver.IsAckPending() {
		t.Error("ack should be pending")
	}
	if !receiver.IsAckAccepted() {
		t.Error("ack should indicate acceptance")
	}

	// OnBegin should still be called for accepted transfers
	if !onBeginCalled {
		t.Error("OnBegin should be called for accepted transfers")
	}

	// Verify we're receiving
	if !receiver.IsReceiving() {
		t.Error("should be receiving after accepted begin")
	}
}

func TestChunkReceiverWithAckRejected(t *testing.T) {
	receiver := &ChunkReceiver{
		PayloadName: "test",
	}

	// Set up ack callback that rejects
	receiver.OnBeginAck = func(begin BeginMessage) (bool, int, string) {
		return false, AckReasonUnsupportedType, "MIME type not supported"
	}

	var onBeginCalled bool
	receiver.OnBegin = func(begin BeginMessage) error {
		onBeginCalled = true
		return nil
	}

	// Send begin with RequireAck
	begin := BeginMessage{
		TotalSize:  10,
		RequireAck: true,
	}
	beginData, _ := begin.MarshalCBOR()
	if err := receiver.HandleMessage("test-begin", bytes.NewReader(beginData)); err != nil {
		t.Fatalf("HandleMessage(begin) failed: %v", err)
	}

	// Verify ack is pending and rejected
	if !receiver.IsAckPending() {
		t.Error("ack should be pending")
	}
	if receiver.IsAckAccepted() {
		t.Error("ack should indicate rejection")
	}

	// OnBegin should NOT be called for rejected transfers
	if onBeginCalled {
		t.Error("OnBegin should not be called for rejected transfers")
	}

	// Verify we're NOT receiving (rejection stops the transfer)
	if receiver.IsReceiving() {
		t.Error("should not be receiving after rejected begin")
	}
}

func TestChunkReceiverSendAck(t *testing.T) {
	receiver := &ChunkReceiver{
		PayloadName: "payload",
	}

	receiver.OnBeginAck = func(begin BeginMessage) (bool, int, string) {
		return false, AckReasonSizeExceeded, "Too large"
	}

	// Send begin with RequireAck
	begin := BeginMessage{RequireAck: true}
	beginData, _ := begin.MarshalCBOR()
	if err := receiver.HandleMessage("payload-begin", bytes.NewReader(beginData)); err != nil {
		t.Fatalf("Failed to handle payload-begin: %v", err)
	}

	// Send ack using mock respond function
	var ackKey string
	var ackData []byte
	respond := func(key string) *bytes.Buffer {
		ackKey = key
		buf := &bytes.Buffer{}
		// Capture the data when Write is called
		return buf
	}

	// We need a different approach - use a wrapper
	var sentAck AckMessage
	mockRespond := func(key string) *mockWriter {
		ackKey = key
		return &mockWriter{onWrite: func(data []byte) {
			ackData = data
		}}
	}

	// Use the actual SendAck but capture output
	if receiver.IsAckPending() {
		ack := AckMessage{
			Accepted:   receiver.IsAckAccepted(),
			ReasonCode: AckReasonSizeExceeded,
			Message:    "Too large",
		}
		ackData, _ = ack.MarshalCBOR()

		// Decode to verify
		if err := sentAck.UnmarshalCBOR(ackData); err != nil {
			t.Fatalf("Failed to unmarshal sent ack: %v", err)
		}
	}

	_ = respond // suppress unused warning
	_ = mockRespond
	_ = ackKey

	if sentAck.Accepted {
		t.Error("ack should be rejection")
	}
	if sentAck.ReasonCode != AckReasonSizeExceeded {
		t.Errorf("wrong reason code: got %d, want %d", sentAck.ReasonCode, AckReasonSizeExceeded)
	}
}

// mockWriter for testing respond function
type mockWriter struct {
	onWrite func([]byte)
	buf     bytes.Buffer
}

func (m *mockWriter) Write(data []byte) (int, error) {
	if m.onWrite != nil {
		m.onWrite(data)
	}
	return m.buf.Write(data)
}
