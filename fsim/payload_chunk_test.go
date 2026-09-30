// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"context"
	"testing"

	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// TestPayloadOwnerChunkSizeNegotiation verifies that PayloadOwner negotiates
// the chunk size correctly based on the Producer's MTU.
func TestPayloadOwnerChunkSizeNegotiation(t *testing.T) {
	testData := make([]byte, 100*1024) // 100KB payload

	tests := []struct {
		name              string
		mtu               uint16
		explicitChunkSize int
		wantChunkSize     int
	}{
		{
			name:          "large MTU uses maxPayloadChunkSize",
			mtu:           65535,
			wantChunkSize: maxPayloadChunkSize,
		},
		{
			name: "default MTU clamps to MTU minus overhead",
			// DefaultMTU is 14000; producer subtracts 3 for CBOR header -> 13997
			// 13997 - payloadChunkOverhead(100) = 13897
			mtu:           serviceinfo.DefaultMTU,
			wantChunkSize: int(serviceinfo.DefaultMTU) - 3 - payloadChunkOverhead,
		},
		{
			name: "small MTU clamps to MTU minus overhead",
			// MTU=1300 -> producer gets 1297 -> 1297 - 100 = 1197
			mtu:           1300,
			wantChunkSize: 1300 - 3 - payloadChunkOverhead,
		},
		{
			name:              "explicit chunk size within MTU",
			mtu:               65535,
			explicitChunkSize: 32000,
			wantChunkSize:     32000,
		},
		{
			name:              "explicit chunk size clamped by small MTU",
			mtu:               1300,
			explicitChunkSize: 60000,
			wantChunkSize:     1300 - 3 - payloadChunkOverhead,
		},
		{
			name:              "explicit chunk size smaller than MTU used as-is",
			mtu:               serviceinfo.DefaultMTU,
			explicitChunkSize: 500,
			wantChunkSize:     500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner := &PayloadOwner{}
			if tt.explicitChunkSize > 0 {
				owner.SetChunkSize(tt.explicitChunkSize)
			}
			owner.AddPayload("application/octet-stream", "test.bin", testData, nil)

			// Call produceInfo once to send "active", then again to trigger
			// sender initialization where chunk size is negotiated.
			ctx := context.Background()

			// First call sends "active"
			producer1 := serviceinfo.NewProducer("fdo.payload", tt.mtu)
			blockPeer, done, err := owner.ProduceInfo(ctx, producer1)
			if err != nil {
				t.Fatalf("ProduceInfo (active): %v", err)
			}
			if done {
				t.Fatal("ProduceInfo (active): unexpected done")
			}
			_ = blockPeer

			// Second call initializes the sender and sends begin
			producer2 := serviceinfo.NewProducer("fdo.payload", tt.mtu)
			_, _, err = owner.ProduceInfo(ctx, producer2)
			if err != nil {
				t.Fatalf("ProduceInfo (begin): %v", err)
			}

			// Verify the negotiated chunk size
			if owner.currentSender == nil {
				t.Fatal("currentSender is nil after ProduceInfo")
			}
			got := owner.currentSender.ChunkSize
			if got != tt.wantChunkSize {
				t.Errorf("chunk size = %d, want %d (MTU=%d, explicit=%d, producer.MTU=%d)",
					got, tt.wantChunkSize, tt.mtu, tt.explicitChunkSize,
					serviceinfo.NewProducer("fdo.payload", tt.mtu).MTU())
			}
		})
	}
}

// TestPayloadOwnerDefaultChunkSizeIsNotHardcoded verifies that a PayloadOwner
// with no explicit SetChunkSize produces chunks sized to the negotiated MTU,
// not the ChunkSender's hardcoded 1014-byte default.
func TestPayloadOwnerDefaultChunkSizeIsNotHardcoded(t *testing.T) {
	owner := &PayloadOwner{}
	owner.AddPayload("text/plain", "readme.txt", make([]byte, 50000), nil)

	ctx := context.Background()

	// Send "active"
	p1 := serviceinfo.NewProducer("fdo.payload", serviceinfo.DefaultMTU)
	if _, _, err := owner.ProduceInfo(ctx, p1); err != nil {
		t.Fatal(err)
	}

	// Send "begin" — this initializes the sender with negotiated chunk size
	p2 := serviceinfo.NewProducer("fdo.payload", serviceinfo.DefaultMTU)
	if _, _, err := owner.ProduceInfo(ctx, p2); err != nil {
		t.Fatal(err)
	}

	if owner.currentSender == nil {
		t.Fatal("currentSender is nil")
	}

	got := owner.currentSender.ChunkSize
	if got == 1014 {
		t.Errorf("chunk size is the hardcoded default 1014; expected negotiated value based on MTU=%d", serviceinfo.DefaultMTU)
	}
	// With DefaultMTU=14000, producer subtracts 3 -> 13997
	// 13997 - payloadChunkOverhead(100) = 13897
	expectedMTU := int(serviceinfo.DefaultMTU) - 3 - payloadChunkOverhead
	if got != expectedMTU {
		t.Errorf("chunk size = %d, want %d (MTU-based)", got, expectedMTU)
	}
}
