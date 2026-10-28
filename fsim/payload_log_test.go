// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// --- test doubles ---

// stubPayloadHandler accepts every payload and reports a fixed result.
type stubPayloadHandler struct {
	status   int
	message  string
	received []byte
}

func (h *stubPayloadHandler) HandlePayload(_ context.Context, _, _ string, _ uint64, _ map[string]any, payload []byte) (int, string, error) {
	h.received = append([]byte(nil), payload...)
	return h.status, h.message, nil
}

// stubLogProvider returns a canned diagnostic log.
type stubLogProvider struct {
	log        *PayloadLog
	err        error
	gotStatus  int
	gotMime    string
	callCount  int
	gotPayName string
}

func (p *stubLogProvider) PayloadLog(_ context.Context, mimeType, name string, statusCode int) (*PayloadLog, error) {
	p.callCount++
	p.gotMime, p.gotPayName, p.gotStatus = mimeType, name, statusCode
	return p.log, p.err
}

// stubLogHandler records what the owner received.
type stubLogHandler struct {
	accept     bool
	reasonCode int
	got        *PayloadLogInfo
	gotSize    uint64
	gotContent string
}

func (h *stubLogHandler) AcceptLog(_, _ string, size uint64, contentType string) (bool, int, string) {
	h.gotSize, h.gotContent = size, contentType
	if h.accept {
		return true, 0, ""
	}
	return false, h.reasonCode, "no thanks"
}

func (h *stubLogHandler) HandleLog(_ context.Context, _, _ string, log *PayloadLogInfo) error {
	h.got = log
	return nil
}

// --- harness ---

// payloadExchange drives a PayloadOwner and a Payload device module against
// each other in memory, mimicking the TO2 ServiceInfo round structure: the
// owner produces a round of KVs, the device consumes them and its responses
// are handed back to the owner before the next round.
//
// It returns the ordered list of message names the device emitted.
func payloadExchange(t *testing.T, owner *PayloadOwner, device *Payload, mtu uint16) []string {
	t.Helper()
	ctx := context.Background()

	var deviceMessages []string

	for round := 0; round < 200; round++ {
		producer := serviceinfo.NewProducer("fdo.payload", mtu)
		_, done, err := owner.ProduceInfo(ctx, producer)
		if err != nil {
			t.Fatalf("round %d: owner ProduceInfo: %v", round, err)
		}

		var responses []*serviceinfo.KV
		respond := func(messageName string) io.Writer {
			buf := &bytes.Buffer{}
			responses = append(responses, &serviceinfo.KV{Key: messageName, Val: nil})
			// Defer capture: record the buffer against the KV just appended.
			kv := responses[len(responses)-1]
			return &kvWriter{kv: kv, buf: buf}
		}

		for _, kv := range producer.ServiceInfo() {
			_, messageName, _ := strings.Cut(kv.Key, ":")
			if err := device.Receive(ctx, messageName, bytes.NewReader(kv.Val), respond, func() {}); err != nil {
				t.Fatalf("round %d: device Receive(%s): %v", round, messageName, err)
			}
		}

		for _, kv := range responses {
			deviceMessages = append(deviceMessages, kv.Key)
			if err := owner.HandleInfo(ctx, kv.Key, bytes.NewReader(kv.Val)); err != nil {
				t.Fatalf("round %d: owner HandleInfo(%s): %v", round, kv.Key, err)
			}
		}

		if done {
			return deviceMessages
		}
	}
	t.Fatal("payload exchange did not complete within 200 rounds")
	return nil
}

// kvWriter writes into a KV's value on each Write.
type kvWriter struct {
	kv  *serviceinfo.KV
	buf *bytes.Buffer
}

func (w *kvWriter) Write(p []byte) (int, error) {
	n, err := w.buf.Write(p)
	w.kv.Val = w.buf.Bytes()
	return n, err
}

// indexOf returns the position of name in msgs, or -1.
func indexOf(msgs []string, name string) int {
	for i, m := range msgs {
		if m == name {
			return i
		}
	}
	return -1
}

// --- tests ---

// TestPayloadLogRoundTrip verifies that a device's diagnostic log reaches the
// owner intact, with metadata, and that payload-result remains terminal.
func TestPayloadLogRoundTrip(t *testing.T) {
	logBody := []byte(strings.Repeat("autoinstall: failed to partition /dev/sda\n", 500))

	logHandler := &stubLogHandler{accept: true}
	owner := &PayloadOwner{LogHandler: logHandler}
	owner.AddPayload("text/x-shellscript", "setup.sh", []byte("#!/bin/sh\nexit 1\n"), nil)

	provider := &stubLogProvider{log: &PayloadLog{
		Data:        logBody,
		ContentType: "text/plain",
		Source:      "installer",
	}}
	device := &Payload{
		UnifiedHandler: &stubPayloadHandler{status: 2, message: "install failed"},
		LogProvider:    provider,
	}

	msgs := payloadExchange(t, owner, device, 1300)
	t.Logf("device emitted %d messages: %s", len(msgs), strings.Join(msgs, " "))

	if provider.callCount != 1 {
		t.Errorf("LogProvider called %d times, want 1", provider.callCount)
	}
	if provider.gotStatus != 2 {
		t.Errorf("LogProvider saw status %d, want 2", provider.gotStatus)
	}
	if provider.gotMime != "text/x-shellscript" {
		t.Errorf("LogProvider saw mime %q", provider.gotMime)
	}

	if logHandler.got == nil {
		t.Fatalf("owner never received a log; device messages: %v", msgs)
	}
	if !bytes.Equal(logHandler.got.Data, logBody) {
		t.Errorf("log body mismatch: got %d bytes, want %d", len(logHandler.got.Data), len(logBody))
	}
	if logHandler.got.ContentType != "text/plain" {
		t.Errorf("content type = %q, want text/plain", logHandler.got.ContentType)
	}
	if logHandler.got.Source != "installer" {
		t.Errorf("source = %q, want installer", logHandler.got.Source)
	}
	if logHandler.got.Truncated {
		t.Error("log unexpectedly marked truncated")
	}
	if logHandler.gotSize != uint64(len(logBody)) {
		t.Errorf("AcceptLog saw size %d, want %d", logHandler.gotSize, len(logBody))
	}

	// The log must have been chunked across several messages, and
	// payload-result must be last.
	endIdx, resultIdx := indexOf(msgs, "payload-log-end"), indexOf(msgs, "payload-result")
	if endIdx < 0 {
		t.Fatalf("no payload-log-end in %v", msgs)
	}
	if resultIdx < 0 {
		t.Fatalf("no payload-result in %v", msgs)
	}
	if endIdx > resultIdx {
		t.Errorf("payload-log-end (%d) must precede payload-result (%d): %v", endIdx, resultIdx, msgs)
	}
	if resultIdx != len(msgs)-1 {
		t.Errorf("payload-result must be terminal, but %v followed it", msgs[resultIdx+1:])
	}

	var chunks int
	for _, m := range msgs {
		if strings.HasPrefix(m, "payload-log-data-") {
			chunks++
		}
	}
	if chunks < 2 {
		t.Errorf("expected the log to span multiple chunks at MTU=1300, got %d", chunks)
	}

	if got := owner.GetLastResult(); got == nil || got.StatusCode != 2 {
		t.Errorf("owner result = %+v, want status 2", got)
	}
}

// TestPayloadLogDeclined verifies that an owner can refuse a log and that the
// device still reports its result.
func TestPayloadLogDeclined(t *testing.T) {
	logHandler := &stubLogHandler{accept: false, reasonCode: 5}
	owner := &PayloadOwner{LogHandler: logHandler}
	owner.AddPayload("text/plain", "conf", []byte("hello"), nil)

	device := &Payload{
		UnifiedHandler: &stubPayloadHandler{status: 2, message: "bad"},
		LogProvider:    &stubLogProvider{log: &PayloadLog{Data: []byte("some diagnostics")}},
	}

	msgs := payloadExchange(t, owner, device, 1300)

	if logHandler.got != nil {
		t.Error("owner received a log it declined")
	}
	for _, m := range msgs {
		if strings.HasPrefix(m, "payload-log-data-") {
			t.Fatalf("device sent log data after rejection: %v", msgs)
		}
	}
	if indexOf(msgs, "payload-log-begin") < 0 {
		t.Errorf("expected payload-log-begin to have been offered: %v", msgs)
	}
	if got := owner.GetLastResult(); got == nil || got.StatusCode != 2 {
		t.Errorf("owner result = %+v, want status 2 despite declined log", got)
	}
}

// TestPayloadLogNoHandlerStillCompletes verifies that an owner with no
// LogHandler configured declines cleanly and the exchange finishes.
func TestPayloadLogNoHandlerStillCompletes(t *testing.T) {
	owner := &PayloadOwner{}
	owner.AddPayload("text/plain", "conf", []byte("hello"), nil)

	device := &Payload{
		UnifiedHandler: &stubPayloadHandler{status: 0},
		LogProvider:    &stubLogProvider{log: &PayloadLog{Data: []byte("chatty but unwanted")}},
	}

	msgs := payloadExchange(t, owner, device, 1300)

	if owner.GetLastLog() != nil {
		t.Error("owner stored a log with no LogHandler configured")
	}
	if got := owner.GetLastResult(); got == nil || got.StatusCode != 0 {
		t.Errorf("owner result = %+v, want status 0: %v", got, msgs)
	}
}

// TestPayloadLogTruncation verifies MaxLogSize clamping and the truncated flag.
func TestPayloadLogTruncation(t *testing.T) {
	logHandler := &stubLogHandler{accept: true}
	owner := &PayloadOwner{LogHandler: logHandler}
	owner.AddPayload("text/plain", "conf", []byte("hello"), nil)

	big := bytes.Repeat([]byte("x"), 10000)
	device := &Payload{
		UnifiedHandler: &stubPayloadHandler{status: 1},
		LogProvider:    &stubLogProvider{log: &PayloadLog{Data: big}},
		MaxLogSize:     4096,
	}

	payloadExchange(t, owner, device, 1300)

	if logHandler.got == nil {
		t.Fatal("owner never received a log")
	}
	if len(logHandler.got.Data) != 4096 {
		t.Errorf("log length = %d, want 4096", len(logHandler.got.Data))
	}
	if !logHandler.got.Truncated {
		t.Error("truncated flag not set on a clipped log")
	}
}

// TestPayloadNoLogProvider verifies the unchanged path: no LogProvider means
// payload-result is sent directly with no log messages at all.
func TestPayloadNoLogProvider(t *testing.T) {
	owner := &PayloadOwner{LogHandler: &stubLogHandler{accept: true}}
	owner.AddPayload("text/plain", "conf", []byte("hello"), nil)

	device := &Payload{UnifiedHandler: &stubPayloadHandler{status: 0, message: "ok"}}

	msgs := payloadExchange(t, owner, device, 1300)

	for _, m := range msgs {
		if strings.HasPrefix(m, "payload-log-") {
			t.Fatalf("unexpected log message %q in %v", m, msgs)
		}
	}
	if got := owner.GetLastResult(); got == nil || got.StatusCode != 0 {
		t.Errorf("owner result = %+v", got)
	}
}

// TestPayloadLogProviderErrorIsNonFatal verifies that a failing LogProvider
// does not break onboarding.
func TestPayloadLogProviderErrorIsNonFatal(t *testing.T) {
	owner := &PayloadOwner{LogHandler: &stubLogHandler{accept: true}}
	owner.AddPayload("text/plain", "conf", []byte("hello"), nil)

	device := &Payload{
		UnifiedHandler: &stubPayloadHandler{status: 0},
		LogProvider:    &stubLogProvider{err: fmt.Errorf("cannot read journal")},
	}

	msgs := payloadExchange(t, owner, device, 1300)

	if got := owner.GetLastResult(); got == nil || got.StatusCode != 0 {
		t.Errorf("owner result = %+v, want status 0 despite log provider error: %v", got, msgs)
	}
}
