// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fsim

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/fsim/chunking"
	"github.com/fido-device-onboard/go-fdo/serviceinfo"
)

// multiLogHandler records every log it receives.
type multiLogHandler struct {
	accept bool
	logs   []*PayloadLogInfo
	names  []string
}

func (h *multiLogHandler) AcceptLog(_, _ string, _ uint64, _ string) (bool, int, string) {
	if h.accept {
		return true, 0, ""
	}
	return false, 0, "no thanks"
}

func (h *multiLogHandler) HandleLog(_ context.Context, _, name string, log *PayloadLogInfo) error {
	h.logs = append(h.logs, log)
	h.names = append(h.names, name)
	return nil
}

// standaloneExchange is payloadExchange plus the parts of the TO2 device
// loop that standalone logs depend on: "active" is answered by the harness
// (as to2_module.go does) and Yield is called after each owner round.
// It returns the owner's and the device's message names, in order.
func standaloneExchange(t *testing.T, owner *PayloadOwner, device *Payload) (ownerMsgs, deviceMsgs []string) {
	t.Helper()
	ctx := context.Background()
	active := false

	for round := 0; round < 200; round++ {
		producer := serviceinfo.NewProducer("fdo.payload", 1300)
		_, done, err := owner.ProduceInfo(ctx, producer)
		if err != nil {
			t.Fatalf("round %d: owner ProduceInfo: %v", round, err)
		}

		var responses []*serviceinfo.KV
		respond := func(messageName string) io.Writer {
			responses = append(responses, &serviceinfo.KV{Key: messageName})
			return &kvWriter{kv: responses[len(responses)-1], buf: &bytes.Buffer{}}
		}

		for _, kv := range producer.ServiceInfo() {
			_, messageName, _ := strings.Cut(kv.Key, ":")
			ownerMsgs = append(ownerMsgs, messageName)
			if messageName == "active" {
				if !active {
					active = true
					if err := device.Transition(true); err != nil {
						t.Fatal(err)
					}
					_, _ = respond("active").Write([]byte{0xf5})
				}
				continue
			}
			if err := device.Receive(ctx, messageName, bytes.NewReader(kv.Val), respond, func() {}); err != nil {
				t.Fatalf("round %d: device Receive(%s): %v", round, messageName, err)
			}
		}
		if active {
			if err := device.Yield(ctx, respond, func() {}); err != nil {
				t.Fatalf("round %d: device Yield: %v", round, err)
			}
		}

		if done {
			// The module is no longer current: anything the device says
			// now would be discarded by the owner's service info loop.
			for _, kv := range responses {
				t.Errorf("device message %q sent after the owner concluded the FSIM", kv.Key)
			}
			return ownerMsgs, deviceMsgs
		}
		for _, kv := range responses {
			deviceMsgs = append(deviceMsgs, kv.Key)
			if err := owner.HandleInfo(ctx, kv.Key, bytes.NewReader(kv.Val)); err != nil {
				t.Fatalf("round %d: owner HandleInfo(%s): %v", round, kv.Key, err)
			}
		}
	}
	t.Fatal("exchange did not complete within 200 rounds")
	return nil, nil
}

func intPtr(v int) *int { return &v }

// TestStandaloneLogReportOnly is the install-report case: a report-only
// device returns its install log and refuses every payload the owner offers,
// before any payload data is sent.
func TestStandaloneLogReportOnly(t *testing.T) {
	logBody := []byte(strings.Repeat("subiquity: curtin command failed\n", 200))

	handler := &multiLogHandler{accept: true}
	owner := &PayloadOwner{LogHandler: handler}
	owner.AddPayloadWithAck("application/vnd.canonical.autoinstall+yaml", "autoinstall.yaml", []byte("autoinstall: {}"), nil)
	owner.AddPayloadWithAck("application/x-iso9660-image", "ubuntu.iso", bytes.Repeat([]byte{0}, 5000), nil)

	report := &StandaloneLog{
		PayloadLog:     PayloadLog{Data: logBody, Source: "installer"},
		Phase:          "install",
		Outcome:        intPtr(2),
		OutcomeMessage: "install failed",
		PayloadName:    "autoinstall.yaml",
		PayloadVersion: "v1",
	}
	device := &Payload{ReportOnly: true, StandaloneLogs: []*StandaloneLog{report}}

	ownerMsgs, deviceMsgs := standaloneExchange(t, owner, device)
	t.Logf("owner: %v", ownerMsgs)
	t.Logf("device: %v", deviceMsgs)

	if !report.Delivered() {
		t.Fatalf("report not delivered: result=%+v declined=%+v", report.Result, report.Declined)
	}
	if len(handler.logs) != 1 {
		t.Fatalf("owner received %d logs, want 1", len(handler.logs))
	}
	got := handler.logs[0]
	if !got.Standalone || got.Phase != "install" || got.Source != "installer" {
		t.Errorf("log metadata = %+v", got)
	}
	if got.Outcome == nil || *got.Outcome != 2 || got.OutcomeMessage != "install failed" {
		t.Errorf("outcome = %v %q, want 2 \"install failed\"", got.Outcome, got.OutcomeMessage)
	}
	if got.PayloadName != "autoinstall.yaml" || got.PayloadVersion != "v1" || handler.names[0] != "autoinstall.yaml" {
		t.Errorf("payload correlation = %q/%q (name arg %q)", got.PayloadName, got.PayloadVersion, handler.names[0])
	}
	if !bytes.Equal(got.Data, logBody) {
		t.Errorf("log body: got %d bytes, want %d", len(got.Data), len(logBody))
	}

	for _, m := range ownerMsgs {
		if strings.HasPrefix(m, "payload-data-") {
			t.Errorf("owner sent payload data to a report-only device: %v", ownerMsgs)
			break
		}
	}
	if n := strings.Count(strings.Join(deviceMsgs, " "), "payload-ack"); n != 2 {
		t.Errorf("device sent %d payload-acks, want 2 (one rejection per payload): %v", n, deviceMsgs)
	}
	if owner.GetLastResult() != nil {
		t.Errorf("unexpected payload-result: %+v", owner.GetLastResult())
	}
}

// TestStandaloneLogsWithoutPayloads checks an owner with nothing to deliver
// still activates the module to collect logs, takes several logs in order,
// and tells "success" (explicit status 0) apart from "not stated".
func TestStandaloneLogsWithoutPayloads(t *testing.T) {
	handler := &multiLogHandler{accept: true}
	owner := &PayloadOwner{LogHandler: handler}

	progress := &StandaloneLog{PayloadLog: PayloadLog{Data: []byte("iso mounted\n")}, Phase: "iso-mount"}
	final := &StandaloneLog{PayloadLog: PayloadLog{Data: []byte("done\n")}, Phase: "install", Outcome: intPtr(0)}
	device := &Payload{ReportOnly: true, StandaloneLogs: []*StandaloneLog{progress, final}}

	standaloneExchange(t, owner, device)

	if !progress.Delivered() || !final.Delivered() {
		t.Fatalf("delivered = %v, %v", progress.Delivered(), final.Delivered())
	}
	if len(handler.logs) != 2 {
		t.Fatalf("owner received %d logs, want 2", len(handler.logs))
	}
	if handler.logs[0].Phase != "iso-mount" || handler.logs[1].Phase != "install" {
		t.Errorf("logs out of order: %q, %q", handler.logs[0].Phase, handler.logs[1].Phase)
	}
	if handler.logs[0].Outcome != nil {
		t.Errorf("progress log outcome = %d, want not stated", *handler.logs[0].Outcome)
	}
	if o := handler.logs[1].Outcome; o == nil || *o != 0 {
		t.Errorf("final log outcome = %v, want explicit 0", o)
	}
}

// TestStandaloneLogDeclined: an owner that does not want the log declines
// it at the ack; no data is sent and the session still completes.
func TestStandaloneLogDeclined(t *testing.T) {
	for name, owner := range map[string]*PayloadOwner{
		"handler declines": {LogHandler: &multiLogHandler{accept: false}},
		"no handler":       {},
	} {
		t.Run(name, func(t *testing.T) {
			owner.AddPayloadWithAck("text/plain", "conf", []byte("hello"), nil)
			report := &StandaloneLog{PayloadLog: PayloadLog{Data: []byte("log")}}
			device := &Payload{
				UnifiedHandler: &stubPayloadHandler{status: 0},
				StandaloneLogs: []*StandaloneLog{report},
			}

			_, deviceMsgs := standaloneExchange(t, owner, device)

			if report.Declined == nil || report.Declined.ReasonCode != chunking.AckReasonDiagnosticsNotRequested {
				t.Errorf("declined = %+v, want reason 5", report.Declined)
			}
			if report.Delivered() {
				t.Error("declined log reported as delivered")
			}
			for _, m := range deviceMsgs {
				if strings.HasPrefix(m, "payload-log-data-") {
					t.Fatalf("device sent log data after decline: %v", deviceMsgs)
				}
			}
			if r := owner.GetLastResult(); r == nil || r.StatusCode != 0 {
				t.Errorf("payload result = %+v, want the payload still applied", r)
			}
		})
	}
}

// ownerAwaitingPayloadAck drives an owner with one require-ack payload until
// it is waiting for the device's payload-ack.
func ownerAwaitingPayloadAck(t *testing.T, owner *PayloadOwner) {
	t.Helper()
	ctx := context.Background()
	for _, want := range []string{"active", "payload-begin"} {
		producer := serviceinfo.NewProducer("fdo.payload", 1300)
		if _, _, err := owner.ProduceInfo(ctx, producer); err != nil {
			t.Fatal(err)
		}
		kvs := producer.ServiceInfo()
		if len(kvs) == 0 || !strings.HasSuffix(kvs[0].Key, want) {
			t.Fatalf("owner sent %v, want %s", kvs, want)
		}
		if want == "active" {
			if err := owner.HandleInfo(ctx, "active", bytes.NewReader([]byte{0xf5})); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// offerLog feeds the owner a payload-log-begin and returns its payload-log-ack.
func offerLog(t *testing.T, owner *PayloadOwner, metadata map[string]any) chunking.AckMessage {
	t.Helper()
	ctx := context.Background()
	begin := chunking.BeginMessage{TotalSize: 3, HashAlg: "sha256", RequireAck: true, Metadata: metadata}
	data, err := begin.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.HandleInfo(ctx, "payload-log-begin", bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	producer := serviceinfo.NewProducer("fdo.payload", 1300)
	if _, _, err := owner.ProduceInfo(ctx, producer); err != nil {
		t.Fatal(err)
	}
	for _, kv := range producer.ServiceInfo() {
		if strings.HasSuffix(kv.Key, "payload-log-ack") {
			var ack chunking.AckMessage
			if err := ack.UnmarshalCBOR(kv.Val); err != nil {
				t.Fatal(err)
			}
			return ack
		}
	}
	t.Fatalf("owner sent no payload-log-ack: %v", producer.ServiceInfo())
	return chunking.AckMessage{}
}

// TestStandaloneLogOwnerBusy: the same-round race. A standalone log offered
// while the owner's payload transfer is in progress is answered Busy (6).
func TestStandaloneLogOwnerBusy(t *testing.T) {
	owner := &PayloadOwner{LogHandler: &multiLogHandler{accept: true}}
	owner.AddPayloadWithAck("text/plain", "conf", []byte("hello"), nil)
	ownerAwaitingPayloadAck(t, owner)

	ack := offerLog(t, owner, map[string]any{"standalone": true})
	if ack.Accepted || ack.ReasonCode != chunking.AckReasonBusy {
		t.Errorf("ack = %+v, want [false, 6]", ack)
	}
}

// TestUnflaggedLogWithoutPayloadDeclined: a log not marked standalone while
// no payload awaits its result is neither nested nor standalone.
func TestUnflaggedLogWithoutPayloadDeclined(t *testing.T) {
	owner := &PayloadOwner{LogHandler: &multiLogHandler{accept: true}}
	producer := serviceinfo.NewProducer("fdo.payload", 1300)
	if _, _, err := owner.ProduceInfo(context.Background(), producer); err != nil {
		t.Fatal(err)
	}

	ack := offerLog(t, owner, map[string]any{"content_type": "text/plain"})
	if ack.Accepted || ack.ReasonCode != chunking.AckReasonDiagnosticsNotRequested {
		t.Errorf("ack = %+v, want [false, 5]", ack)
	}
}

// TestStandaloneLogDeviceRetriesAfterBusy: Busy is not a final decline; the
// device keeps the log and offers it again.
func TestStandaloneLogDeviceRetriesAfterBusy(t *testing.T) {
	ctx := context.Background()
	report := &StandaloneLog{PayloadLog: PayloadLog{Data: []byte("log")}}
	device := &Payload{ReportOnly: true, StandaloneLogs: []*StandaloneLog{report}}
	if err := device.Transition(true); err != nil {
		t.Fatal(err)
	}

	var sent []string
	respond := func(name string) io.Writer { sent = append(sent, name); return io.Discard }

	if err := device.Yield(ctx, respond, func() {}); err != nil {
		t.Fatal(err)
	}
	busy, _ := (&chunking.AckMessage{ReasonCode: chunking.AckReasonBusy}).MarshalCBOR()
	if err := device.Receive(ctx, "payload-log-ack", bytes.NewReader(busy), respond, func() {}); err != nil {
		t.Fatal(err)
	}
	if report.Declined != nil {
		t.Fatalf("Busy recorded as a final decline: %+v", report.Declined)
	}
	if err := device.Yield(ctx, respond, func() {}); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.Join(sent, " "), "payload-log-begin"); n != 2 {
		t.Errorf("payload-log-begin sent %d times, want 2 (offer + retry): %v", n, sent)
	}
}

// TestSendLogBodyPacksMessages checks the two rules the device's service info
// loop imposes on a multi-message log (see sendLogBody): no message is
// over-filled (the chunker would split a KV across messages), and yield is
// never called on an empty message (that ends the round and loses the rest).
func TestSendLogBodyPacksMessages(t *testing.T) {
	const mtu = 1300
	ctx := context.WithValue(context.Background(), serviceinfo.MTUKey{}, uint16(mtu))
	sender := chunking.NewChunkSender("payload-log", bytes.Repeat([]byte("x"), 50000))
	sender.BeginFields.HashAlg = "sha256"

	// The message already holds a small reply when the log starts.
	var sizes []int
	cur := 200
	respond := func(name string) io.Writer {
		cur += len(name) + 4 // key and KV framing
		return writerFunc(func(p []byte) (int, error) { cur += len(p); return len(p), nil })
	}
	yield := func() {
		if cur == 0 {
			t.Fatal("yield on an empty message")
		}
		sizes = append(sizes, cur)
		cur = 0
	}
	if err := sendLogBody(ctx, sender, respond, yield); err != nil {
		t.Fatal(err)
	}
	sizes = append(sizes, cur)

	if len(sizes) < 40 {
		t.Errorf("50000 bytes at MTU %d went out in only %d messages", mtu, len(sizes))
	}
	for i, n := range sizes {
		if n > mtu {
			t.Errorf("message %d holds %d bytes, over the %d MTU", i, n, mtu)
		}
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// TestOwnerLogOnlyDeviceInactive: an owner activated only to collect logs
// concludes quietly when the device does not support the module.
func TestOwnerLogOnlyDeviceInactive(t *testing.T) {
	ctx := context.Background()
	owner := &PayloadOwner{LogHandler: &multiLogHandler{accept: true}}
	if _, _, err := owner.ProduceInfo(ctx, serviceinfo.NewProducer("fdo.payload", 1300)); err != nil {
		t.Fatal(err)
	}
	inactive, _ := cbor.Marshal(false)
	if err := owner.HandleInfo(ctx, "active", bytes.NewReader(inactive)); err != nil {
		t.Fatalf("inactive device should not fail a log-only owner: %v", err)
	}
	_, done, err := owner.ProduceInfo(ctx, serviceinfo.NewProducer("fdo.payload", 1300))
	if err != nil || !done {
		t.Errorf("done=%v err=%v, want done", done, err)
	}
}
