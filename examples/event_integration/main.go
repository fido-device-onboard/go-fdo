// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

// Package main demonstrates FDO event callback integration with external systems.
// This example shows how to use the EventHandler interface to integrate FDO events
// with databases, monitoring systems, and user interfaces.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// DatabaseEventLogger logs FDO events to a database for tracking device onboarding state
type DatabaseEventLogger struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewDatabaseEventLogger creates a new database event logger
func NewDatabaseEventLogger(db *sql.DB) *DatabaseEventLogger {
	return &DatabaseEventLogger{
		db:     db,
		logger: slog.New(slog.NewJSONHandler(os.Stdout, nil)),
	}
}

// HandleEvent processes FDO events and stores them in a database
func (d *DatabaseEventLogger) HandleEvent(ctx context.Context, event fdo.Event) {
	// In a real implementation, this would insert into a database
	// For this example, we'll just log the structured data
	d.logger.Info("FDO Event",
		"event_type", event.Type.String(),
		"timestamp", event.Timestamp,
		"guid", event.GUID,
		"protocol_version", event.ProtocolVersion,
		"has_error", event.Error != nil,
	)

	// Example: Track device onboarding state transitions
	if event.GUID != nil {
		switch event.Type {
		case fdo.EventTypeDICompleted:
			d.updateDeviceState(*event.GUID, "DI_COMPLETED", event.Timestamp)
		case fdo.EventTypeTO0Completed:
			d.updateDeviceState(*event.GUID, "TO0_COMPLETED", event.Timestamp)
		case fdo.EventTypeTO1Completed:
			d.updateDeviceState(*event.GUID, "TO1_COMPLETED", event.Timestamp)
		case fdo.EventTypeTO2Completed:
			// Check attestation mode to determine completion type
			if data, ok := event.Data.(fdo.TO2EventData); ok && data.AttestationMode == fdo.ModeSingleSided {
				d.updateDeviceState(*event.GUID, "TO2_SINGLE_SIDED_COMPLETED", event.Timestamp)
			} else {
				d.updateDeviceState(*event.GUID, "TO2_COMPLETED", event.Timestamp)
			}
		case fdo.EventTypeTO2SingleSidedComplete:
			// This is a specific trigger for single-sided completion
			// Client implementations can use this to re-attempt full onboarding
			d.updateDeviceState(*event.GUID, "TO2_SINGLE_SIDED_WIFI_READY", event.Timestamp)
		case fdo.EventTypeDIFailed, fdo.EventTypeTO0Failed, fdo.EventTypeTO1Failed, fdo.EventTypeTO2Failed:
			d.updateDeviceState(*event.GUID, "FAILED", event.Timestamp)
		}
	}
}

func (d *DatabaseEventLogger) updateDeviceState(guid protocol.GUID, state string, timestamp time.Time) {
	// In a real implementation:
	// _, err := d.db.Exec("UPDATE devices SET state = ?, last_update = ? WHERE guid = ?", state, timestamp, guid[:])
	d.logger.Info("Device state updated",
		"guid", fmt.Sprintf("%x", guid),
		"state", state,
		"timestamp", timestamp,
	)
}

// MetricsCollector collects metrics from FDO events for monitoring and alerting
type MetricsCollector struct {
	mu                 sync.Mutex
	diSuccessCount     int64
	diFailureCount     int64
	to0SuccessCount    int64
	to0FailureCount    int64
	to1SuccessCount    int64
	to1FailureCount    int64
	to2SuccessCount    int64
	to2FailureCount    int64
	certErrorCount     int64
	protocolErrorCount int64
	logger             *slog.Logger
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}
}

// HandleEvent processes FDO events and updates metrics
func (m *MetricsCollector) HandleEvent(ctx context.Context, event fdo.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch event.Type {
	case fdo.EventTypeDICompleted:
		m.diSuccessCount++
	case fdo.EventTypeDIFailed:
		m.diFailureCount++
	case fdo.EventTypeTO0Completed:
		m.to0SuccessCount++
	case fdo.EventTypeTO0Failed:
		m.to0FailureCount++
	case fdo.EventTypeTO1Completed:
		m.to1SuccessCount++
	case fdo.EventTypeTO1Failed:
		m.to1FailureCount++
	case fdo.EventTypeTO2Completed:
		m.to2SuccessCount++
	case fdo.EventTypeTO2Failed:
		m.to2FailureCount++
	case fdo.EventTypeCertValidationFailed:
		m.certErrorCount++
	case fdo.EventTypeProtocolError:
		m.protocolErrorCount++
	}

	// In a real implementation, these would be exported to Prometheus, StatsD, etc.
	m.logger.Debug("Metrics updated",
		"di_success", m.diSuccessCount,
		"di_failure", m.diFailureCount,
		"to2_success", m.to2SuccessCount,
		"to2_failure", m.to2FailureCount,
	)
}

// GetMetrics returns current metrics snapshot
func (m *MetricsCollector) GetMetrics() map[string]int64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	return map[string]int64{
		"di_success":      m.diSuccessCount,
		"di_failure":      m.diFailureCount,
		"to0_success":     m.to0SuccessCount,
		"to0_failure":     m.to0FailureCount,
		"to1_success":     m.to1SuccessCount,
		"to1_failure":     m.to1FailureCount,
		"to2_success":     m.to2SuccessCount,
		"to2_failure":     m.to2FailureCount,
		"cert_errors":     m.certErrorCount,
		"protocol_errors": m.protocolErrorCount,
	}
}

// WebhookNotifier sends FDO events to external webhooks for real-time notifications
type WebhookNotifier struct {
	webhookURL string
	logger     *slog.Logger
}

// NewWebhookNotifier creates a new webhook notifier
func NewWebhookNotifier(webhookURL string) *WebhookNotifier {
	return &WebhookNotifier{
		webhookURL: webhookURL,
		logger:     slog.New(slog.NewJSONHandler(os.Stdout, nil)),
	}
}

// HandleEvent processes FDO events and sends notifications
func (w *WebhookNotifier) HandleEvent(ctx context.Context, event fdo.Event) {
	// Only notify on important events
	switch event.Type {
	case fdo.EventTypeDICompleted, fdo.EventTypeTO2Completed,
		fdo.EventTypeDIFailed, fdo.EventTypeTO2Failed,
		fdo.EventTypeCertValidationFailed:
		// In a real implementation, this would POST to the webhook
		payload := map[string]interface{}{
			"event_type": event.Type.String(),
			"timestamp":  event.Timestamp,
			"guid":       event.GUID,
			"error":      nil,
		}
		if event.Error != nil {
			payload["error"] = event.Error.Error()
		}

		jsonData, _ := json.Marshal(payload)
		w.logger.Info("Webhook notification",
			"url", w.webhookURL,
			"payload", string(jsonData),
		)
	}
}

// UIStateManager manages device state for a user interface
type UIStateManager struct {
	mu      sync.RWMutex
	devices map[string]*DeviceState
	logger  *slog.Logger
}

// DeviceState represents the current state of a device in the UI
type DeviceState struct {
	GUID            string
	CurrentState    string
	LastUpdate      time.Time
	ProtocolVersion string
	ErrorMessage    string
	Progress        int // 0-100
}

// NewUIStateManager creates a new UI state manager
func NewUIStateManager() *UIStateManager {
	return &UIStateManager{
		devices: make(map[string]*DeviceState),
		logger:  slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}
}

// HandleEvent processes FDO events and updates UI state
func (u *UIStateManager) HandleEvent(ctx context.Context, event fdo.Event) {
	if event.GUID == nil {
		return
	}

	guidStr := fmt.Sprintf("%x", *event.GUID)

	u.mu.Lock()
	defer u.mu.Unlock()

	state, exists := u.devices[guidStr]
	if !exists {
		state = &DeviceState{
			GUID: guidStr,
		}
		u.devices[guidStr] = state
	}

	state.LastUpdate = event.Timestamp
	state.ProtocolVersion = fmt.Sprintf("%d", event.ProtocolVersion)

	// Update state and progress based on event type
	switch event.Type {
	case fdo.EventTypeDIStarted:
		state.CurrentState = "Initializing Device"
		state.Progress = 10
	case fdo.EventTypeDICompleted:
		state.CurrentState = "Device Initialized"
		state.Progress = 25
	case fdo.EventTypeTO0Started:
		state.CurrentState = "Registering with Rendezvous"
		state.Progress = 30
	case fdo.EventTypeTO0Completed:
		state.CurrentState = "Rendezvous Registration Complete"
		state.Progress = 40
	case fdo.EventTypeTO1Started:
		state.CurrentState = "Contacting Rendezvous"
		state.Progress = 50
	case fdo.EventTypeTO1Completed:
		state.CurrentState = "Owner Service Located"
		state.Progress = 60
	case fdo.EventTypeTO2Started:
		state.CurrentState = "Onboarding to Owner"
		state.Progress = 70
	case fdo.EventTypeTO2KeyExchangeCompleted:
		state.CurrentState = "Secure Channel Established"
		state.Progress = 80
	case fdo.EventTypeTO2ServiceInfoCompleted:
		state.CurrentState = "Configuration Applied"
		state.Progress = 90
	case fdo.EventTypeTO2Completed:
		state.CurrentState = "Onboarding Complete"
		state.Progress = 100
	case fdo.EventTypeDIFailed, fdo.EventTypeTO0Failed, fdo.EventTypeTO1Failed, fdo.EventTypeTO2Failed:
		state.CurrentState = "Failed"
		state.Progress = 0
		if event.Error != nil {
			state.ErrorMessage = event.Error.Error()
		}
	case fdo.EventTypeCertValidationFailed:
		state.CurrentState = "Certificate Validation Failed"
		state.ErrorMessage = event.CertErrorMsg
	}

	u.logger.Info("UI state updated",
		"guid", guidStr,
		"state", state.CurrentState,
		"progress", state.Progress,
	)
}

// GetDeviceState returns the current state of a device
func (u *UIStateManager) GetDeviceState(guid string) *DeviceState {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.devices[guid]
}

// GetAllDevices returns all tracked devices
func (u *UIStateManager) GetAllDevices() []*DeviceState {
	u.mu.RLock()
	defer u.mu.RUnlock()

	devices := make([]*DeviceState, 0, len(u.devices))
	for _, state := range u.devices {
		devices = append(devices, state)
	}
	return devices
}

func main() {
	slog.Info("FDO Event Integration Example")

	// Example 1: Database event logger
	// In a real implementation, you would open a real database connection
	// db, _ := sql.Open("postgres", "connection_string")
	// dbLogger := NewDatabaseEventLogger(db)
	// fdo.RegisterEventHandler(dbLogger)

	// Example 2: Metrics collector
	metrics := NewMetricsCollector()
	fdo.RegisterEventHandler(metrics)

	// Example 3: Webhook notifier
	webhook := NewWebhookNotifier("https://example.com/fdo-webhook")
	fdo.RegisterEventHandler(webhook)

	// Example 4: UI state manager
	uiManager := NewUIStateManager()
	fdo.RegisterEventHandler(uiManager)

	// Example 5: Simple function-based handler
	fdo.RegisterEventHandler(fdo.EventHandlerFunc(func(ctx context.Context, event fdo.Event) {
		if event.Error != nil {
			slog.Error("FDO Error Event",
				"type", event.Type.String(),
				"error", event.Error,
			)
		}
	}))

	slog.Info("Event handlers registered successfully")

	// Note: In real usage, events are emitted automatically by the FDO library
	// during protocol execution (DI, TO0, TO1, TO2). The handlers above will
	// receive those events and process them accordingly.

	slog.Info("Event handlers are now active and will receive FDO protocol events")
	time.Sleep(100 * time.Millisecond)

	// Display metrics
	slog.Info("Current Metrics", "metrics", metrics.GetMetrics())

	// Display UI state
	for _, device := range uiManager.GetAllDevices() {
		slog.Info("Device State",
			"guid", device.GUID,
			"state", device.CurrentState,
			"progress", device.Progress,
		)
	}

	slog.Info("Event integration example completed")
	slog.Info("In production, these handlers would integrate with:")
	slog.Info("  - PostgreSQL/MySQL for device state tracking")
	slog.Info("  - Prometheus/Grafana for metrics and monitoring")
	slog.Info("  - Slack/PagerDuty webhooks for alerting")
	slog.Info("  - React/Vue.js UIs for real-time device status")
	slog.Info("  - Elasticsearch/Kibana for log aggregation")

	// Keep the example running briefly to show async event handling
	time.Sleep(500 * time.Millisecond)

	// Cleanup
	fdo.UnregisterAllEventHandlers()
	slog.Info("Event handlers unregistered")
}
