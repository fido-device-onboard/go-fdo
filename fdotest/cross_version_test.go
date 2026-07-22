// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdotest_test

import (
	"testing"

	"github.com/fido-device-onboard/go-fdo/fdotest"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// TestCrossVersion_V11ClientV20Server runs the full onboarding flow using a
// v1.1 client (fdo.TO2) against a TO2Server that supports both v1.1 and v2.0.
// The server dispatches based on the message type received (60-71 for v1.1,
// 80-91 for v2.0), so a v1.1 client naturally gets v1.1 responses. This
// validates backwards compatibility: existing v1.1 devices must continue to
// work after a server is upgraded to support v2.0.
func TestCrossVersion_V11ClientV20Server(t *testing.T) {
	fdotest.RunClientTestSuite(t, fdotest.Config{
		ProtocolVersion: protocol.Version101,
	})
}

// TestCrossVersion_V11ThenV20Sequential runs a v1.1 onboarding followed by
// a v2.0 onboarding against the same server state. This simulates a fleet
// migration scenario where a device onboards with v1.1, the voucher is
// extended, and then the same device (now with a new credential) onboards
// again using v2.0. The two runs share the same in-memory state via
// RunClientTestSuite's internal state singleton.
func TestCrossVersion_V11ThenV20Sequential(t *testing.T) {
	t.Run("Phase1_V11", func(t *testing.T) {
		fdotest.RunClientTestSuite(t, fdotest.Config{
			ProtocolVersion: protocol.Version101,
		})
	})
	t.Run("Phase2_V20", func(t *testing.T) {
		fdotest.RunClientTestSuite(t, fdotest.Config{
			ProtocolVersion: protocol.Version200,
		})
	})
}

// TestCrossVersion_V20ThenV11Sequential is the reverse of the above: a v2.0
// onboarding followed by a v1.1 onboarding. This verifies that server state
// is not corrupted by a v2.0 session in a way that prevents subsequent v1.1
// sessions.
func TestCrossVersion_V20ThenV11Sequential(t *testing.T) {
	t.Run("Phase1_V20", func(t *testing.T) {
		fdotest.RunClientTestSuite(t, fdotest.Config{
			ProtocolVersion: protocol.Version200,
		})
	})
	t.Run("Phase2_V11", func(t *testing.T) {
		fdotest.RunClientTestSuite(t, fdotest.Config{
			ProtocolVersion: protocol.Version101,
		})
	})
}

// TestCrossVersion_V11WithCredentialReuse runs v1.1 with credential reuse
// to confirm it still works alongside v2.0 support. The credential reuse
// protocol has structural differences between v1.1 and v2.0 (where the
// replacement HMAC lives), so both versions must be tested independently.
func TestCrossVersion_V11WithCredentialReuse(t *testing.T) {
	fdotest.RunClientTestSuite(t, fdotest.Config{
		ProtocolVersion: protocol.Version101,
		Reuse:           true,
	})
}
