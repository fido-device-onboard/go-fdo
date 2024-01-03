// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"fmt"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// ErrorMessage indicates that the previous protocol message could not be
// processed. The error message is a “catch-all” whenever processing cannot
// continue. This includes protocol errors and any trust or security
// violations.
//
// The FIDO Device Onboard protocol is always terminated after an error message
// (and retries, automatically, as per RendezvousInfo), and all FIDO Device
// Onboard error conditions send an error message. However, security errors
// might not indicate the exact cause of the problem, if this would cause a
// security issue.
//
// The contents of the error message are intended to help diagnose the error.
// The “EMErrorCode” is an error code, please see following section, Error Code
// Values, for detailed information. The “EMPrevMsgID” gives the message ID of
// the previous message, making it easier to put the error into context. The
// “EMErrorStr” tag gives a string suitable for logging about the error.
//
// The string in the “EMErrorStr” tag must not include security details that
// are inappropriate for logging, such as a specific security condition, or any
// key or password information.
//
// The values EMErrorTS and EMErrorCID are intended to expedite diagnosis of
// problems, especially between cloud-based entities where large logs must be
// searched. In a typical scenario, an endpoint generates a correlation ID for
// each request and includes it in column of each event or trace logged
// throughout processing for that request. The combination of correlation ID
// and the time of the transaction help to find the log item and its context.
//
// EMErrorTS and EMErrorUuid may be CBOR Null if there is no appropriate value.
// This may occur in Device based implementations. In some Devices, a time
// value may exist that is not correlated to UTC time, but might still be
// useful. The TIMET choice is intended to remove the UTC restriction and allow
// a Device-local time value to be used.
//
//	ErrorMessage = [
//	    EMErrorCode: uint16,       ;; Error code
//	    EMPrevMsgID: uint8,        ;; Message ID of the previous message
//	    EMErrorStr:  tstr,         ;; Error string
//	    EMErrorTs:   timestamp,    ;; UTC timestamp
//	    EMErrorCID:  correlationId ;; Unique id associated with this request
//	]
//	correlationId = uint
type ErrorMessage struct {
	Code          uint16
	PrevMsg       uint8
	String        string
	Timestamp     Timestamp
	CorrelationID uint
}

// Timestamp implements the timestamp CBOR format used in the FDO error message
// type. The expected string format, if used, is RFC3339.
//
//	timestamp = null / UTCStr / UTCInt / TIME_T
//	UTCStr = #6.0(tstr)
//	UTCInt = #6.1(uint)
//	TIMET  = #6.1(uint)
type Timestamp time.Time

func (ts Timestamp) MarshalCBOR() ([]byte, error) {
	if time.Time(ts).IsZero() {
		return cbor.Marshal(nil)
	}
	return cbor.Marshal(cbor.Tag[int]{
		Num: 1,
		Val: time.Time(ts).UTC().Second(),
	})
}

func (ts *Timestamp) UnmarshalCBOR(data []byte) error {
	// Parse into a null or tag structure
	var tag *cbor.Tag[cbor.RawBytes]
	if err := cbor.Unmarshal(data, &tag); err != nil {
		return err
	}

	// If value is null, set timestamp to zero value
	if tag == nil {
		*ts = Timestamp(time.Time{})
		return nil
	}

	switch tag.Number() {
	// Tag 0: Parse string as RFC3339
	case 0:
		var value string
		if err := cbor.Unmarshal([]byte(tag.Val), &value); err != nil {
			return err
		}
		t, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return fmt.Errorf("invalid timestamp string, must be RFC3339 format: %w", err)
		}
		*ts = Timestamp(t)
		return nil

	// Tag 1: Parse uint as seconds
	case 1:
		var sec int64
		if err := cbor.Unmarshal([]byte(tag.Val), &sec); err != nil {
			return err
		}
		*ts = Timestamp(time.Unix(sec, 0))
		return nil
	}

	return fmt.Errorf("unknown tag number %d", tag.Number())
}

type neverRetry struct{}

func (neverRetry) ShouldRetry(ErrorMessage) <-chan time.Time { return nil }

// Retrier implements RetryDecider by retrying up to a maximum number of times.
// The rules used are as follows:
//
//  1. The error string, timestamp, and correlation ID are not considered.
//  2. The protocol of the previous message type is determined.
//  3. If the previous message type has an integer value greater than or equal
//     to the last error of the same protocol, the retry counter is increased.
//     If the value is less, then the retry counter is cleared.
//  4. If the retry counter exceeds the maximum, then a nil chan is returned.
//  5. Otherwise, a receive-only chan that is sent a value after some backoff
//     is returned.
//
// This type is not safe for use in clients that may be used concurrently.
type Retrier struct {
	max      int64
	counters map[Protocol]*retryCount
}

type retryCount struct {
	prev  uint8
	count int64
}

// Retry n times with a default backoff scheme.
//
// The returned value is not safe for use in clients that may be used
// concurrently.
func Retry(n int64) *Retrier {
	return &Retrier{
		max:      n,
		counters: make(map[Protocol]*retryCount),
	}
}

func (r *Retrier) ShouldRetry(em ErrorMessage) <-chan time.Time {
	// Get the protocol counter, initializing it as needed
	proto := ProtocolOf(em.PrevMsg)
	counter := r.counters[proto]
	if counter == nil {
		counter = new(retryCount)
		r.counters[proto] = counter
	}

	// Reset the counter if the message type ID has gone backwards
	if counter.prev >= em.PrevMsg {
		counter.count = 0
	}

	// Update the counter
	counter.count++
	counter.prev = em.PrevMsg

	// Decide whether to retry
	if counter.count > r.max {
		return nil
	}
	// TODO: Default delay is 120s +/- 30s
	return time.After(time.Second)
}
