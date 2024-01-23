// Copyright 2023 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"fmt"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
)

// ErrorMsgType is the response type number associated with an ErrorMessage
// response.
const ErrorMsgType uint8 = 255

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
	PrevMsgType   uint8
	ErrString     string
	Timestamp     Timestamp
	CorrelationID uint
}

// String implements Stringer.
func (e ErrorMessage) String() string {
	return fmt.Sprintf("%s [code=%d,prevMsgType=%d,id=%d] %s",
		time.Time(e.Timestamp), e.Code, e.PrevMsgType, e.CorrelationID, e.ErrString,
	)
}

// Error implements the standard error interface.
func (e ErrorMessage) Error() string { return e.String() }

// Timestamp implements the timestamp CBOR format used in the FDO error message
// type. The expected string format, if used, is RFC3339.
//
//	timestamp = null / UTCStr / UTCInt / TIME_T
//	UTCStr = #6.0(tstr)
//	UTCInt = #6.1(uint)
//	TIMET  = #6.1(uint)
type Timestamp time.Time

// MarshalCBOR implements cbor.Marshaler.
func (ts Timestamp) MarshalCBOR() ([]byte, error) {
	if time.Time(ts).IsZero() {
		return cbor.Marshal(nil)
	}
	return cbor.Marshal(cbor.Tag[int]{
		Num: 1,
		Val: time.Time(ts).UTC().Second(),
	})
}

// UnmarshalCBOR implements cbor.Unmarshaler.
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
