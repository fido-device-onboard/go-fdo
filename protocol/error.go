// SPDX-FileCopyrightText: (C) 2024 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package protocol

import (
	"fmt"
	"time"
)

// Error codes
const (
	// JWT token is missing or invalid. Each token has its own validity period,
	// server rejects expired tokens. Server failed to parse JWT token or JWT
	// signature did not verify correctly. The JWT token refers to the token
	// mentioned in section 4.3 (which is not required by protocol to be a JWT
	// token). The error message applies to non-JWT tokens, as well.
	//
	// Messages: DI.SetHMAC, TO0.OwnerSign, TO1.ProveToRV, TO2.GetOVNextEntry,
	//           TO2.ProveDevice, TO2.NextDeviceServiceInfo, TO2.Done
	InvalidJwtTokenCode = 1

	// Ownership Voucher is invalid: One of Ownership Voucher verification
	// checks has failed. Precise information is not returned to the client but
	// saved only in service logs.
	//
	// Messages: TO0.OwnerSign
	InvalidOwnershipVoucherCode = 2

	// Verification of signature of owner message failed. TO0.OwnerSign message
	// is signed by the final owner (using key signed by the last Ownership
	// Voucher entry). This error is returned in case that signature is
	// invalid.
	//
	// Messages: TO0.OwnerSign
	InvalidOwnerSignBodyCode = 3

	// IP address is invalid. Bytes that are provided in the request do not
	// represent a valid IPv4/IPv6 address.
	//
	// Messages: TO0.OwnerSign
	InvalidIPAddrCode = 4

	// GUID is invalid. Bytes that are provided in the request do not represent
	// a proper GUID.
	//
	// Messages: TO0.OwnerSign
	InvalidGUID = 5

	// The owner connection info for GUID is not found. TO0 Protocol wasn’t
	// properly executed for the specified GUID or information that was stored
	// in database has expired and/or has been removed.
	//
	// Messages: TO1.HelloRV, TO2.HelloDevice
	ResourceNotFound = 6

	// Message Body is structurally unsound: JSON parse error, or valid JSON,
	// but is not mapping to the expected Secure Device Onboard type (see 4.6)
	//
	// Messages: DI.AppStart, DI.SetHMAC, TO0.Hello, TO0.OwnerSign,
	//           TO1.HelloRV, TO1.ProveToRV, TO2.HelloDevice,
	//           TO2.GetOVNextEntry, TO2.ProveDevice,
	//           TO2.DeviceServiceInfo, TO2.OwnerServiceInfo, TO2.Done
	MessageBodyErrCode = 100

	// Message structurally sound, but failed validation tests. The nonce
	// didn’t match, signature didn’t verify, hash, or mac didn’t verify, index
	// out of bounds, etc...
	//
	// Messages: TO0.OwnerSign, TO1.HelloRV, TO1.ProveToRV, TO2.HelloDevice,
	//           TO2.GetOVNextEntry, TO2.ProveDevice,
	//           TO2.DeviceServiceInfo, TO2.OwnerServiceInfo,
	InvalidMessageErrCode = 101

	// Credential reuse rejected.
	//
	// Messages: TO2.SetupDevice
	CredReuseErrCode = 102

	// Something went wrong which couldn’t be classified otherwise.  (This was
	// chosen to match the HTTP 500 error code.)
	//
	// Messages: DI.AppStart, DI.SetHMAC, TO0.Hello, TO0.OwnerSign,
	//           TO1.HelloRV, TO1.ProveToRV, TO2.HelloDevice,
	//           TO2.GetOVNextEntry, TO2.ProveDevice,
	//           TO2.DeviceServiceInfo, TO2.OwnerServiceInfo, TO2.Done
	InternalServerErrCode = 500
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
	Timestamp     int64 // Timestamp once the Java implementation is fixed
	CorrelationID *uint
}

// String implements Stringer.
func (e ErrorMessage) String() string {
	return fmt.Sprintf("%s [code=%d,prevMsgType=%d,id=%d] %s",
		time.Unix(e.Timestamp, 0),
		e.Code, e.PrevMsgType, e.CorrelationID, e.ErrString,
	)
}

// Error implements the standard error interface.
func (e ErrorMessage) Error() string { return e.String() }
