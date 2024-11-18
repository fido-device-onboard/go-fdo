// SPDX-FileCopyrightText: (C) 2024 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"encoding/asn1"
	"fmt"
)

// These OIDs are contants defined under "Delegate Protocol" in the sepcification

var OID_delegateBase asn1.ObjectIdentifier = asn1.ObjectIdentifier{1,3,6,1,4,1,45724,3}
var OID_delegateOnboard asn1.ObjectIdentifier = asn1.ObjectIdentifier{1,3,6,1,4,1,45724,3,1}
var OID_delegateUpload asn1.ObjectIdentifier = asn1.ObjectIdentifier{1,3,6,1,4,1,45724,3,2}
var OID_delegateRedirect asn1.ObjectIdentifier = asn1.ObjectIdentifier{1,3,6,1,4,1,45724,3,3}
var OID_delegateClaim asn1.ObjectIdentifier = asn1.ObjectIdentifier{1,3,6,1,4,1,45724,3,4}
var OID_delegateProvision asn1.ObjectIdentifier = asn1.ObjectIdentifier{1,3,6,1,4,1,45724,3,5}

var oidMap  = map[int]string {
	1: "onboard",
	2: "upload",
	3: "redirect",
	4: "claim",
	5: "provision",
}

func DelegateOIDtoString(oid asn1.ObjectIdentifier)(string, error) {
	if (oid.Equal(OID_delegateOnboard)) { return "onboard", nil }
	if (oid.Equal(OID_delegateUpload)) { return "upload", nil }
	if (oid.Equal(OID_delegateRedirect)) { return "redirect", nil }
	if (oid.Equal(OID_delegateClaim)) { return "claim", nil }
	if (oid.Equal(OID_delegateProvision)) { return "provision", nil }
	return oid.String(), fmt.Errorf("Invalid Delegate OID")
}

func DelegateStringToOID(str string) (asn1.ObjectIdentifier, error) {
	switch {
		case str == "onboard": return OID_delegateOnboard,nil
		case str == "upload": return OID_delegateUpload,nil
		case str == "redirect": return OID_delegateRedirect,nil
		case str == "claim": return OID_delegateClaim,nil
		case str == "provision": return OID_delegateProvision,nil
		default: return OID_delegateBase, fmt.Errorf("Invalid Delegate OID string")

	}
}
