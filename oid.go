// SPDX-FileCopyrightText: (C) 2024 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"encoding/asn1"
)

// These OIDs are contants defined under "Delegate Protocol" in the sepcification

var OID_delegateBase asn1.ObjectIdentifier = asn1.ObjectIdentifier{1,3,6,1,4,1,45724,3}
var OID_delegateOnboard asn1.ObjectIdentifier = asn1.ObjectIdentifier{1,3,6,1,4,1,45724,3,1}
var OID_delegateUpload asn1.ObjectIdentifier = asn1.ObjectIdentifier{1,3,6,1,4,1,45724,3,2}
var OID_delegateRedirect asn1.ObjectIdentifier = asn1.ObjectIdentifier{1,3,6,1,4,1,45724,3,3}
var OID_delegateClaim asn1.ObjectIdentifier = asn1.ObjectIdentifier{1,3,6,1,4,1,45724,3,4}

