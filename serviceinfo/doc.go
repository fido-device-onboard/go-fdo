// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

/*
Package serviceinfo contains interfaces and implementations for service info
modules as well as types for handling CBOR-encoded service info.

Service info modules are the handlers for service info sent between the device
and owner service in message types 68 and 69. While the FDO 1.1 spec only
lightly describes "Management Service - Agent interactions" in section 3.8,
examples of service info modules may be found in the FIDO Alliance
[FSIM Repository]. The one defined service info module from the FDO spec is
devmod, which is required to be the first service info module in a TO2 session.

Service info is lists of key value pairs where the key is a string containing
the module name and message name and the value contains arbitrary data. Service
info modules are the logic for how the device and owner service should handle
and respond to different messages. Effectively, they are subprotocols of FDO.

Service info module implementations involve the logic handlers for the device
and owner service. These are referred to in Go-FDO as the Device Modules and
Owner Modules. Each service info module is the logical composition of
corresponding device and owner modules.

[FSIM Repository]: https://github.com/fido-alliance/fdo-sim
*/
package serviceinfo
