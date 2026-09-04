# FDO Service Info Module: fdo.csr

Copyright &copy; 2023 FIDO Alliance

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

------------------

This specification defines the 'CSR' (certificate signing request) FDO serviceinfo module (FSIM) for the purpose of certificate enrollment. An FSIM is a set of key-value pairs; they define the onboarding operations that can be performed on a given FDO device. FSIM key-value pairs are exchanged between the device and it's owning Device Management Service. It is up to the owning Device Management Service and the device to interpret the key-value pairs in accordance with the FSIM specification.

This specification supports a number of features related to certificate enrollment, including client- and server-side key generation. To support constrained IoT devices not all features are mandatory to implement by an FDO Device.

## fdo.csr FSIM Definition

The CSR module provides the functionality to issue a certificate signing request from the FDO Device to a Certification Authority (CA) or a Registration Authority (RA) via the owning Device Management Service. It supports a subset of the functionality defined in RFC 7030, for example the full Certificate Management over CMS (CMC) functionality is not supported. The benefit of re-using RFC 7030 is the ability to integrate with existing certificate enrollment infrastructure. Such integration may, for example, utilize the owning Device Management Service to relay communication between a CA back and the device. The communication from the owning Device Management Service to the CA may happen via the Enrollment over Secure Transport protocol (EST). Since this specification re-uses the standardized payloads, those can be re-used for the communication between the owning Device Management Service and the device.

The CSR FSIM supports the following functionality:

- Distribution of CA certificates
- Enrollments of clients
- Re-enrollment of clients
- Server-side key generation
- CSR attributes

A constrained device may not be able to afford to implement both client- and server-side key generation functionality. Hence, this specification allows to implement either of the two features. CSR attributes discovery is an optional feature.

FSIM's communicate over a reliable channel that experiences communication security with confidentiality, integrity and replay protection. Certificate enrollment messages benefit from the security protection offered by the underlying channel but may require additional protection, depending on the use case.

The following table describes key-value pairs for the CSR FSIM.

| Direction | Key Name | Value | Meaning |
| --------- | -------- | ----- | ------- |
| o <-> d | `fdo.csr:active` | `bool` | Instructs the device to activate or deactivate the module |
| o <-- d | `fdo.csr:cacerts-req` | `uint` | Request to obtain CA certificates |
| o --> d | `fdo.csr:cacerts-res` | `tstr` | CA certificates |
| o <-- d | `fdo.csr:simpleenroll-req` | `tstr` | Certificate enrollment request |
| o --> d | `fdo.csr:simpleenroll-res` | `tstr` | Enrollments of clients |
| o <-- d | `fdo.csr:simplereenroll-req` | `tstr` | Request to re-enroll a client |
| o --> d | `fdo.csr:simplereenroll-res` | `tstr` | Re-enrollment response |
| o <-- d | `fdo.csr:serverkeygen-req` | `tstr` | Request for server-side key generation |
| o --> d | `fdo.csr:serverkeygen-res` | `tstr` | Certificate and private key |
| o <-- d | `fdo.csr:csrattrs-req` | `uint` | Request for CSR attributes |
| o --> d | `fdo.csr:csrattrs-res` | `tstr` | CSR attributes |
| o --> d | `fdo.csr:error` | `uint` | Error Indication |

## fdo.csr:cacerts-req and fdo.csr:cacerts-res

A device requests CA certificates by issuing the fdo.csr:cacerts-req message. The indicated value informs the owning Device Management Service in what format the CA certificates have to be returned.

A successful response is conveyed in the fdo.csr:cacerts-res message. The format mandatory-to-implement is 'application/pkcs7-mime; smime-type=certs-only' with value 281. The optional format is 'application/pkix-cert' with value 287.

The certificates returned by this request can be used to update trust anchors on the system, so that other CA-based operations (such as TLS connections) can use the updated trust anchors.  This includes, for example, the WGET FSIM.

## fdo.csr:simpleenroll-req and fdo.csr:simpleenroll-res

A device uses a Simple PKI Request, as specified in CMC (RFC 5272, Section 3.1 (i.e., a PKCS #10 Certification Request [RFC2986]), to request a certificate. The payload in the fdo.csr:simpleenroll-req message is encoded as a 'application/pkcs10' payload.
The Certification Signing Request (CSR) signature provides proof-of-possession of the client-possessed private key.

A successful response is carried in a fdo.csr:simpleenroll-res message, which carries the certificate encoded as 'application/pkix-cert'.

## fdo.csr:simplereenroll-req and fdo.csr:simplereenroll-res

A device can renew/rekey an existing certificate by submitting a re-enrollment request.

A certificate signing request employs the same format as the "simpleenroll" request (see previous section).  The request Subject field
and SubjectAltName extension MUST be identical to the corresponding fields in the certificate being renewed/rekeyed.  The
ChangeSubjectName attribute, as defined in [RFC6402], MAY be included in the CSR to request that these fields be changed in the new
certificate.

If the Subject Public Key Info in the certification signing request is the same as the current certificate, then the certificate
will be renewed.  If the public key information in the certification signing request is different than the current certificate,
then the server rekeys the certificate.

The payload in the fdo.csr:simplereenroll-req message is encoded as a 'application/pkcs10' payload.
The Certificate Signing Request (CSR) signature provides proof-of-possession of the client-possessed private key.

A successful response is carried in a fdo.csr:simplereenroll-res message, which carries the certificate encoded as 'application/pkix-cert'.

## fdo.csr:serverkeygen-req and fdo.csr:serverkeygen-res

A device requests server-side key generation by issuing a fdo.csr:serverkeygen-req to the owning Device Management Service.

The request uses the same format as the fdo.csr:simpleenroll-req and the fdo.csr:simplereenroll-req messages. The owning Device
Management Service and the certificate enrollment servers SHOULD treat the CSR as it would any enroll or re-enroll CSR, as
described in RFC 7030. The only distinction is that the public key values and signature in the CSR MUST be ignored. These are
included in the request only to allow re-use of existing libraries for generating and parsing such requests.

If the device wants to receive an private key encrypted end-to-end from the device to the CA/RA there are two technical options, namely

- to use object layer security, and
- to use communication security from the device to the owning Device Management Service and between the owning Device Management Service and the CA/RA.

This specification utilizes the latter. A future version of this specification, or another FSIM, may introduce the object layer security solution.

A successful response is returned in the fdo.csr:serverkeygen-res in form of a multipart/mixed MIME payload with boundary
set to "fdo" containing two parts: one part is the private key and the other part is the certificate.  

The certificate is an "application/pkcs7-mime" and exactly matches the certificate response to simpleenroll response message.

The format in which the private key part is returned is dependent on whether the private key is being returned with
additional encryption on top of that provided by FDO.

Since this specification does not use the object encryption, the private key data MUST be placed in an "application/pkcs8".
An "application/pkcs8" part consists of the base64-encoded DER-encoded PrivateKeyInfo with a Content-Transfer-Encoding of "base64" [RFC2045].

An example of a successful response to a fdo.csr:serverkeygen-req might look like:

    --fdo
    Content-Type: application/pkcs8
    Content-Transfer-Encoding: base64
    
    MIIEvgIB...//Base64-encoded private key//..ATp4HiBmgQ
    --fdo
    Content-Type: application/pkcs7-mime; smime-type=certs-only
    Content-Transfer-Encoding: base64
    
    MIIDRQYJK..//Base64-encoded certificate//..dDoQAxAA==
    --fdo--

## fdo.csr:csrattrs-req and fdo.csr:csrattrs-res

A device requests CSR attributes from the owning Device Management Service and consequently from the certificate enrollment servers with a fdo.csr:csrattrs-req message. The value carried in the fdo.csr:csrattrs-req message is ignored by the owning Device Management Service.

A successful response informs the device about the fields to include in a CSR. This Certificate Signing Request (CSR) attribute messages is encoded in application/csrattrs format, as defined in Section 4.5.2 of RFC 7030.

## fdo.csr:error

The following table lists error codes returned by the fdo.csr:error message.

| Error Number | Description | Sent in response to |
| ------------ | ----------- | ------------------- |
| 1 | Bad request. | fdo.csr:simpleenroll-req |
| | | fdo.csr:simplereenroll-req |
| | | fdo.csr:serverkeygen-req |
| | | fdo.csr:csrattrs-req |
| 2 | Unauthorized. | fdo.csr:simpleenroll-req |
| | | fdo.csr:simplereenroll-req |
| | | fdo.csr:serverkeygen-req |
| | | fdo.csr:csrattrs-req |
| 3 | Feature not supported. | fdo.csr:csrattrs-req |
| | | fdo.csr:serverkeygen-req |
| 4 | Rate exceeded. Try later. | fdo.csr:simpleenroll-req |
| | | fdo.csr:simplereenroll-req |
| | | fdo.csr:serverkeygen-req |
| 5 | Unsupported format. | fdo.csr:cacerts-req |

An error of type 'unauthorized' is used when the request by the client cannot be processed by the Device Management Service, Certification Authority (CA) or Registration Authority (RA) due to insufficient permissions. The error of type 'bad request' is used when the request is malformed and parsing failed.

The "Feature not supported" error code allows the FDO device to indicate that it does not support optional features defined in this specification. This enables more constrained IoT devices to implement a subset of the features in this specification without causing interoperability problems. When the invocation of a command returns a "Feature not supported" error, then the caller needs to rely on the mandatory features. This fallback might be done based on the documentation of the target device, or could be implemented as a programmable backoff and retry procedure.

## Example

The following table describes an example exchange for the CSR FSIM:

| Device sends | Owner sends | Meaning |
| ------------ | ----------- | ------- |
| `[fdo.csr:active, True]` | - | Device instructs owner to activate the CSR FSIM |
| `[fdo.csr:cacerts-req, 281]` | - | Request for CA certs |
| - | `[fdo.csr:cacerts-res, (tstr)abc...]` | CA cert response |
| `[fdo.csr:simpleenroll-req, (tstr)cde...]` | - | Certificate enrollment request |
| - | `[fdo.csr:simpleenroll-res, (tstr)efa...]` | Certificate |
| `[fdo.csr:active, False]` | - | Device instructs owner to deactivate the CSR FSIM |

## Payload Encoding Summary

This specification re-using standardized encodings for certificates, certificate signing requests, private keys and CSR attributes. This table summarizes them. For convenience, the format registered as a media type is used.

| Media Type | Reference | Notes |
| ---------- | --------- | ----- |
| application/pkcs7-mime; smime-type=certs-only | [RFC5751] | 1 |
| application/csrattrs | [RFC7030] | |
| application/pkcs10 | [RFC5967] | |
| application/pkix-cert | [RFC2585] | 2 |
| application/pkcs7-mime; smime-type=server-generated-key | [RFC5751],[RFC7030] | 1 |
| multipart/mixed | [RFC2046] | |

Notes:

1) application/pkcs7-mime media type is used to carry CMS content types, including EnvelopedData, SignedData, and CompressedData. To indicate what type of CMS data is contained, the smime-type parameter provides further help. "certs-only" refers to the CMS type SignedData and is used as a certificate management message to convey certificates and/or CRLs. The SignedData structure does not, in the degenerate case, contain signature information (see Section 2.4.2 of RFC 8551). "server-generated-key" is the parameter value for server-side key generation response.

2) application/pkix-cert contains exactly one certificate encoded in DER format.

## References

[RFC7030]  Pritikin, M., Ed., Yee, P., Ed., and D. Harkins, Ed., "Enrollment over Secure Transport", RFC 7030, DOI 10.17487/RFC7030, October 2013, <https://www.rfc-editor.org/info/rfc7030>.

[RFC2986]  Nystrom, M. and B. Kaliski, "PKCS #10: Certification Request Syntax Specification Version 1.7", RFC 2986, DOI 10.17487/RFC2986, November 2000, <https://www.rfc-editor.org/info/rfc2986>.

[RFC2046]  Freed, N. and N. Borenstein, "Multipurpose Internet Mail Extensions (MIME) Part Two: Media Types", RFC 2046, DOI 10.17487/RFC2046, November 1996,
<https://www.rfc-editor.org/info/rfc2046>.

[RFC2045]  Freed, N. and N. Borenstein, "Multipurpose Internet Mail Extensions (MIME) Part One: Format of Internet Message Bodies", RFC 2045, DOI 10.17487/RFC2045, November 1996, <https://www.rfc-editor.org/info/rfc2045>.

[RFC5751]  Ramsdell, B. and S. Turner, "Secure/Multipurpose Internet Mail Extensions (S/MIME) Version 3.2 Message Specification", RFC 5751, DOI 10.17487/RFC5751, January 2010, <https://www.rfc-editor.org/info/rfc5751>.

[RFC5967]  Turner, S., "The application/pkcs10 Media Type", RFC 5967, DOI 10.17487/RFC5967, August 2010, <https://www.rfc-editor.org/info/rfc5967>.

[RFC2585]  Housley, R. and P. Hoffman, "Internet X.509 Public Key Infrastructure Operational Protocols: FTP and HTTP", RFC 2585, DOI 10.17487/RFC2585, May 1999, <https://www.rfc-editor.org/info/rfc2585>.

[RFC6402] J. Schaad, "Certificate Management over CMS (CMC) Updates", RFC 6402, DOI 10.17487/RFC6402, November 2011, <https://www.rfc-editor.org/info/rfc6402>.
