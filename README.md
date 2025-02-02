# FIDO Device Onboard - Go Library

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/fido-device-onboard/go-fdo/badge)](https://scorecard.dev/viewer/?uri=github.com/fido-device-onboard/go-fdo)
[![Lint](https://github.com/fido-device-onboard/go-fdo/actions/workflows/lint.yml/badge.svg)](https://github.com/fido-device-onboard/go-fdo/actions/workflows/lint.yml)
[![Test](https://github.com/fido-device-onboard/go-fdo/actions/workflows/test.yml/badge.svg)](https://github.com/fido-device-onboard/go-fdo/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/fido-device-onboard/go-fdo/main/LICENSE)
[![Building](https://img.shields.io/badge/go-%3E%3D%201.23-blue)](#building-the-example-application)
[![Go Reference](https://pkg.go.dev/badge/github.com/fido-device-onboard/go-fdo.svg)](https://pkg.go.dev/github.com/fido-device-onboard/go-fdo)

> [!WARNING]
> This library has not yet completed interop testing with the FIDO Alliance, but will at the next opportunity.

`go-fdo` is a lightweight stdlib-only library for implementing FDO device, owner service, and device initialization server roles.

It implements [FIDO Device Onboard Specification 1.1][fdo] as well as necessary dependencies such as [CBOR][cbor] and [COSE][cose]. Implementations of dependencies are not meant to be complete implementations of their relative specifications, but are supported and any breaking changes to their APIs will be considered a breaking change to `go-fdo`.

[fdo]: https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v1.1-20220419/FIDO-Device-Onboard-PS-v1.1-20220419.html
[cbor]: https://www.rfc-editor.org/rfc/rfc8949.html
[cose]: https://datatracker.ietf.org/doc/html/rfc8152

## Building the Example Application

The example client and server application can be built with `go build` directly, but requires a Go workspace to build from the root package directory.

```console
$ go work init
$ go work use -r .
$ go run ./examples/cmd

Usage:
  fdo [global_options] [client|server] [--] [options]

Global options:
  -debug
        Run subcommand with debug enabled

Client options:
  -blob string
        File path of device credential blob (default "cred.bin")
  -cipher suite
        Name of cipher suite to use for encryption (see usage) (default "A128GCM")
  -debug
        Print HTTP contents
  -di URL
        HTTP base URL for DI server
  -di-key string
        Key for device credential [options: ec256, ec384, rsa2048, rsa3072] (default "ec384")
  -di-key-enc string
        Public key encoding to use for manufacturer key [x509,x5chain,cose] (default "x509")
  -download dir
        A dir to download files into (FSIM disabled if empty)
  -echo-commands
        Echo all commands received to stdout (FSIM disabled if false)
  -insecure-tls
        Skip TLS certificate verification
  -kex suite
        Name of cipher suite to use for key exchange (see usage) (default "ECDH384")
  -print
        Print device credential blob and stop
  -rv-only
        Perform TO1 then stop
  -tpm path
        Use a TPM at path for device credential secrets
  -upload files
        List of dirs and files to upload files from, comma-separated and/or flag provided multiple times (FSIM disabled if empty)
  -wget-dir dir
        A dir to wget files into (FSIM disabled if empty)

Server options:
  -command-date
        Use fdo.command FSIM to have device run "date +%s"
  -db string
        SQLite database file path
  -db-pass string
        SQLite database encryption-at-rest passphrase
  -debug
        Print HTTP contents
  -download file
        Use fdo.download FSIM for each file (flag may be used multiple times)
  -ext-http addr
        External address devices should connect to (default "127.0.0.1:${LISTEN_PORT}")
  -http addr
        The address to listen on (default "localhost:8080")
  -import-voucher path
        Import a PEM encoded voucher file at path
  -insecure-tls
        Listen with a self-signed TLS certificate
  -print-owner-public type
        Print owner public key of type and exit
  -resale-guid guid
        Voucher guid to extend for resale
  -resale-key path
        The path to a PEM-encoded x.509 public key for the next owner
  -reuse-cred
        Perform the Credential Reuse Protocol in TO2
  -rv-bypass
        Skip TO1
  -rv-delay seconds
        Delay TO1 by N seconds
  -to0 addr
        Rendezvous server address to register RV blobs (disables self-registration)
  -to0-guid guid
        Device guid to immediately register an RV blob (requires to0 flag)
  -upload file
        Use fdo.upload FSIM for each file (flag may be used multiple times)
  -upload-dir path
        The directory path to put file uploads (default "uploads")
  -wget url
        Use fdo.wget FSIM for each url (flag may be used multiple times)

Key types:
  - RSA2048RESTR
  - RSAPKCS
  - RSAPSS
  - SECP256R1
  - SECP384R1

Encryption suites:
  - A128GCM
  - A192GCM
  - A256GCM
  - AES-CCM-64-128-128 (not implemented)
  - AES-CCM-64-128-256 (not implemented)
  - COSEAES128CBC
  - COSEAES128CTR
  - COSEAES256CBC
  - COSEAES256CTR

Key exchange suites:
  - DHKEXid14
  - DHKEXid15
  - ASYMKEX2048
  - ASYMKEX3072
  - ECDH256
  - ECDH384
```

### Testing Device Onboard

First, start a server in a separate console.

```console
$ go run ./examples/cmd server -http 127.0.0.1:9999 -db ./test.db
[2024-09-01 00:00:00] INFO: Listening
  local: 127.0.0.1:9999
  external: 127.0.0.1:9999
```

Then DI, followed by TO1 and TO2 may be run. Passing the `-debug` flag allows message payloads to be viewed.

```console
$ go run ./examples/cmd client -di http://127.0.0.1:9999
Success
$ go run ./examples/cmd client
Success
```

Running TO1 and TO2 again will fail, because the new voucher has not been registered for rendezvous.

```console
$ go run ./examples/cmd client
[2024-09-01 00:00:00] ERROR: TO1 failed
  base URL: http://127.0.0.1:9999
  error: error received from TO1.HelloRV request: 2024-09-01 00:00:00 UTC [code=6,prevMsgType=30,id=0] not found
client error: transfer of ownership not successful
exit status 2
```

If the server had been started with the `-rv-bypass` flag, then the second onboarding attempt would have failed with not found, because unextended vouchers are not automatically allowed for re-onboarding.

```console
[2024-09-01 00:00:00] ERROR: TO2 failed
  base URL: http://127.0.0.1:9999
  error: error received from TO2.HelloDevice request: 2024-09-01 00:00:00 UTC [code=6,prevMsgType=60,id=0] error retrieving voucher for device fa667c70e50b696086bbd8e05ba2773b: not found
client error: transfer of ownership not successful
exit status 2
```

To test repeatedly without the device credential changing, run the server with the `-reuse-cred` flag to enable the [Credential Reuse Protocol][Credential Reuse Protocol].

[Credential Reuse Protocol]: https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v1.1-20220419/FIDO-Device-Onboard-PS-v1.1-20220419.html#credreuse

### Testing RV Blob Registration

First, start a server in a separate console.

```console
$ go run ./examples/cmd server -http 127.0.0.1:9999 -to0 http://127.0.0.1:9999 -db ./test.db
[2024-09-01 00:00:00] INFO: Listening
  local: 127.0.0.1:9999
  external: 127.0.0.1:9999
```

Next, initialize the device and check that TO1 fails.

```console
$ go run ./examples/cmd client -di http://127.0.0.1:9999
$ go run ./examples/cmd client -print
blobcred[
  ...
  GUID          d21d841a3f54f4e89a60ed9b9779e9e8
  ...
]
$ go run ./examples/cmd client -rv-only
[2024-09-01 00:00:00] ERROR: TO1 failed
  base URL: http://127.0.0.1:9999
  error: error received from TO1.HelloRV request: 2024-09-01 00:00:00 +0000 UTC [code=6,prevMsgType=30,id=0] not found
```

Then register an RV blob with the server.

```console
$ go run ./examples/cmd server -http 127.0.0.1:9999 -to0 http://127.0.0.1:9999 -to0-guid d21d841a3f54f4e89a60ed9b9779e9e8 -db ./test.db
[2024-09-01 00:00:00] INFO: RV blob registered
  ttl: 1193046h28m15s
```

Finally, check that TO1 now succeeds.

```console
$ go run ./examples/cmd client -rv-only
TO1 Blob: to1d[
  RV:
    - http://127.0.0.1:9999
  To0dHash:
    Algorithm: Sha256Hash
    Value: 340129067ad5839e2a5424baa3e7aa4bb984f610f29123b47b56353f47d71145
]
```

### Testing Key Exchanges

First, start a server in a separate console.

```console
$ go run ./examples/cmd server -http 127.0.0.1:9999 -db ./test.db
[2024-09-01 00:00:00] INFO: Listening
  local: 127.0.0.1:9999
  external: 127.0.0.1:9999
```

Then DI, followed by TO1 and TO2 may be run.

Because in the example the device key type and owner key type will always match and to use ASYMKEX\* key exchange the owner key must be RSA, the device key must also be RSA. To specify the device key type, use `-di-key` when running DI.

```console
$ go run ./examples/cmd client -di http://127.0.0.1:9999 -di-key rsa2048
Success
$ go run ./examples/cmd client -kex ASYMKEX2048
Success
```

### Testing Resale Protocol

First, start a server in a separate console.

```console
$ go run ./examples/cmd server -http 127.0.0.1:9999 -to0 http://127.0.0.1:9999 -db ./test.db
[2024-09-01 00:00:00] INFO: Listening
  local: 127.0.0.1:9999
  external: 127.0.0.1:9999
```

Next, initialize the device and perform transfer of ownership.

```console
$ go run ./examples/cmd client -di http://127.0.0.1:9999
$ go run ./examples/cmd client
Success
$ go run ./examples/cmd client -print
blobcred[
  ...
  GUID          d21d841a3f54f4e89a60ed9b9779e9e8
  ...
]
```

Then, using a randomly-generated SHA384 public key, perform resale:

```console
$ cat <<EOF >key.pem
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEqS9eSmpzrxw74krScl3+uOr5XU0nb3sZ
UB8rNQaXd7CACcjqlihEnJQIr3BWC6quWV8wnoghsW1zT6Ufw22yJ1twtkOphrW7
lw0a/66AlYljvN0Bq5RX924IWu8vlNz9
-----END PUBLIC KEY-----
EOF
$ go run ./examples/cmd server -resale-guid d21d841a3f54f4e89a60ed9b9779e9e8 -resale-key key.pem -db ./test.db
-----BEGIN OWNERSHIP VOUCHER-----
hRhlWOaGGGVQ18NXTN2UDTKMCY7F/ckKtYGDggxBAYIFSmlsb2NhbGhvc3SCA0MZ
H5BmZ290ZXN0gwsBWHgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATZfbKj0Hfzztvd
BlxP6xvcNLArHhn2hHIetTOJ3jK/kMJljCyD/e7kEySuNI3ZkbanWQlwQJSNpdmc
WqurNM9rF6GP+ovDKiXtJk0wIEr7LVSbuk7KzAucy/rAimFAnk6COCpYMAQyXU7V
FfmqG8K3DtkUSPB102O8vN7cmVzDpbVmtWvlGtqUS01fkQFPS4vljVtZ8YIGWDD3
/LT9iLHTHCROt1FE9zApA9JBuOftcfDhnONYyWa2vfYfZ3T/fHQ65jS8edGn0DyC
WQGfMIIBmzCCASGgAwIBAgIRALr6K7WkGYUBYitf2Tfw5tMwCgYIKoZIzj0EAwMw
EjEQMA4GA1UEAxMHVGVzdCBDQTAgFw0yNDA5MTcwMTI0NThaGA8yMDU0MDQxMzAx
MjQ1OFowGDEWMBQGA1UEAxMNZGV2aWNlLmdvLWZkbzB2MBAGByqGSM49AgEGBSuB
BAAiA2IABIKuaRfY831T//0D+qpVNznhj8iRRWUUEFQIR3h58ZKKaN+Grwrp+k5q
ov9tWvtM+/cbI+E2sD5XgwSJwHku2AkcBtGNsvohMkjq5OXXLtwLPmVi0CnAdXxS
NzNJNmofn6MzMDEwDgYDVR0PAQH/BAQDAgeAMB8GA1UdIwQYMBaAFOFx/qD3xlTs
iKpls6oIzO5tcta9MAoGCCqGSM49BAMDA2gAMGUCMCpfigiEdodr5oIB+9t93C8o
e1E99b4+/Zi316X9hCaYAsOLcXS9JvnNoJv1Pu4MfQIxAJAHV8199THTxVbTnoA0
VGkDlYAMgTNdRFl8fjINEFERjx5p9metcYhQdVWJDfWMrFkBiDCCAYQwggEKoAMC
AQICAQEwCgYIKoZIzj0EAwMwEjEQMA4GA1UEAxMHVGVzdCBDQTAgFw0yNDA5MTUx
NDI3MDhaGA8yMDU0MDkwODE0MjcwOFowEjEQMA4GA1UEAxMHVGVzdCBDQTB2MBAG
ByqGSM49AgEGBSuBBAAiA2IABJoEXAUK7ZgV87mH49gI7XnFLw1k8vFPm4lxdTUz
F8lLMJHACcTXAnsYWaFCTKnyTA7avGimBLMGxIWWQH2kL2QhDsgM5XmAWRN4jD/E
cf1SEbUFwe7KNJFpGVWGZeTPSaMyMDAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQU4XH+oPfGVOyIqmWzqgjM7m1y1r0wCgYIKoZIzj0EAwMDaAAwZQIxAJ6TF7ms
PQb3fBx7kPH87ne9kkOu5fJAK1y+KrHdRNCwy+pmzbsLexx4wjookPpBEwIwMj1b
M1wAKzERNOnxhbKe17t9MgP54sNKpDjsKM6I7JSfOCOC83KYvAyBnF3cLKnxgdKE
RKEBOCKgWOqEgjgqWDBftCgxPk1Do9rcJHZcimJMwzvKgPUP5cSb+eUMelCOM3qi
xn9DM4Bf9fCIQoqy11aCOCpYMFehu5uT7NJQEXuy569NxVYYXX8ClhTH+HK6wDPN
9/SgPFXhxbQl9i/LcJh2lOCoBkGggwsBWHgwdjAQBgcqhkjOPQIBBgUrgQQAIgNi
AASpL15KanOvHDviStJyXf646vldTSdvexlQHys1Bpd3sIAJyOqWKESclAivcFYL
qq5ZXzCeiCGxbXNPpR/DbbInW3C2Q6mGtbuXDRr/roCViWO83QGrlFf3bgha7y+U
3P1YYPSf746ATSncxVbMYy+iAZwssR14hPDyqXz9RvMfF52a6Us6sKu06jd4Yprc
i2op2Hc819qjlgzt0kCmpOs75TtIIcOr2pSMy6pB+1bCr3QLdKH4bf7y8p9Hh8Tu
s0hciw==
-----END OWNERSHIP VOUCHER-----
```

### Testing with a TPM

First, start a server in a separate console.

```console
$ go run ./examples/cmd server -http 127.0.0.1:9999 -db ./test.db
[2024-09-01 00:00:00] INFO: Listening
  local: 127.0.0.1:9999
  external: 127.0.0.1:9999
```

Then run DI, with the TPM resource manager path specified. The key type must always be explicit through the `-di-key` flag.

```console
$ go run ./examples/cmd client -di http://127.0.0.1:9999 -di-key ec384 -tpm /dev/tpmrm0
[2024-09-01 00:00:00] INFO: tpm: max input buffer size undefined, using default
  size: 1024
Success
```

Finally, run TO1/TO2.

```console
$ go run ./examples/cmd client -di-key ec384 -tpm /dev/tpmrm0
[2024-09-01 00:00:00] INFO: tpm: max input buffer size undefined, using default
  size: 1024
Success
```

The TPM simulator may be used with 3 caveats:

1. RSA3072 keys are not supported
2. OpenSSL libraries and headers must be installed
3. The executable must be built with cgo enabled

```console
$ go run ./examples/cmd client -di http://127.0.0.1:9999 -di-key rsa2048 -tpm simulator
[2024-09-01 00:00:00] INFO: tpm: max input buffer size undefined, using default
  size: 1024
Success

$ go run ./examples/cmd client -di-key rsa2048 -tpm simulator
[2024-09-01 00:00:00] INFO: tpm: max input buffer size undefined, using default
  size: 1024
Success
```

## FIPS Compliance

To build a FIPS 140-2 certifiable binary, use the [Microsoft Go][Microsoft Go] toolchain and be sure to deploy with a FIPS-compliant version of OpenSSL 3.0.

As an example, the following multi-stage `Dockerfile` will build the included example FDO application with FIPS-compliant crypto.

```Dockerfile
FROM mcr.microsoft.com/oss/go/microsoft/golang:1.23-fips-cbl-mariner2.0 AS build
WORKDIR /build
COPY . .
RUN go work; go work use -r . && \
    go build -tags=requirefips -o fdo ./examples/cmd

FROM gcr.io/distroless/cc-debian12
COPY --from=build /build/fdo .
# COPY in a FIPS-compliant OpenSSL 3.0 library!
ENTRYPOINT [ "./fdo" ]
```

Note that for FIPS certification, the NIST 800-108 key derivation function in `internal/nistkdf/kdf.go` would still need to be inspected.

[Microsoft Go]: https://github.com/microsoft/go/blob/microsoft/main/eng/doc/fips/README.md
