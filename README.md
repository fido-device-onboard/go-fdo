# FIDO Device Onboard - Go Library

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
$ go build -o fdo ./examples/cmd
$ ./fdo

Usage:
  fdo [global_options] [client|server] [--] [options]

Global options:
  -debug
        Run subcommand with debug enabled

Client options:
  -blob string
        File path of device credential blob (default "cred.bin")
  -debug
        Print HTTP contents
  -di URL
        HTTP base URL for DI server
  -download dir
        A dir to download files into (FSIM disabled if empty)
  -insecure-tls
        Skip TLS certificate verification
  -print
        Print device credential blob and stop
  -rv-only
        Perform TO1 then stop
  -upload files
        List of dirs and files to upload files from, comma-separated and/or flag provided multiple times (FSIM disabled if empty)

Server options:
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
  -insecure-tls
        Listen with a self-signed TLS certificate
  -rv-bypass
        Skip TO1
  -to0 addr
        Rendezvous server address to register RV blobs (disables self-registration)
  -to0-guid guid
        Device guid to immediately register an RV blob (requires to0 flag)
  -upload file
        Use fdo.upload FSIM for each file (flag may be used multiple times)
  -upload-dir path
        The directory path to put file uploads (default "uploads")
```

### Testing RV Blob Registration

First, start a server in a separate console.

```console
$ ./fdo server -http 127.0.0.1:9999 -to0 http://127.0.0.1:9999 -db ./test.db
```

Next, initialize the device and check that TO1 fails.

```console
$ ./fdo client -di http://127.0.0.1:9999
$ ./fdo client -print
blobcred[
  ...
  GUID          d21d841a3f54f4e89a60ed9b9779e9e8
  ...
]
$ ./fdo client -rv-only
TO1 failed for "http://127.0.0.1:9999": error received from TO1.HelloRV request: 2024-08-23 09:59:20 -0400 EDT [code=6,prevMsgType=30,id=0] not found
```

Then register an RV blob with the server.

```console
$ ./fdo server -http 127.0.0.1:9999 -to0 http://127.0.0.1:9999 -to0-guid d21d841a3f54f4e89a60ed9b9779e9e8 -db ./test.db
2024/08/23 10:03:06 to0 refresh in 1193046h28m15s
```

Finally, check that TO1 now succeeds.

```console
$ ./fdo client -rv-only
TO1 Blob: to1d[
  RV:
    - http://127.0.0.1:9999
  To0dHash:
    Algorithm: Sha256Hash
    Value: 340129067ad5839e2a5424baa3e7aa4bb984f610f29123b47b56353f47d71145
]
```
