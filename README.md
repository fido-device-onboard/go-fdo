# FIDO Device Onboard - Go Library

`go-fdo` is a lightweight stdlib-only library for implementing FDO device, owner service, and device initialization server roles.

It implements [FIDO Device Onboard Specification 1.1][fdo] as well as necessary dependencies such as [CBOR][cbor] and [COSE][cose]. Implementations of dependencies are not meant to be complete implementations of their relative specifications, but are supported and any breaking changes to their APIs will be considered a breaking change to `go-fdo`.

[fdo]: https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v1.1-20220419/FIDO-Device-Onboard-PS-v1.1-20220419.html
[cbor]: https://www.rfc-editor.org/rfc/rfc8949.html
[cose]: https://datatracker.ietf.org/doc/html/rfc8152

## Building the Example Application

The example client and server application can be built with `go build` directly, but requires a Go workspace to build from the root package directory.

```sh
$ go work init
$ go work use -r .
$ go build -o fdo ./examples/cmd
$ ./fdo

Usage:
  fdo [client|server] [--] [options]

Client options:
  -blob string
        File path of device credential blob (default "cred.bin")
  -debug
        Print HTTP contents
  -di URL
        HTTP base URL for DI server
  -download dir
        A dir to download files into (FSIM disabled if empty)
  -print
        Print device credential blob and stop
  -rv-only
        Perform TO1 then stop
  -upload files
        List of dirs and files to upload files from, comma-separated and/or flag provided multiple times (FSIM disabled if empty)

Server options:
  -db string
        SQLite database file path (defaults to in-memory)
  -debug
        Print HTTP contents
  -download file
        Use fdo.download FSIM for each file (flag may be used multiple times)
  -ext-http addr
        External address devices should connect to (default "127.0.0.1:${LISTEN_PORT}")
  -http addr
        The address to listen on (default "localhost:8080")
  -rv-bypass
        Skip TO1
  -upload file
        Use fdo.upload FSIM for each file (flag may be used multiple times)
  -upload-dir path
        The directory path to put file uploads (default "uploads")
```

## Scaling Considerations

If you are considering horizontal scaling, you're probably "holding it wrong." Device onboarding should be measured in devices per day, not per second. A rendezvous (TO1) server is likely the only piece that will ever need more than verical scaling, due to its centralized nature. (This is contingent on FDO becoming more popular, so it is a "good" problem to have.)

That said, a particularly memory usage-heavy FSIM could necessitate horizontal scaling, so here's what's needed:

TO2 state is mostly handled with a JWT-like Authorization token. Like JWTs, the HMAC secret must be shared between all instances.

The remaining state to be shared is Owner Key and Voucher persistence, To1d (RV) blobs, and FSIM state. These few methods should be implemented with a distributed database backend. See `server_state.go`.

Unfortunately, FSIM state is not yet setup to be shared and may never be. A reasonable workaround to this is to base server selection in the reverse proxy by using a hash of the Authorization token (or even creating true client-server affinity for the whole protocol). A hash of the Authorization token works, because when performing a message loop 68->69 for service info exchange, the Authorization token will not change. FSIM state is only relevant for this loop. All other TO2 state is embedded in the Authorization token.
