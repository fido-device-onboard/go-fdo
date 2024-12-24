# Rendzvous Service on Cloudflare Workers

## Prerequisites

Download TinyGo (>= 0.35.0) from your OS package manager and Wrangler from npm.

## Deploy

Create a Cloudflare Worker with the name "rv" and start a new repo with the configuration in `wrangler.toml`.

Create a D1 database instance with name "rv" and update `wrangler.toml` with its UUID.

Execute the included schema.sql setup.

```console
wrangler d1 execute rv --remote --file=./schema.sql
```

Then deploy the application.

```console
wrangler deploy
```

## Usage

Add users by email address.

```console
wrangler d1 execute rv --remote --command 'INSERT INTO trusted_emails (email) VALUES ("user@example.com")'
```

Add owner keys, connected to user accounts for auditability.

```console
wrangler d1 execute rv --remote --command "INSERT INTO trusted_owners (email, pkix) VALUES ('user@example.com', UNHEX('$OWNER_KEY'))"
```

### Example

Get the owner key from the example application to add to RV server.

```bash
OWNER_KEY=$(go run ./examples/cmd server -db db.test -print-owner-public SECP384R1 | head -n -1 | tail -n +2 | tr -d '\n' | base64 -d | xxd -p -c 0)
```

Initialize device credentials.

```console
$ go run ./examples/cmd server -db db.test -http 127.0.0.1:9999 -to0 https://rv.${SUBDOMAIN}.workers.dev
[2024-11-01 00:00:00] INFO: Listening
  local: 127.0.0.1:9999
  external: 127.0.0.1:9999
```

```console
$ go run ./examples/cmd client -di http://127.0.0.1:9999
$ go run ./examples/cmd client -print
blobcred[
  ...
  GUID          d21d841a3f54f4e89a60ed9b9779e9e8
  ...
]
$ go run ./examples/cmd client -rv-only
```

Register RV blob with RV server.

```console
$ go run ./examples/cmd server -db db.test -http 127.0.0.1:9999 -to0 https://rv.${SUBDOMAIN}.workers.dev -to0-guid d21d841a3f54f4e89a60ed9b9779e9e8
[2024-11-01 00:00:00] INFO: RV blob registered
  ttl: 168h0m0s
```

Transfer ownership using the Cloudflare RV service and local owner service.

```console
$ go run ./examples/cmd client
Success
```
