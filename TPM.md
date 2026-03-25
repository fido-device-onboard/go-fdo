# TPM Integration

Build tags select the TPM transport at compile time. No runtime flags needed.

## Build Modes

| Tag | Transport | CGO | Use case |
|-----|-----------|-----|----------|
| *(none, Linux)* | `/dev/tpmrm0` | No | Production hardware |
| `tpmsim` | Software simulator | Yes | Development/CI |
| `tinygo` | Unsupported | No | Embedded/WASM |

```bash
# Production (real TPM)
go build -tags=tpm -o fdo-client ./examples/cmd

# Development (simulator, needs CGO)
CGO_ENABLED=1 go build -tags=tpmsim -o fdo-client ./examples/cmd
```

## 1. Device Initialization (DI) — credentials land in TPM

Build with `-tags=tpm` or `-tags=tpmsim`. The DI command is the same as a
non-TPM build — no extra flags:

```bash
# Start server
fdo-client server -http 127.0.0.1:9999 -db test.db

# DI — build tag already selected TPM backend
fdo-client client -di http://127.0.0.1:9999 -di-key ec384
```

After DI, the TPM holds: DAK key (persistent handle `0x81020002`), HMAC key
(`0x81020003`), and NV indices `0x01D10000`–`0x01D10005` for credential data.

## 2. Test provisioning — plop fake credentials into TPM

The spec compliance test suite provisions a TPM end-to-end without a network:

```bash
# Run against simulator (provisions TPM NV indices + persistent keys)
CGO_ENABLED=1 FDO_TPM=sim go test -v -tags=spec_compliance_test \
  -run TestSpecCompliance/Phase6 -count=1 ./tpm/

# Run against real hardware
sudo FDO_TPM=/dev/tpmrm0 go test -v -tags=spec_compliance_test \
  -run TestSpecCompliance/Phase6 -count=1 ./tpm/
```

Phase 6 writes all NV indices and persistent keys that a real DI would create.

## 3. Inspect TPM credentials — no flags, just works

```bash
# Show everything stored in TPM NV indices
fdo-client client -tpm-show

# Export DAK public key as PEM
fdo-client client -tpm-export-dak > dak.pem

# Prove DAK possession (sign a challenge)
fdo-client client -tpm-prove
fdo-client client -tpm-prove -tpm-challenge "my-nonce"
```

These commands call `tpm.DefaultOpen()` which is selected by build tag.
Override with `-tpm /dev/tpmrm0` or `-tpm simulator` if needed.

## 4. Onboard (TO1/TO2) — uses stored credentials

```bash
# Onboard — same command as a blob build; build tag selects TPM
fdo-client client
```

The HMAC and device key are regenerated deterministically from the TPM seed on
each run. The credential file (`cred.bin`) stores only the `DeviceCredential`
metadata (GUID, RV info, etc.); secrets never leave the TPM.

## Credential Store API for downstream apps

The `cred` module (`go-fdo/cred`) provides a unified `cred.Store` interface
that abstracts credential storage behind build tags. **This is the recommended
approach for new applications.** Application code is identical regardless of
backend — only the build command changes.

```go
import "github.com/fido-device-onboard/go-fdo/cred"

// Open credential store — build tag selects backend.
//   go build              → blob (software keys in CBOR file)
//   go build -tags=tpm    → hardware TPM
//   go build -tags=tpmsim → TPM simulator
store, err := cred.Open("cred.bin")
if err != nil {
    log.Fatal(err)
}
defer store.Close()

// Device Initialization — generate HMAC + device key
h256, h384, key, err := store.NewDI(protocol.Secp384r1KeyType)
dc, err := fdo.DI(ctx, transport, mfgInfo, fdo.DIConfig{
    HmacSha256: h256, HmacSha384: h384, Key: key,
})
store.Save(*dc)

// Transfer of Ownership — load stored credential
dc, h256, h384, key, err := store.Load()
newDC, err := fdo.TO2(ctx, transport, to1d, fdo.TO2Config{
    Cred: *dc, HmacSha256: h256, HmacSha384: h384, Key: key,
    // ...
})
if newDC != nil {
    store.Save(*newDC)
}
```

To use `cred.Store`, add the `go-fdo/cred` module to your `go.mod`:

```bash
go get github.com/fido-device-onboard/go-fdo/cred
```

### Existing apps — no changes required

Apps that import `go-fdo/blob` or `go-fdo/tpm` directly continue to work.
`cred.Store` is additive — it does not change or remove any existing API.
Migrate when convenient by replacing direct backend imports with `cred.Open()`.

## Low-level TPM API

For TPM-specific operations (NV inspection, DAK proof) that go beyond
credential storage, use the `tpm` package directly:

```go
import "github.com/fido-device-onboard/go-fdo/tpm"

// Open TPM — build tag selects transport automatically.
t, err := tpm.DefaultOpen()
if err != nil {
    log.Fatal(err)
}
defer t.Close()

// Read all NV-stored credentials
info, err := tpm.ReadNVCredentials(t)
// info.Active, info.GUID, info.DeviceInfo, info.HasDAK, ...

// Export DAK public key
pubKey, err := tpm.ReadDAKPublicKey(t)

// Prove DAK possession (sign challenge with policy-session auth)
proof, err := tpm.ProveDAKPossession(t, []byte("challenge"))
// proof.PublicKey, proof.Challenge, proof.Signature
```

## 5. End-to-End Integration Tests

The `test_tpm_examples.sh` script runs the full DI → TO1/TO2 flow with all
client credential storage going through the TPM. The server runs in standard
(non-TPM) mode.

```bash
# Hardware TPM (requires /dev/tpmrm0 read/write access)
./test_tpm_examples.sh all
make test-tpm

# Software TPM via swtpm (no hardware needed; install: sudo apt install swtpm)
TPM_MODE=sim ./test_tpm_examples.sh all
make test-tpm-sim
```

| Test | Description |
|------|-------------|
| `basic` | DI + TO1/TO2 with TPM NV credential storage |
| `basic-reuse` | DI + multiple onboards with credential reuse |
| `fdo200` | DI + TO1/TO2 with FDO 2.0 protocol |
| `all` | Run all TPM tests (default) |

The swtpm mode uses a Unix domain socket for cross-process TPM state
persistence. The test script manages the swtpm lifecycle (start, restart per
test, stop) automatically.

## NV Index Map

| Index | Handle | Contents | Auth |
|-------|--------|----------|------|
| DCActive | `0x01D10000` | 1 byte flag | OwnerRead |
| DCTPM | `0x01D10001` | GUID + DeviceInfo | AuthRead |
| DCOV | `0x01D10002` | Ownership Voucher | OwnerRead |
| HMAC_US | `0x01D10003` | HMAC Unique String | AuthRead |
| DeviceKey_US | `0x01D10004` | Device Key Unique String | AuthRead |
| FDO_Cert | `0x01D10005` | X.509 certificate | OwnerRead |
| DAK | `0x81020002` | ECC signing key (persistent) | PolicyNV+PolicySecret |
| HMAC Key | `0x81020003` | HMAC key (persistent) | — |

Per "Securing FDO Credentials in the TPM v1.0" specification.

## 6. Cross-Language TPM Verification

The Go FDO CLI can inspect TPM credentials written by any spec-compliant
implementation -- including the [Rust FDO client](../fido-device-onboard-rs).
This serves as a practical proof of interoperability: if Go can parse
credentials provisioned by Rust, both implementations agree on NV index
layout, CBOR encoding, and key formats.

### Go TPM inspection commands

| Command | What it reads | Output |
|---------|---------------|--------|
| `-tpm-show` | All 6 NV indices + 2 persistent handles | GUID, DeviceInfo, version, key type, RV URLs, DAK curve/coords, HMAC key presence |
| `-tpm-export-dak` | DAK persistent handle (`0x81020002`) | PEM-encoded public key |
| `-tpm-prove` | DAK + DeviceKey_US (for policy auth) | Challenge, signature, self-verification result |
| `-tpm-clear` | All FDO NV indices + persistent handles | Removes everything (factory reset) |

### Build the Go TPM inspector

```bash
cd go-fdo/examples

# Hardware TPM (pure Go, no CGO)
go build -tags=tpm -o fdo ./cmd

# Software TPM / swtpm (also pure Go for socket-based swtpm)
go build -tags=tpm -o fdo ./cmd

# In-process simulator (requires CGO)
CGO_ENABLED=1 go build -tags=tpmsim -o fdo ./cmd
```

### Verification workflow

After another implementation (e.g. Rust) provisions a device via DI:

```bash
# Read all credentials from TPM
./fdo client -tpm-show

# Export the DAK public key for external signature verification
./fdo client -tpm-export-dak > dak.pem

# Prove the DAK private key is present (sign + self-verify)
./fdo client -tpm-prove

# Prove with a specific challenge string
./fdo client -tpm-prove -tpm-challenge "interop-test-2026"
```

If `-tpm-show` displays valid GUID, DeviceInfo, RV URLs, and key type, and
`-tpm-prove` succeeds, the provisioning implementation is spec-compliant.

### Using an alternate TPM device

```bash
# Explicit hardware TPM path
./fdo client -tpm /dev/tpm0 -tpm-show

# swtpm Unix domain socket
./fdo client -tpm /tmp/swtpm.sock -tpm-show

# In-process simulator (tpmsim build only)
./fdo client -tpm simulator -tpm-show
```

## CGO Requirements

CGO is needed **only** for the software simulator (Microsoft's C reference TPM).
All real-TPM paths are pure Go.

| Build | CGO | Why |
|-------|-----|-----|
| `go build ./...` | No | Production binary, pure Go |
| `go build -tags=tpmsim ./...` | Yes | Simulator wraps C code |
| `go test ./tpm/...` | Yes | Standard tests use simulator |
| `go test -tags=spec_compliance_test ./tpm/` | Depends | `FDO_TPM=sim` needs CGO; real TPM does not |
