# FSIM Specifications

FSIM specifications are **not** maintained in this repository. The
authoritative source is the `fdo-sim` FSIM repository:

<https://github.com/bkgoodman/fdo-sim> — directory `fsim-repository/`

Copies of several of these documents previously lived at the root of this
repo. They were incidental check-ins that drifted out of sync with the
originals, and have been removed to leave a single source of truth. Update the
spec in `fdo-sim`, not here.

## Index

| Specification | Implemented by |
| ------------- | -------------- |
| [chunking-strategy.md](https://github.com/bkgoodman/fdo-sim/blob/main/fsim-repository/chunking-strategy.md) | `fsim/chunking/` |
| [fdo.bmo.md](https://github.com/bkgoodman/fdo-sim/blob/main/fsim-repository/fdo.bmo.md) | `fsim/bmo_*.go` |
| [fdo.credentials.md](https://github.com/bkgoodman/fdo-sim/blob/main/fsim-repository/fdo.credentials.md) | `fsim/credentials_*.go`, `fsim/credential_*.go` |
| [fdo.payload.md](https://github.com/bkgoodman/fdo-sim/blob/main/fsim-repository/fdo.payload.md) | `fsim/payload_*.go` |
| [fdo.sysconfig.md](https://github.com/bkgoodman/fdo-sim/blob/main/fsim-repository/fdo.sysconfig.md) | `fsim/sysconfig_*.go` |
| [fdo.wifi-setup.md](https://github.com/bkgoodman/fdo-sim/blob/main/fsim-repository/fdo.wifi-setup.md) | `fsim/wifi_*.go` |
| [fdo-single-sided-wifi-strategy.md](https://github.com/bkgoodman/fdo-sim/blob/main/fsim-repository/fdo-single-sided-wifi-strategy.md) | `fsim/wifi_*.go` |
| [fdo.command.md](https://github.com/bkgoodman/fdo-sim/blob/main/fsim-repository/fdo.command.md) | `fsim/command_*.go` |
| [fdo.download.md](https://github.com/bkgoodman/fdo-sim/blob/main/fsim-repository/fdo.download.md) | `fsim/download_*.go` |
| [fdo.upload.md](https://github.com/bkgoodman/fdo-sim/blob/main/fsim-repository/fdo.upload.md) | `fsim/upload_*.go` |
| [fdo.wget.md](https://github.com/bkgoodman/fdo-sim/blob/main/fsim-repository/fdo.wget.md) | `fsim/wget_*.go` |

Source comments throughout `fsim/` reference these documents by filename
(e.g. "per fdo.payload.md"). Those refer to the `fdo-sim` originals.

## Legacy / Superseded

| Specification | Status |
| ------------- | ------ |
| [fdo.csr.md](https://github.com/bkgoodman/fdo-sim/blob/main/fsim-repository/fdo.csr.md) | **Superseded by `fdo.credentials.md`**, which states that it "incorporates and extends concepts from *fdo.csr* — certificate enrollment and server-generated keys". An upstream FIDO Alliance document (2023), not maintained here. |

The `fsim/csr_*.go` implementation of `fdo.csr` remains in the tree but is
**not wired into the example CLI and has no integration test**. New work
needing certificate enrollment should use `fdo.credentials` (`x509_cert`
credential type), which covers the same ground with the shared chunking
pattern. See `fsim/CSR_IMPLEMENTATION.md` for the historical notes.

## Documentation That Does Live Here

These are implementation notes for this codebase, not specifications, and are
correctly maintained in this repo:

| Document | Covers |
| -------- | ------ |
| [fsims.md](fsims.md) | Which FSIM to use for which job, and why |
| [fsim/chunking/README.md](fsim/chunking/README.md) | Go API for the chunking package, including reverse-direction transfers |
| [fsim/CHUNKING_PATTERN.md](fsim/CHUNKING_PATTERN.md) | Unified vs chunked handler patterns |
| [fsim/FSIM-DEVELOPMENT-GUIDE.md](fsim/FSIM-DEVELOPMENT-GUIDE.md) | Writing a new FSIM; `Yield`/`Receive` and `blockPeer` semantics |
| [fsim/CSR_IMPLEMENTATION.md](fsim/CSR_IMPLEMENTATION.md) | `fdo.csr` implementation notes |
| [CLI_COMMANDS.md](CLI_COMMANDS.md) | CLI flags for exercising each FSIM |
| [DESIGN-PROPOSALS.md](DESIGN-PROPOSALS.md) | Proposals not yet upstreamed to `fdo-sim` |

Note that `attestedpayload.md`, `delegate.md`, `VOUCHER_TRANSFER.md` and
`TPM.md` describe mechanisms specific to this implementation rather than FSIMs,
and are also maintained here.
