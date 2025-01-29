# Nix

A flake is provided for developers building on NixOS. The flake and nix-command experimental features must be enabled.

## Building the Example Application

```sh
# Build the example as a static binary
$ nix build .
$ ldd result/bin/fdo
        not a dynamic executable

# Build the example with the TPM Simulator (requires dynamic linking)
$ nix build '.#example-tpmsim'
$ ldd result/bin/fdo-tpmsim
        linux-vdso.so.1 (0x00007efd93b59000)
        libresolv.so.2 => /nix/store/nqb2ns2d1lahnd5ncwmn6k84qfd7vx2k-glibc-2.40-36/lib/libresolv.so.2 (0x00007efd93b42000)
        libpthread.so.0 => /nix/store/nqb2ns2d1lahnd5ncwmn6k84qfd7vx2k-glibc-2.40-36/lib/libpthread.so.0 (0x00007efd93b3d000)
        libcrypto.so.3 => /nix/store/zs44kdd3k01schy32fa916pa17gr7y68-openssl-3.3.2/lib/libcrypto.so.3 (0x00007efd93400000)
        libc.so.6 => /nix/store/nqb2ns2d1lahnd5ncwmn6k84qfd7vx2k-glibc-2.40-36/lib/libc.so.6 (0x00007efd93207000)
        libdl.so.2 => /nix/store/nqb2ns2d1lahnd5ncwmn6k84qfd7vx2k-glibc-2.40-36/lib/libdl.so.2 (0x00007efd93b36000)
        /nix/store/nqb2ns2d1lahnd5ncwmn6k84qfd7vx2k-glibc-2.40-36/lib/ld-linux-x86-64.so.2 => /nix/store/nqb2ns2d1lahnd5ncwmn6k84qfd7vx2k-glibc-2.40-36/lib64/ld-linux-x86-64.so.2 (0x00007efd93b5b000)

# Run the example (with TPM simulator enabled) directly
$ nix run '.#example-tpmsim'

Usage:
  fdo [global_options] [client|server] [--] [options]
...
```

## Updating dependencies

After updates are made to `go.mod`, both `gomod2nix.toml` and `modules.txt` need to be updated. Until they are updated, Nix users will see the following error:

```sh
$ nix build .#example-tpmsim
error: builder for '/nix/store/kz2zlwjhgv2xp24y6rbjhbc5x60hb2in-fdo-tpmsim.drv' failed with exit code 1;
       last 18 log lines:
       > Running phase: unpackPhase
       > unpacking source archive /nix/store/p1aml70salsbqq42xn7isgjbrks8zmx9-hisfqn6s2isiqd8h9bmn6phaay35hri8-source
       > source root is hisfqn6s2isiqd8h9bmn6phaay35hri8-source
       > Running phase: patchPhase
       > Running phase: updateAutotoolsGnuConfigScriptsPhase
       > Running phase: configurePhase
       > Running phase: buildPhase
       > Building subPackage ./examples/cmd
       > go: inconsistent vendoring in /build/hisfqn6s2isiqd8h9bmn6phaay35hri8-source:
       >      github.com/fido-device-onboard/go-fdo@v0.0.0-20250129140218-bb17959de676: is explicitly required in go.mod, but not marked as explicit in vendor/modules.txt
       >   github.com/fido-device-onboard/go-fdo/fsim@v0.0.0-20250129140218-bb17959de676: is explicitly required in go.mod, but not marked as explicit in vendor/modules.txt
       >      github.com/fido-device-onboard/go-fdo/sqlite@v0.0.0-20250129140218-bb17959de676: is explicitly required in go.mod, but not marked as explicit in vendor/modules.txt
       >    github.com/fido-device-onboard/go-fdo/tpm@v0.0.0-20250129140218-bb17959de676: is explicitly required in go.mod, but not marked as explicit in vendor/modules.txt
       >       golang.org/x/term@v0.28.0: is explicitly required in go.mod, but not marked as explicit in vendor/modules.txt
       >
       >         To ignore the vendor directory, use -mod=readonly or -mod=mod.
       >         To sync the vendor directory, run:
       >             go work vendor
       For full logs, run 'nix log /nix/store/kz2zlwjhgv2xp24y6rbjhbc5x60hb2in-fdo-tpmsim.drv'.
```

To update `modules.txt`, generate a new one with `go work vendor` from the root directory of the repo. Copy `vendor/modules.txt` to `nix/modules.txt`.

To update `gomod2nix.toml`, enter a dev shell with `nix develop` and run `gomod2nix`. Exit the dev shell and copy `gomod2nix.toml` to `nix/gomod2nix.toml`.
