{
  description = "Flake for building and testing with Nix";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    gomod2nix = {
      # Fork:
      # - Fixes a panic when symlinking existing directories containing files
      # - Trims package list from `gomod2nix.toml` when patched version used for `gomod2nix generate`
      url = "github:ben-krieger/gomod2nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
  };

  outputs = {
    nixpkgs,
    gomod2nix,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      go = pkgs.go_1_25;
      pkgs = nixpkgs.legacyPackages.${system};

      tinygo_patched = pkgs.tinygo.overrideAttrs (old: {
        nativeBuildInputs = old.nativeBuildInputs ++ [go];
        postInstall = ''
          ln -s ${pkgs.writeShellScript "go" ''
            if [ "$1" = "build" ]; then
              tinygo "$@"
            else
              ${go}/bin/go "$@"
            fi
          ''} $out/bin/go
        '';
        patches =
          old.patches
          ++ [
            ./nix/patches/tinygo-rand.diff
            ./nix/patches/tinygo-testing-context.diff
          ];
        doCheck = false;
      });

      buildGoApplication = {ldflags ? [], ...} @ attrs:
        gomod2nix.legacyPackages.${system}.buildGoApplication (
          {
            go = attrs.go or go;
            src = ./.;
            modules = ./nix/gomod2nix.toml;
            subPackages = ["examples/cmd"];
            postConfigure = ''
              # Copy known good modules.txt into vendor, because gomod2nix
              # doesn't do this for us
              chmod 755 vendor
              cp ${./nix/modules.txt} vendor/modules.txt

              # Setup workspace
              go work init
              go work use .
              go work use examples
              go work use fsim
              go work use sqlite
              go work use tpm
            '';
            postInstall = ''
              mv $out/bin/cmd $out/bin/${attrs.name}
            '';
            doCheck = false;
          }
          // attrs
          // {
            ldflags =
              [
                "-s"
                "-w"
              ]
              ++ ldflags;
          }
        );
    in {
      packages = rec {
        default = example;

        example = buildGoApplication {
          name = "fdo";
          CGO_ENABLED = 0;
          ldflags = [
            "-extldflags -static"
          ];
        };

        example-tinygo = buildGoApplication {
          name = "fdo";
          go = tinygo_patched;
          buildInputs = with pkgs; [
            openssl
          ];
        };

        example-tpmsim = buildGoApplication {
          name = "fdo-tpmsim";
          CGO_ENABLED = 1;
          buildInputs = with pkgs; [
            openssl
          ];
        };
      };

      devShells = rec {
        default = go;

        go = pkgs.mkShell {
          packages = with pkgs; [
            go_1_25
            gotools
            gomod2nix.packages.${system}.default
            golangci-lint
          ];
          nativeBuildInputs = with pkgs; [
            openssl
          ];
        };

        tinygo = pkgs.mkShell {
          packages = with pkgs; [
            tinygo_patched
            go_1_25
            gotools
            gomod2nix.packages.${system}.default
            golangci-lint
          ];
          nativeBuildInputs = with pkgs; [
            openssl
          ];
        };
      };
    });
}
