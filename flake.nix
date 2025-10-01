{
  description = "Flake for building and testing with Nix";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.05";
    nixpkgs-unstable.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    gomod2nix = {
      url = "github:nix-community/gomod2nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
    };
  };

  outputs = {
    nixpkgs,
    nixpkgs-unstable,
    gomod2nix,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      pkgs-unstable = nixpkgs-unstable.legacyPackages.${system};

      buildGoApplication = {ldflags ? [], ...} @ attrs:
        gomod2nix.legacyPackages.${system}.buildGoApplication (
          {
            src = ./.;
            pwd = ./.;
            modules = ./nix/gomod2nix.toml;
            subPackages = ["examples/cmd"];
            postConfigure = ''
              go work init
              go work use .
              go work use examples
              go work use fsim
              go work use sqlite
              go work use tpm
              chmod 755 vendor
              cp ${./nix/modules.txt} vendor/modules.txt
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

        example-tpmsim = buildGoApplication {
          name = "fdo-tpmsim";
          CGO_ENABLED = 1;
          buildInputs = with pkgs; [
            openssl
          ];
        };
      };

      devShells = {
        default = pkgs.mkShell {
          packages = with pkgs; [
            pkgs-unstable.go_1_25
            gotools
            gomod2nix.packages.${system}.default
          ];
          nativeBuildInputs = with pkgs; [
            openssl
          ];
        };

        tinygo = pkgs.mkShell {
          packages = with pkgs; [
            (pkgs-unstable.tinygo.overrideAttrs (old: {
              patches =
                old.patches
                ++ [
                  ./nix/patches/tinygo-rand.diff
                  ./nix/patches/tinygo-testing-context.diff
                ];
            }))
            gotools
            gomod2nix.packages.${system}.default
          ];
          nativeBuildInputs = with pkgs; [
            openssl
          ];
        };
      };
    });
}
