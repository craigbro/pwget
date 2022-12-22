{
  description = "A simple cli utility for accessing PWSafe3 databases";

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
    rust-overlay.url = "github:oxalica/rust-overlay";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, flake-utils, naersk, nixpkgs, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = (import nixpkgs) {
          inherit system overlays;
        };

        naersk' = pkgs.callPackage naersk {
        };

      in
      with pkgs;
      {

        # For `nix build` & `nix run`:
        defaultPackage = naersk'.buildPackage {
          buildInputs =  [ darwin.apple_sdk.frameworks.AppKit ];
          src = ./.;
        };

        # For `nix develop`:
        devShell = pkgs.mkShell {
          buildInputs = [
            darwin.apple_sdk.frameworks.AppKit
            rust-bin.stable.latest.default
          ];
        };
      }
    );
}
