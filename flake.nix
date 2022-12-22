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
        inherit (pkgs.stdenv) isDarwin isLinux;
        overlays = [ (import rust-overlay) ];
        pkgs = (import nixpkgs) {
          inherit system overlays;
        };

        myrust = pkgs.rust-bin.beta.latest.default.override {
          extensions = [ "rust-analyzer" ];
        };

        # configure naersk to use our rust overlay
        naersk' = pkgs.callPackage naersk {
          cargo = myrust;
          rustc = myrust;
        };

        appkit = if isDarwin then pkgs.darwin.apple_sdk.frameworks.AppKit else null;

      in
      with pkgs;
      {


        # For `nix build` & `nix run`:
        packages.default = naersk'.buildPackage {
          buildInputs =  [
            appkit
          ];
          src = ./.;
        };

        # For `nix develop`:
        devShells.default = pkgs.mkShell {
          buildInputs = [
            appkit
            myrust
          ];
        };
      }
    );
}
