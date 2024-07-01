{
  # Note, a lot of this is boilerplate i just lifted from another project of
  # mine.
  # TODO: Refactor this.
  description = "Dipper, a pure rust DPI system";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    flake-utils,
    crane,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [rust-overlay.overlays.default];
      };
      inherit (pkgs) lib;
      commonPkgs = [
        pkgs.openssl
        pkgs.pkg-config
        pkgs.protobuf
        pkgs.protolint
        pkgs.grcov
        pkgs.rustc.llvmPackages.llvm
        pkgs.llvmPackages.bintools
        pkgs.gcc
        pkgs.libpcap
        pkgs.tcpdump
        pkgs.rust-bin.stable.latest.complete
      ];

      # We have protobuf files we want to include. To do this we need to apply a filter
      # nix a functional language after all!
      protoFilter = path: _type: null != builtins.match ".*proto$" path;
      protoOrCargo = path: type: (protoFilter path type) || (craneLib.filterCargoSources path type);
      craneLib = crane.lib.${system};
      dipperSrc = lib.cleanSourceWith {
        src = craneLib.path ./.;
        filter = protoOrCargo;
      };
      dipper = craneLib.buildPackage {
        src = dipperSrc;
        nativeBuildInputs = [pkgs.protobuf];
        buildInputs = [
          commonPkgs
        ];
        PROTOC = "${pkgs.protobuf}/bin/protoc";
        doCheck = false;
        cargoTestCommand = "";
      };

      shellPkgs = [
        pkgs.rust-analyzer-unwrapped
        pkgs.gpsd
        pkgs.cargo-cross
        pkgs.rustup
        pkgs.cargo2junit
        pkgs.mosquitto
        pkgs.poetry
        pkgs.nodePackages.npm
        pkgs.nodejs
      ];

      # shared ShellHook Elements.
      sharedHook = ''
        export PROTOBUF_LOCATION=${pkgs.protobuf}
        export PROTOC_INCLUDE=$PROTOBUF_LOCATION/include
        export PROTOC=$PROTOBUF_LOCATION/bin/protoc
        export LLVM_TOOL_PATH=${pkgs.rustc.llvmPackages.llvm}/bin
        export LD_LIBRARY_PATH=${pkgs.stdenv.cc.cc.lib}/lib/
        export RUST_LOG="info"
        export REPORT=true
      '';
    in
      with pkgs; {
        packages.default = dipper;

        apps.default = flake-utils.lib.mkApp {
          drv = dipper;
        };

        devShells.default = mkShell {
          buildInputs = [
            commonPkgs
            shellPkgs
          ];
          shellHook = sharedHook;
        };
      });
}
