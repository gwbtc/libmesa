{
  description = "libmesa: standalone Mesa protocol + Groundwire identity";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            rust-analyzer
            python3
          ];
        };

        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "libmesa";
          version = "0.0.1";
          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = path: type:
              pkgs.lib.cleanSourceFilter path type
              && !(builtins.elem (baseNameOf path) [ "target" "__pycache__" ])
              && !(pkgs.lib.hasSuffix ".pyc" path);
          };
          cargoLock.lockFile = ./Cargo.lock;
          nativeCheckInputs = [ pkgs.python3 ];
          postCheck = ''
            python3 tools/v2-vectors.py --check
            python3 tools/noun-vectors.py --check
            $CC -std=c11 -Wall -Wextra -Werror \
              -I crates/mesa-ffi/include crates/mesa-ffi/tests/smoke.c \
              target/${pkgs.stdenv.hostPlatform.rust.rustcTarget}/release/libmesa_ffi.a \
              -lpthread -ldl -lm ${pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isDarwin "-liconv -framework Security -framework CoreFoundation"} \
              -o mesa-ffi-smoke
            ./mesa-ffi-smoke
          '';
          installPhase = ''
            runHook preInstall
            mkdir -p $out/lib $out/include
            cp target/${pkgs.stdenv.hostPlatform.rust.rustcTarget}/release/libmesa_ffi.a $out/lib/
            cp crates/mesa-ffi/include/mesa.h $out/include/
            runHook postInstall
          '';
        };
      });
}
