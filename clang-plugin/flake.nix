{
  description = "clang-plugin: search_malloc / search_um / checker built against pinned Clang/LLVM 18";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f (import nixpkgs { inherit system; }));
    in {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.cmake
            pkgs.ninja
            pkgs.pkg-config
            pkgs.llvmPackages_18.clang
            pkgs.llvmPackages_18.libclang.dev
            pkgs.llvmPackages_18.llvm.dev
            pkgs.jsoncpp.dev
          ];

          shellHook = ''
            export CC=clang
            export CXX=clang++
            echo "clang-plugin dev shell — Clang/LLVM $(clang --version | head -n1 | awk '{print $NF}')"
            echo "build:  mkdir -p build && cd build && cmake .. -G Ninja && ninja search_malloc search_um checker"
            echo "smoke:  ./tests/run_plugin_smoke.sh"
          '';
        };
      });
    };
}
