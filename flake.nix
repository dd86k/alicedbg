{
  description = "Alice Debugger Project";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    let
      mkAlicedbg =
        { buildType
        , compiler
        , config
        }: { buildDubPackage, pkg-config, openssl, ... }:
        buildDubPackage rec {
          pname = "alicedbg-${buildType}-${config}-${compiler.pname}";
          version = "0.4.1";
          src = ./.;
          dubLock = ./dub-lock.json;
          dubBuildType = buildType;
          dubFlags = [
            "--config=${config}"
          ];
          inherit compiler;
          buildInputs = [
            pkg-config
            openssl
          ];
          installPhase =
            let
              mvArtifacts = {
                "debugger" = "install -Dm755 alicedbg -t $out/bin";
                "dumper" = "install -Dm755 alicedump -t $out/bin";
                "simple" = "install -Dm755 simple -t $out/bin";
                "library" = ''
                  mkdir -p $out/lib
                  for lib in *.a *.lib; do
                    if [ -f "$lib" ]; then
                      install -Dm644 "$lib" "$out/lib"
                    fi
                  done
                '';
                "shared" = ''
                  mkdir -p $out/lib
                  for lib in *.so *.dll; do
                    if [ -f "$lib" ]; then
                      install -Dm644 "$lib" "$out/lib"
                    fi
                  done
                '';
              }.${config};
            in
            ''
              runHook preInstall
              ${if buildType != "docs"
                then mvArtifacts
                else ''
                  mkdir -p $out
                  if [ -d docs ]; then
                    mv docs $out/
                  fi
                ''
              }
              runHook postInstall
            '';
        };
    in
    # for a list of avaliable systems
      # see https://github.com/numtide/flake-utils/blob/main/allSystems.nix
    flake-utils.lib.eachSystem [
      "x86_64-windows"
      "x86_64-linux"
      "x86_64-freebsd13"
      "i686-linux"
      "i686-freebsd13"
      "i686-windows"
      "armv7l-linux"
      "armv7a-linux"
      "aarch64-linux"
    ]
      (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [
              self.overlays.default
            ];
          };

        in
        {
          packages = {
            default = pkgs.alicedbg.alicedbg-release-debugger-ldc;
          } // pkgs.alicedbg;

          devShells.default = pkgs.mkShell {
            buildInputs = with pkgs;
              [
                nil
                nixpkgs-fmt
                dub-to-nix
                dub
                dmd
                ldc
                gdc
              ];
          };

          checks = builtins.mapAttrs
            (_: p: p.overrideAttrs (oldAttrs: {
              doCheck = true;
            }))
            self.packages.${system};
        }
      ) // {

      overlays.default = final: prev:
        let
          compilers = [ final.ldc final.dmd final.gdc ];
          buildTypes = [
            "debug"
            "debugv"
            "release"
            "release-nobounds"
            "docs"
            #"ddox"
          ];
          configs = [
            "debugger"
            "dumper"
            "simple"
            "library"
            "shared"
          ];
          combinations = builtins.concatMap
            (compiler:
              builtins.concatMap
                (buildType:
                  builtins.map
                    (config: {
                      inherit compiler buildType config;
                    })
                    configs
                )
                buildTypes
            )
            compilers;
          builds = builtins.map
            (args:
              final.callPackage (mkAlicedbg args) { })
            combinations;
          namedBuilds = builtins.listToAttrs (builtins.map
            (x: {
              name = x.pname;
              value = x;
            })
            builds);
        in
        {
          alicedbg = namedBuilds;
        };

    };
}
