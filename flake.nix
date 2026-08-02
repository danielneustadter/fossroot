{
  # nix run github:danielneustadter/fossroot -- status
  # nix build github:danielneustadter/fossroot
  #
  # Uses cargoLock.lockFile, so no vendored-hash bookkeeping is needed on
  # version bumps. Tests run in CI, not in the sandboxed Nix build.
  description = "Fossroot — open-source manager for DoD PKI CA certificate trust stores";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      eachSystem = f: nixpkgs.lib.genAttrs systems (system: f system);
    in
    {
      packages = eachSystem (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          inherit (pkgs) lib stdenv;
        in
        rec {
          fossroot = pkgs.rustPlatform.buildRustPackage {
            pname = "fossroot";
            version = "0.1.0";
            src = self;
            cargoLock.lockFile = ./Cargo.lock;
            cargoBuildFlags = [ "-p" "fossroot" ];
            doCheck = false;

            nativeBuildInputs = [ pkgs.installShellFiles ];

            postInstall =
              lib.optionalString stdenv.hostPlatform.isLinux ''
                install -Dm644 packaging/linux/com.fossroot.Fossroot.desktop \
                  -t $out/share/applications
                install -Dm644 packaging/linux/com.fossroot.Fossroot.metainfo.xml \
                  -t $out/share/metainfo
                install -Dm644 assets/icon/fossroot.svg \
                  $out/share/icons/hicolor/scalable/apps/com.fossroot.Fossroot.svg
                for s in 16 24 32 48 64 128 256 512; do
                  install -Dm644 assets/icon/fossroot-$s.png \
                    $out/share/icons/hicolor/''${s}x''${s}/apps/com.fossroot.Fossroot.png
                done
              ''
              + lib.optionalString (stdenv.buildPlatform.canExecute stdenv.hostPlatform) ''
                installShellCompletion --cmd fossroot \
                  --bash <($out/bin/fossroot completions bash) \
                  --zsh <($out/bin/fossroot completions zsh) \
                  --fish <($out/bin/fossroot completions fish)
                $out/bin/fossroot man --out man-pages
                installManPage man-pages/*.1
              '';

            meta = {
              description = "Open-source manager for DoD PKI CA certificate trust stores";
              homepage = "https://github.com/danielneustadter/fossroot";
              license = with lib.licenses; [ mit asl20 ];
              mainProgram = "fossroot";
            };
          };
          default = fossroot;
        });

      apps = eachSystem (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/fossroot";
        };
      });
    };
}
