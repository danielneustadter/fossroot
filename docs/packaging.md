# Packaging & installation

How Fossroot ships on each platform, what's automated, and what remains to
publish. The `packaging/` tree holds all format definitions; CI
(`.github/workflows/package.yml`) builds and smoke-tests the Linux artifacts
on every push, and `release.yml` attaches them to tagged releases.

A note on trust, because it matters more for this tool than most: every
package format below ships the **same single binary** built from this repo —
no format adds patches, and none of them bundle certificates. On Linux the
trust-store write is system-wide (`update-ca-certificates` /
`update-ca-trust`), so `install`/`remove` need `sudo` regardless of how
Fossroot was installed; `status` and `export` never do.

## AppImage (any distro) — recommended

Download `Fossroot-<version>-x86_64.AppImage` from
[Releases](https://github.com/danielneustadter/fossroot/releases), verify the
checksum against `SHA256SUMS.linux`, then:

```bash
chmod +x Fossroot-*.AppImage
./Fossroot-*.AppImage status          # read-only report
sudo ./Fossroot-*.AppImage install    # system trust store needs root
```

Built by `packaging/appimage/build-appimage.sh` on ubuntu-22.04 (old glibc
floor). The AppImage bundles only the Fossroot binary plus desktop
integration; it uses the system's X11/OpenGL like any desktop program. No
FUSE? Run with `--appimage-extract-and-run`.

## Debian / Ubuntu (.deb)

```bash
sudo apt install ./fossroot_<version>_amd64.deb
```

From `cargo deb`; config lives in `crates/fossroot/Cargo.toml`
(`[package.metadata.deb]`). Installs the binary, desktop entry, icons,
AppStream metainfo, bash/zsh/fish completions, and man pages
(`man fossroot`). Depends on `ca-certificates` for `update-ca-certificates`.

## Fedora / RHEL (.rpm)

```bash
sudo dnf install ./fossroot-<version>-1.x86_64.rpm
```

From `cargo generate-rpm`; config in the same Cargo.toml. Same contents as
the deb. Depends on `ca-certificates` for `update-ca-trust`.

## Arch Linux (AUR)

`packaging/aur/` contains a buildable `fossroot-git` PKGBUILD (builds from
`main`):

```bash
git clone https://github.com/danielneustadter/fossroot
cd fossroot/packaging/aur && makepkg -si
```

**To publish:** push PKGBUILD + .SRCINFO to `ssh://aur@aur.archlinux.org/fossroot-git.git`
(regenerate `.SRCINFO` with `makepkg --printsrcinfo > .SRCINFO` first). A
fixed-version `fossroot` package follows the first release tag that contains
the `packaging/` tree.

## Nix

The repo root is a flake:

```bash
nix run github:danielneustadter/fossroot -- status
nix profile install github:danielneustadter/fossroot
```

Uses `cargoLock.lockFile` (no vendor-hash bookkeeping). CI runs
`nix flake check` + `nix build`. **To publish:** upstream to nixpkgs as
`pkgs/by-name/fo/fossroot` once a release tag contains `packaging/`.

## Snap — scaffold

`packaging/snap/snapcraft.yaml`. Blocked on process, not code: writing the
system trust store requires **classic confinement**, and classic snaps need a
manual review by the Snap Store team before publication. Build locally with
`snapcraft` if you have LXD.

## Flatpak — scaffold, and a poor fit

`packaging/flatpak/com.fossroot.Fossroot.yml`. Flatpak's sandbox cannot
write the host trust store — Fossroot's entire job — so a flatpak'd build
would be limited to read-only `status`/`export`. The manifest exists so the
door is open if a sandbox-compatible trust path (e.g. a p11-kit portal) ever
materializes; until then, prefer the AppImage.

## Gentoo — scaffold

`packaging/gentoo/app-crypt/fossroot/fossroot-9999.ebuild`, written to
Gentoo conventions (cargo + git-r3 eclasses, live ebuild) but **untested on
real Gentoo hardware**. A versioned ebuild with a `CRATES` list (via
`pycargoebuild`) accompanies the next release. Publishing target: the GURU
overlay.

## Windows / macOS

Windows: signed-exe distribution and winget are on the roadmap; today,
download `fossroot.exe` from Releases (SHA-256 alongside). macOS: Homebrew
tap planned after code-signing/notarization.

## Maintainer cheat-sheet

| Task | Command |
|---|---|
| Rebuild all Linux artifacts locally (on Linux) | `cargo build --release -p fossroot && bash packaging/appimage/build-appimage.sh && cargo deb -p fossroot --no-build && cargo generate-rpm -p crates/fossroot` |
| Regenerate completions/man pages | `fossroot completions <shell>` / `fossroot man --out DIR` (also run by CI into `target/gen/`) |
| Regenerate icons | see `assets/icon/README.md` |
| Validate desktop/metainfo | `desktop-file-validate` + `appstreamcli validate` (run in CI) |
| Cut a release | push a `v*` tag — `release.yml` attaches exe, AppImage, deb, rpm + checksums |
