#!/usr/bin/env bash
# Build Fossroot-<version>-<arch>.AppImage from a release binary.
#
# Usage:  packaging/appimage/build-appimage.sh [path-to-fossroot-binary]
#   ARCH=x86_64|aarch64   target arch label (default x86_64)
#   OUT_DIR=dir           output directory (default <repo>/dist)
#   APPIMAGETOOL=path     use an existing appimagetool instead of downloading
#
# The AppImage bundles only the fossroot binary plus desktop integration
# (desktop entry, icons, AppStream metainfo). Fossroot links against the
# system's X11/OpenGL stack like any desktop binary; everything else is
# statically linked by the Rust toolchain. Build on the oldest supported
# distro (CI uses ubuntu-22.04) so the glibc requirement stays low.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
arch="${ARCH:-x86_64}"
appid="com.fossroot.Fossroot"

bin="${1:-$repo/target/release/fossroot}"
if [[ ! -x "$bin" ]]; then
  echo "error: fossroot binary not found at $bin (build with: cargo build --release)" >&2
  exit 1
fi

# Version from the workspace manifest — no need to execute the binary, which
# may be for a foreign arch.
version="$(grep -m1 '^version' "$repo/Cargo.toml" | cut -d'"' -f2)"

out="${OUT_DIR:-$repo/dist}"
appdir="$out/AppDir"
rm -rf "$appdir"
mkdir -p "$out" "$appdir/usr/bin" "$appdir/usr/share/applications" \
  "$appdir/usr/share/metainfo" "$appdir/usr/share/icons/hicolor/scalable/apps"

cp "$bin" "$appdir/usr/bin/fossroot"
cp "$repo/packaging/linux/$appid.desktop" "$appdir/usr/share/applications/"
cp "$repo/packaging/linux/$appid.metainfo.xml" "$appdir/usr/share/metainfo/"
cp "$repo/assets/icon/fossroot.svg" "$appdir/usr/share/icons/hicolor/scalable/apps/$appid.svg"
for s in 16 24 32 48 64 128 256 512; do
  mkdir -p "$appdir/usr/share/icons/hicolor/${s}x${s}/apps"
  cp "$repo/assets/icon/fossroot-$s.png" "$appdir/usr/share/icons/hicolor/${s}x${s}/apps/$appid.png"
done

# AppDir top-level conventions: AppRun entry point, desktop file, icon.
ln -sf usr/bin/fossroot "$appdir/AppRun"
cp "$repo/packaging/linux/$appid.desktop" "$appdir/"
cp "$repo/assets/icon/fossroot-256.png" "$appdir/$appid.png"
ln -sf "$appid.png" "$appdir/.DirIcon"

# appimagetool: use $APPIMAGETOOL, then PATH, then download the pinned
# 1.9.1 release from the official AppImage project.
tool="${APPIMAGETOOL:-}"
if [[ -z "$tool" ]] && command -v appimagetool >/dev/null 2>&1; then
  tool="$(command -v appimagetool)"
fi
if [[ -z "$tool" ]]; then
  tool="$out/appimagetool-$arch.AppImage"
  if [[ ! -x "$tool" ]]; then
    curl -fsSL -o "$tool" \
      "https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-$arch.AppImage"
    chmod +x "$tool"
  fi
fi

# --appimage-extract-and-run avoids a FUSE requirement on CI runners.
target="$out/Fossroot-$version-$arch.AppImage"
ARCH="$arch" "$tool" --appimage-extract-and-run --no-appstream "$appdir" "$target"

sha256sum "$target" | tee "$target.sha256"
echo "built: $target"
