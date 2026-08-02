# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

# Scaffold: written to Gentoo conventions but not yet tested on a real
# Gentoo box or submitted to GURU. Live ebuild; a versioned ebuild with a
# CRATES list (pycargoebuild) will accompany the first release that
# includes the packaging/ tree.

EAPI=8

CRATES=""

inherit bash-completion-r1 cargo desktop git-r3 xdg

DESCRIPTION="Open-source manager for DoD PKI CA certificate trust stores"
HOMEPAGE="https://github.com/danielneustadter/fossroot"
EGIT_REPO_URI="https://github.com/danielneustadter/fossroot.git"

LICENSE="|| ( MIT Apache-2.0 )"
# Crate licenses (live ebuild: refreshed when the CRATES list lands).
LICENSE+=" Apache-2.0 BSD ISC MIT Unicode-DFS-2016"
SLOT="0"
KEYWORDS=""

RDEPEND="app-misc/ca-certificates"
BDEPEND=">=virtual/rust-1.75"

# GUI binary links no X11 directly (winit dlopens at runtime).
QA_FLAGS_IGNORED="usr/bin/fossroot"

src_unpack() {
	git-r3_src_unpack
	cargo_live_src_unpack
}

src_compile() {
	cargo_src_compile -p fossroot

	local bin="$(cargo_target_dir)/fossroot"
	"${bin}" completions bash >fossroot.bash || die
	"${bin}" completions zsh >_fossroot || die
	"${bin}" completions fish >fossroot.fish || die
	"${bin}" man --out man-pages || die
}

src_install() {
	dobin "$(cargo_target_dir)/fossroot"

	domenu packaging/linux/com.fossroot.Fossroot.desktop
	insinto /usr/share/metainfo
	doins packaging/linux/com.fossroot.Fossroot.metainfo.xml

	newicon -s scalable assets/icon/fossroot.svg com.fossroot.Fossroot.svg
	local s
	for s in 16 24 32 48 64 128 256; do
		newicon -s "${s}" "assets/icon/fossroot-${s}.png" com.fossroot.Fossroot.png
	done

	newbashcomp fossroot.bash fossroot
	insinto /usr/share/zsh/site-functions
	doins _fossroot
	insinto /usr/share/fish/vendor_completions.d
	doins fossroot.fish
	doman man-pages/*.1

	einstalldocs
}
