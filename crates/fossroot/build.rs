//! Build metadata for the fossroot binary.
//!
//! - Injects the short git hash and target triple so `--version` can report
//!   exactly what was built (falls back to "unknown" in tarball builds
//!   without a .git directory, e.g. distro packaging).
//! - On Windows, embeds the application icon and VERSIONINFO resource.

fn main() {
    let hash = std::process::Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=FOSSROOT_GIT_HASH={hash}");
    println!(
        "cargo:rustc-env=FOSSROOT_TARGET={}",
        std::env::var("TARGET").unwrap_or_default()
    );
    println!("cargo:rerun-if-changed=../../.git/HEAD");

    embed_windows_resources();
}

#[cfg(windows)]
fn embed_windows_resources() {
    let mut res = winresource::WindowsResource::new();
    res.set_icon("../../assets/icon/fossroot.ico");
    res.set("ProductName", "Fossroot");
    res.set("FileDescription", "Fossroot — DoD PKI trust store manager");
    res.set("LegalCopyright", "MIT OR Apache-2.0");
    res.compile().expect("embedding Windows resources");
}

#[cfg(not(windows))]
fn embed_windows_resources() {}
