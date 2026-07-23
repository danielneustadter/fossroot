//! Linux trust-store backend.
//!
//! Linux has no per-user OS trust store that applications uniformly respect, and
//! no separate "root" vs "intermediate" system stores — there is a single set of
//! system trust anchors, updated by a distro tool. Fossroot therefore:
//!
//! - writes each managed certificate as its own PEM file, named by SHA-1
//!   thumbprint, into the distro's "local anchors" source directory;
//! - runs the distro's update command so the change takes effect;
//! - classifies a listed anchor as belonging to the ROOT or CA logical store by
//!   whether it is self-issued, so the shared [`crate::diff`] logic still works.
//!
//! Both [`Location`] values map to the same system anchors (writes require root);
//! the location is accepted for API symmetry but does not change the target.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::certs::{hex, to_pem, CertInfo};
use crate::store::{InstalledCert, StoreKind, SystemStore, TrustStore};
use crate::{Error, Result};

pub struct LinuxStore;

/// A distro's trust-anchor layout: where Fossroot drops PEM files, and the
/// command that rebuilds the consolidated trust store afterwards.
struct Layout {
    anchor_dir: PathBuf,
    update_cmd: &'static str,
    update_args: &'static [&'static str],
}

fn detect_layout() -> Result<Layout> {
    // RHEL / Fedora / SUSE family.
    let rhel = Path::new("/etc/pki/ca-trust/source/anchors");
    if rhel.is_dir() {
        return Ok(Layout {
            anchor_dir: rhel.to_path_buf(),
            update_cmd: "update-ca-trust",
            update_args: &["extract"],
        });
    }
    // Debian / Ubuntu family.
    let debian = Path::new("/usr/local/share/ca-certificates");
    if debian.is_dir() || Path::new("/etc/ssl/certs").is_dir() {
        return Ok(Layout {
            anchor_dir: debian.to_path_buf(),
            update_cmd: "update-ca-certificates",
            update_args: &[],
        });
    }
    Err(Error::Store(
        "unsupported Linux trust layout: neither /etc/pki/ca-trust/source/anchors \
         nor /usr/local/share/ca-certificates was found"
            .into(),
    ))
}

/// Files Fossroot manages are named so we can find and remove exactly ours.
fn anchor_filename(sha1: &[u8; 20]) -> String {
    format!("fossroot-{}.crt", hex(sha1))
}

fn is_fossroot_anchor(name: &str) -> bool {
    name.starts_with("fossroot-") && name.ends_with(".crt")
}

fn run_update(layout: &Layout) -> Result<()> {
    let out = Command::new(layout.update_cmd)
        .args(layout.update_args)
        .output()
        .map_err(|e| Error::Store(format!("failed to run {}: {e}", layout.update_cmd)))?;
    if !out.status.success() {
        return Err(Error::Store(format!(
            "{} failed: {}",
            layout.update_cmd,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

impl TrustStore for LinuxStore {
    fn list(&self, store: SystemStore) -> Result<Vec<InstalledCert>> {
        let layout = detect_layout()?;
        let mut out = Vec::new();
        let dir = match std::fs::read_dir(&layout.anchor_dir) {
            Ok(d) => d,
            Err(_) => return Ok(out), // dir may not exist yet — nothing managed
        };
        for entry in dir.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !is_fossroot_anchor(&name) {
                continue;
            }
            let Ok(bytes) = std::fs::read(entry.path()) else {
                continue;
            };
            let der = pem_to_der(&bytes).unwrap_or(bytes);
            if let Ok(info) = CertInfo::from_der(&der) {
                // Map ROOT ↔ self-issued, CA ↔ issued-by-another, so the diff
                // logic sees each cert in exactly the store it expects.
                let matches = match store.kind {
                    StoreKind::Root => info.is_self_issued,
                    StoreKind::Ca => !info.is_self_issued,
                };
                if matches {
                    out.push(InstalledCert {
                        subject: info.subject,
                        sha1: info.sha1,
                        not_after: info.not_after,
                    });
                }
            }
        }
        Ok(out)
    }

    fn add(&self, _store: SystemStore, der: &[u8]) -> Result<()> {
        let layout = detect_layout()?;
        let info = CertInfo::from_der(der)?;
        let path = layout.anchor_dir.join(anchor_filename(&info.sha1));
        std::fs::write(&path, to_pem(der))
            .map_err(|e| Error::Store(format!("writing {}: {e}", path.display())))?;
        run_update(&layout)
    }

    fn remove_by_sha1(&self, _store: SystemStore, sha1: &[u8; 20]) -> Result<bool> {
        let layout = detect_layout()?;
        let path = layout.anchor_dir.join(anchor_filename(sha1));
        if !path.exists() {
            return Ok(false);
        }
        std::fs::remove_file(&path)
            .map_err(|e| Error::Store(format!("removing {}: {e}", path.display())))?;
        run_update(&layout)?;
        Ok(true)
    }

    fn probe_write(&self, _store: SystemStore) -> Result<()> {
        let layout = detect_layout()?;
        std::fs::create_dir_all(&layout.anchor_dir).ok();
        let probe = layout.anchor_dir.join(".fossroot-write-probe");
        match std::fs::write(&probe, b"") {
            Ok(()) => {
                let _ = std::fs::remove_file(&probe);
                Ok(())
            }
            Err(e) => Err(Error::Store(format!(
                "cannot write to {} ({e}). The Linux trust store is system-wide; \
                 re-run with sudo.",
                layout.anchor_dir.display()
            ))),
        }
    }
}

fn pem_to_der(bytes: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(bytes).ok()?;
    if !text.contains("-----BEGIN") {
        return None;
    }
    let b64: String = text
        .lines()
        .filter(|l| !l.starts_with("-----") && !l.trim().is_empty())
        .collect();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()
}
