//! Fetching and unpacking DISA certificate bundle zips.

use std::io::{Cursor, Read};

use sha2::{Digest, Sha256};

use crate::certs::{hex, parse_p7b, CertInfo};
use crate::verify::{self, Manifest, VerifyReport};
use crate::{Error, Result};

/// DISA's stable distribution URL — always serves the latest DoD-only bundle.
pub const DOD_BUNDLE_URL: &str =
    "https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip";

/// A fetched-and-verified certificate bundle.
#[derive(Debug, Clone)]
pub struct Bundle {
    /// e.g. "5.14"
    pub version: String,
    /// SHA-256 of the zip archive as downloaded (hex). Empty for bare p7b input.
    pub zip_sha256: String,
    pub certs: Vec<CertInfo>,
    pub verify: VerifyReport,
    /// Where this bundle came from (URL or file path).
    pub source: String,
}

impl Bundle {
    /// Download the latest DoD bundle from DISA and verify it. Fails closed on
    /// any verification error.
    pub fn fetch() -> Result<Bundle> {
        let resp = ureq::get(DOD_BUNDLE_URL)
            .timeout(std::time::Duration::from_secs(60))
            .call()
            .map_err(|e| Error::Network(e.to_string()))?;
        let mut raw = Vec::new();
        resp.into_reader()
            .take(64 * 1024 * 1024)
            .read_to_end(&mut raw)?;
        Self::from_zip_bytes(&raw, DOD_BUNDLE_URL)
    }

    /// Load a bundle from a local file: either the official zip or a bare .p7b.
    pub fn from_file(path: &std::path::Path) -> Result<Bundle> {
        let raw = std::fs::read(path)?;
        let source = path.display().to_string();
        if raw.starts_with(b"PK") {
            Self::from_zip_bytes(&raw, &source)
        } else {
            Self::from_p7b_bytes(&raw, &source)
        }
    }

    /// Parse + verify the official zip layout (…_DoD.der.p7b + CMS .sha256 manifest).
    pub fn from_zip_bytes(raw: &[u8], source: &str) -> Result<Bundle> {
        let zip_sha256 = hex(&Sha256::digest(raw));
        let mut zip = zip::ZipArchive::new(Cursor::new(raw)).map_err(|e| Error::Zip(e.to_string()))?;

        let mut p7b_name = None;
        let mut manifest_name = None;
        for i in 0..zip.len() {
            let name = zip
                .by_index(i)
                .map_err(|e| Error::Zip(e.to_string()))?
                .name()
                .to_string();
            let base = name.rsplit('/').next().unwrap_or(&name).to_string();
            // The main bundle: "Certificates_PKCS7_v5_14_DoD.der.p7b" (not per-root files).
            if base.ends_with(".der.p7b") && !base.contains("Root_CA") {
                p7b_name = Some(name.clone());
            }
            if base.ends_with(".sha256") {
                manifest_name = Some(name.clone());
            }
        }
        let p7b_name = p7b_name.ok_or_else(|| Error::MissingFile("*_DoD.der.p7b".into()))?;
        let manifest_name = manifest_name.ok_or_else(|| Error::MissingFile("*.sha256".into()))?;

        let read_entry = |zip: &mut zip::ZipArchive<Cursor<&[u8]>>, name: &str| -> Result<Vec<u8>> {
            let mut buf = Vec::new();
            zip.by_name(name)
                .map_err(|e| Error::Zip(e.to_string()))?
                .read_to_end(&mut buf)?;
            Ok(buf)
        };
        let p7b_bytes = read_entry(&mut zip, &p7b_name)?;
        let manifest_bytes = read_entry(&mut zip, &manifest_name)?;

        let certs = parse_p7b(&p7b_bytes)?;

        // Verify the CMS-signed manifest, then the p7b's checksum against it.
        let manifest: Manifest = verify::verify_manifest(&manifest_bytes, &certs)?;
        let p7b_base = p7b_name.rsplit('/').next().unwrap_or(&p7b_name);
        let expected = manifest
            .checksums
            .iter()
            .find(|(name, _)| name == p7b_base)
            .map(|(_, h)| h.clone())
            .ok_or_else(|| Error::Verify(format!("manifest has no checksum for {p7b_base}")))?;
        let actual = hex(&Sha256::digest(&p7b_bytes));
        if expected != actual {
            return Err(Error::Verify(format!(
                "checksum mismatch for {p7b_base}: manifest {expected}, actual {actual}"
            )));
        }

        let anchored = verify::verify_chains(&certs)?;
        Ok(Bundle {
            version: parse_version(&p7b_name).unwrap_or_else(|| "unknown".into()),
            zip_sha256,
            certs,
            verify: VerifyReport {
                anchored_roots: anchored,
                chained_ok: 0,
                manifest_signed: true,
                manifest_signer: Some(manifest.signer),
            }
            .finalize_counts(),
            source: source.to_string(),
        }
        .count_chained())
    }

    /// Parse + verify a bare .p7b (no signed manifest available — chains only).
    pub fn from_p7b_bytes(raw: &[u8], source: &str) -> Result<Bundle> {
        let certs = parse_p7b(raw)?;
        let anchored = verify::verify_chains(&certs)?;
        Ok(Bundle {
            version: parse_version(source).unwrap_or_else(|| "unknown".into()),
            zip_sha256: String::new(),
            certs,
            verify: VerifyReport {
                anchored_roots: anchored,
                chained_ok: 0,
                manifest_signed: false,
                manifest_signer: None,
            },
            source: source.to_string(),
        }
        .count_chained())
    }

    fn count_chained(mut self) -> Bundle {
        self.verify.chained_ok = self.certs.len();
        self
    }
}

impl VerifyReport {
    fn finalize_counts(self) -> Self {
        self
    }
}

/// "…PKCS7_v5_14_DoD…" → "5.14"
fn parse_version(name: &str) -> Option<String> {
    let idx = name.find("_v")?;
    let rest = &name[idx + 2..];
    let end = rest.find("_DoD").or_else(|| rest.find('.'))?;
    let ver = &rest[..end];
    if ver.is_empty() || !ver.chars().all(|c| c.is_ascii_digit() || c == '_') {
        return None;
    }
    Some(ver.replace('_', "."))
}

#[cfg(test)]
mod tests {
    use super::parse_version;

    #[test]
    fn version_from_names() {
        assert_eq!(
            parse_version("Certificates_PKCS7_v5_14_DoD.der.p7b").as_deref(),
            Some("5.14")
        );
        assert_eq!(
            parse_version("dir/Certificates_PKCS7_v5_14_DoD.der.p7b").as_deref(),
            Some("5.14")
        );
        assert_eq!(parse_version("random.p7b"), None);
    }
}
