//! Fetching and unpacking DISA certificate bundle zips.

use std::io::{Cursor, Read};

use sha2::{Digest, Sha256};

use crate::certs::{hex, parse_p7b, CertInfo};
use crate::verify::{self, Manifest, VerifyReport};
use crate::{Error, Result};

/// DISA's stable distribution URL for the DoD-only bundle. Retained as a public
/// constant for callers that want the default group; see [`Group`] for the rest.
pub const DOD_BUNDLE_URL: &str = Group::Dod.url_const();

/// A DISA certificate-bundle group. Each is published at its own stable URL on
/// dl.dod.cyber.mil and always serves the latest version of that group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Group {
    /// DoD PKI — the certificates home users need for CAC-enabled DoW sites.
    Dod,
    /// External Certification Authorities (DoD-approved commercial issuers).
    Eca,
    /// JITC test PKI — for interoperability testing, not production trust.
    Jitc,
    /// Web Content Filtering (WCF) break-and-inspect PKI.
    Wcf,
}

impl Group {
    pub const ALL: [Group; 4] = [Group::Dod, Group::Eca, Group::Jitc, Group::Wcf];

    /// The archive basename DISA uses for this group's stable download.
    const fn slug(self) -> &'static str {
        match self {
            Group::Dod => "DoD",
            Group::Eca => "ECA",
            Group::Jitc => "JITC",
            Group::Wcf => "WCF",
        }
    }

    /// Short human name.
    pub const fn name(self) -> &'static str {
        match self {
            Group::Dod => "DoD PKI",
            Group::Eca => "ECA PKI",
            Group::Jitc => "JITC (test) PKI",
            Group::Wcf => "WCF PKI",
        }
    }

    /// Lowercase token accepted on the command line.
    pub const fn token(self) -> &'static str {
        match self {
            Group::Dod => "dod",
            Group::Eca => "eca",
            Group::Jitc => "jitc",
            Group::Wcf => "wcf",
        }
    }

    pub fn from_token(s: &str) -> Option<Group> {
        Group::ALL
            .into_iter()
            .find(|g| g.token() == s.to_lowercase())
    }

    /// JITC is a *test* PKI — installing it into a production trust store is
    /// almost never what a home user wants, so it is called out explicitly.
    pub const fn is_test_pki(self) -> bool {
        matches!(self, Group::Jitc)
    }

    const fn url_const(self) -> &'static str {
        match self {
            Group::Dod => "https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip",
            Group::Eca => "https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_ECA.zip",
            Group::Jitc => "https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_JITC.zip",
            Group::Wcf => "https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_WCF.zip",
        }
    }

    pub fn url(self) -> &'static str {
        self.url_const()
    }
}

/// A fetched-and-verified certificate bundle.
#[derive(Debug, Clone)]
pub struct Bundle {
    pub group: Group,
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
    /// Download and verify the DoD bundle. Convenience wrapper over [`fetch_group`].
    pub fn fetch() -> Result<Bundle> {
        Self::fetch_group(Group::Dod)
    }

    /// Download the latest bundle for `group` from DISA and verify it. Fails
    /// closed on any verification error.
    pub fn fetch_group(group: Group) -> Result<Bundle> {
        let url = group.url();
        let resp = ureq::get(url)
            .timeout(std::time::Duration::from_secs(60))
            .call()
            .map_err(|e| Error::Network(e.to_string()))?;
        let mut raw = Vec::new();
        resp.into_reader()
            .take(64 * 1024 * 1024)
            .read_to_end(&mut raw)?;
        Self::from_zip_bytes_group(&raw, url, group)
    }

    /// Load a bundle from a local file: either the official zip or a bare .p7b.
    /// The group is inferred from the archive contents.
    pub fn from_file(path: &std::path::Path) -> Result<Bundle> {
        let raw = std::fs::read(path)?;
        let source = path.display().to_string();
        if raw.starts_with(b"PK") {
            Self::from_zip_bytes(&raw, &source)
        } else {
            Self::from_p7b_bytes(&raw, &source)
        }
    }

    /// Parse + verify an official zip, inferring the group from its filenames.
    pub fn from_zip_bytes(raw: &[u8], source: &str) -> Result<Bundle> {
        let group = infer_group(raw).unwrap_or(Group::Dod);
        Self::from_zip_bytes_group(raw, source, group)
    }

    /// Parse + verify the official zip layout (main `.p7b` + CMS `.sha256`
    /// manifest) for a known `group`.
    ///
    /// Trust flow: the CMS manifest is verified to a pinned DoD root (DISA signs
    /// every group's manifest with a DoD PKE credential), the main certificate
    /// file's SHA-256 is checked against that signed manifest, and finally every
    /// certificate is verified to chain to a self-issued root inside the (now
    /// manifest-vouched) bundle.
    pub fn from_zip_bytes_group(raw: &[u8], source: &str, group: Group) -> Result<Bundle> {
        let zip_sha256 = hex(&Sha256::digest(raw));
        let mut zip =
            zip::ZipArchive::new(Cursor::new(raw)).map_err(|e| Error::Zip(e.to_string()))?;

        let mut p7b_name = None;
        let mut manifest_name = None;
        for i in 0..zip.len() {
            let name = zip
                .by_index(i)
                .map_err(|e| Error::Zip(e.to_string()))?
                .name()
                .to_string();
            let base = name.rsplit('/').next().unwrap_or(&name).to_string();
            if is_main_p7b(&base) {
                p7b_name = Some(name.clone());
            }
            if base.to_lowercase().ends_with(".sha256") {
                manifest_name = Some(name.clone());
            }
        }
        let p7b_name = p7b_name.ok_or_else(|| Error::MissingFile("main bundle .p7b".into()))?;
        let manifest_name = manifest_name.ok_or_else(|| Error::MissingFile("*.sha256".into()))?;

        let read_entry =
            |zip: &mut zip::ZipArchive<Cursor<&[u8]>>, name: &str| -> Result<Vec<u8>> {
                let mut buf = Vec::new();
                zip.by_name(name)
                    .map_err(|e| Error::Zip(e.to_string()))?
                    .read_to_end(&mut buf)?;
                Ok(buf)
            };
        let p7b_bytes = read_entry(&mut zip, &p7b_name)?;
        let manifest_bytes = read_entry(&mut zip, &manifest_name)?;

        let certs = parse_p7b(&p7b_bytes)?;

        // Verify the CMS-signed manifest (anchored to a pinned DoD root), then
        // the p7b's checksum against it.
        let manifest: Manifest = verify::verify_manifest(&manifest_bytes, &certs)?;
        let p7b_base = p7b_name.rsplit('/').next().unwrap_or(&p7b_name);
        let expected = manifest
            .checksums
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(p7b_base))
            .map(|(_, h)| h.clone())
            .ok_or_else(|| Error::Verify(format!("manifest has no checksum for {p7b_base}")))?;
        let actual = hex(&Sha256::digest(&p7b_bytes));
        if expected != actual {
            return Err(Error::Verify(format!(
                "checksum mismatch for {p7b_base}: manifest {expected}, actual {actual}"
            )));
        }

        // With the bundle manifest-anchored, require only internal chain
        // consistency — each group's own roots are vouched for transitively.
        let roots = verify::verify_chains_internal(&certs)?;
        Ok(Bundle {
            group,
            version: parse_version(&p7b_name).unwrap_or_else(|| "unknown".into()),
            zip_sha256,
            certs: certs.clone(),
            verify: VerifyReport {
                anchored_roots: roots,
                chained_ok: certs.len(),
                manifest_signed: true,
                manifest_signer: Some(manifest.signer),
            },
            source: source.to_string(),
        })
    }

    /// Parse + verify a bare `.p7b` (no signed manifest available). Without a
    /// manifest to anchor the bundle, every chain must terminate at a pinned DoD
    /// root — so this path only accepts the DoD group.
    pub fn from_p7b_bytes(raw: &[u8], source: &str) -> Result<Bundle> {
        let certs = parse_p7b(raw)?;
        let roots = verify::verify_chains_pinned(&certs)?;
        Ok(Bundle {
            group: Group::Dod,
            version: parse_version(source).unwrap_or_else(|| "unknown".into()),
            zip_sha256: String::new(),
            certs: certs.clone(),
            verify: VerifyReport {
                anchored_roots: roots,
                chained_ok: certs.len(),
                manifest_signed: false,
                manifest_signer: None,
            },
            source: source.to_string(),
        })
    }
}

/// The main bundle file is the group's aggregate DER `.p7b` — not a per-root
/// file and not the PEM sibling. DISA names it either `..._DoD.der.p7b` (dot) or
/// `..._eca_der.p7b` (underscore); both contain "der". Requiring "der" (and
/// excluding "pem") is what makes selection deterministic when the archive ships
/// both a DER and a PEM copy — otherwise a tampered DER file could be silently
/// ignored in favour of the untouched PEM one.
fn is_main_p7b(base: &str) -> bool {
    let b = base.to_lowercase();
    b.ends_with("p7b")
        && b.contains("der")
        && !b.contains("pem")
        && !b.contains("root")
        && !b.contains("_ca_")
}

/// Infer the group from the archive's main p7b filename.
fn infer_group(raw: &[u8]) -> Option<Group> {
    let mut zip = zip::ZipArchive::new(Cursor::new(raw)).ok()?;
    for i in 0..zip.len() {
        let name = zip.by_index(i).ok()?.name().to_lowercase();
        let base = name.rsplit('/').next().unwrap_or(&name);
        if is_main_p7b(base) {
            for g in Group::ALL {
                if base.contains(&g.slug().to_lowercase()) {
                    return Some(g);
                }
            }
        }
    }
    None
}

/// "…PKCS7_v5_14_DoD…" or "…pkcs7_v5_12_eca…" → "5.14" / "5.12"
fn parse_version(name: &str) -> Option<String> {
    let lower = name.to_lowercase();
    let idx = lower.find("_v")?;
    let rest = &lower[idx + 2..];
    // Take the leading run of digits and underscores (the version), stopping at
    // the first non-version character (e.g. the group slug).
    let ver: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '_')
        .collect();
    let ver = ver.trim_matches('_');
    if ver.is_empty() || !ver.chars().next()?.is_ascii_digit() {
        return None;
    }
    Some(ver.replace('_', "."))
}

#[cfg(test)]
mod tests {
    use super::{parse_version, Group};

    #[test]
    fn version_from_names() {
        assert_eq!(
            parse_version("Certificates_PKCS7_v5_14_DoD.der.p7b").as_deref(),
            Some("5.14")
        );
        assert_eq!(
            parse_version("dir/certificates_pkcs7_v5_12_eca_der.p7b").as_deref(),
            Some("5.12")
        );
        assert_eq!(
            parse_version("Certificates_PKCS7_v5_17_JITC.der.p7b").as_deref(),
            Some("5.17")
        );
        assert_eq!(parse_version("random.p7b"), None);
    }

    #[test]
    fn group_tokens_roundtrip() {
        for g in Group::ALL {
            assert_eq!(Group::from_token(g.token()), Some(g));
        }
        assert_eq!(Group::from_token("DOD"), Some(Group::Dod));
        assert_eq!(Group::from_token("nope"), None);
    }
}
