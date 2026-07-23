//! Comparing a verified bundle against what a trust store actually contains.

use crate::certs::CertInfo;
use crate::store::{InstalledCert, StoreKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertStatus {
    /// Present in the store.
    Installed,
    /// In the bundle but absent from the store.
    Missing,
    /// In the bundle but expired — never installed by Fossroot.
    Expired,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DiffEntry {
    #[serde(flatten)]
    pub cert: CertInfo,
    /// Which store this cert belongs in (roots → ROOT, intermediates → CA).
    pub store: StoreKind,
    pub status: CertStatus,
}

#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct DiffReport {
    pub entries: Vec<DiffEntry>,
    /// DoD-issued certs found in the store that are NOT in the current bundle —
    /// stale CAs that DISA has dropped (candidates for removal).
    pub stale: Vec<InstalledCert>,
    pub installed: usize,
    pub missing: usize,
    pub expired: usize,
}

/// Compare bundle certs against the contents of the ROOT and CA stores.
pub fn diff(
    bundle_certs: &[CertInfo],
    in_root: &[InstalledCert],
    in_ca: &[InstalledCert],
    now_unix: i64,
) -> DiffReport {
    let mut report = DiffReport::default();
    for cert in bundle_certs {
        let (kind, installed_set) = if cert.is_self_issued {
            (StoreKind::Root, in_root)
        } else {
            (StoreKind::Ca, in_ca)
        };
        let status = if installed_set.iter().any(|i| i.sha1 == cert.sha1) {
            CertStatus::Installed
        } else if cert.is_expired(now_unix) {
            CertStatus::Expired
        } else {
            CertStatus::Missing
        };
        match status {
            CertStatus::Installed => report.installed += 1,
            CertStatus::Missing => report.missing += 1,
            CertStatus::Expired => report.expired += 1,
        }
        report.entries.push(DiffEntry {
            cert: cert.clone(),
            store: kind,
            status,
        });
    }

    // Stale: store certs that look DoD-issued but aren't in the bundle anymore.
    let bundle_sha1: Vec<&[u8; 20]> = bundle_certs.iter().map(|c| &c.sha1).collect();
    for ic in in_root.iter().chain(in_ca.iter()) {
        if looks_dod(&ic.subject) && !bundle_sha1.iter().any(|s| **s == ic.sha1) {
            report.stale.push(ic.clone());
        }
    }
    report
}

/// Heuristic: DISA-operated DoD NIPR PKI subjects. Deliberately narrow — we only
/// flag certs we'd confidently call DoD PKI CAs, never third-party ones.
fn looks_dod(subject: &str) -> bool {
    let s = subject.to_uppercase();
    (s.contains("OU=DOD") || s.contains("OU=PKI,OU=DOD") || s.contains("CN=DOD "))
        && s.contains("O=U.S. GOVERNMENT")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_cert(subject: &str, self_issued: bool, sha1_seed: u8, not_after: i64) -> CertInfo {
        CertInfo {
            subject: subject.into(),
            issuer: if self_issued {
                subject.into()
            } else {
                "CN=Other".into()
            },
            serial: "01".into(),
            not_before: 0,
            not_after,
            sha1: [sha1_seed; 20],
            sha256: [sha1_seed; 32],
            is_self_issued: self_issued,
            der: vec![],
        }
    }

    fn installed(subject: &str, sha1_seed: u8) -> InstalledCert {
        InstalledCert {
            subject: subject.into(),
            sha1: [sha1_seed; 20],
            not_after: i64::MAX,
        }
    }

    #[test]
    fn classifies_installed_missing_expired() {
        let far = 4102444800; // 2100
        let bundle = vec![
            fake_cert(
                "CN=DoD Root CA 3,OU=PKI,OU=DoD,O=U.S. Government,C=US",
                true,
                1,
                far,
            ),
            fake_cert(
                "CN=DOD ID CA-59,OU=PKI,OU=DoD,O=U.S. Government,C=US",
                false,
                2,
                far,
            ),
            fake_cert(
                "CN=DOD OLD CA,OU=PKI,OU=DoD,O=U.S. Government,C=US",
                false,
                3,
                100,
            ),
        ];
        let in_root = vec![installed(
            "CN=DoD Root CA 3,OU=PKI,OU=DoD,O=U.S. Government,C=US",
            1,
        )];
        let report = diff(&bundle, &in_root, &[], 1_000_000);
        assert_eq!(report.installed, 1);
        assert_eq!(report.missing, 1);
        assert_eq!(report.expired, 1);
        assert!(report.stale.is_empty());
    }

    #[test]
    fn flags_stale_dod_certs_only() {
        let in_ca = vec![
            installed(
                "CN=DOD EMAIL CA-33, OU=PKI, OU=DoD, O=U.S. Government, C=US",
                9,
            ),
            installed("CN=Some Corp CA, O=Some Corp, C=US", 10),
        ];
        let report = diff(&[], &[], &in_ca, 0);
        assert_eq!(report.stale.len(), 1);
        assert!(report.stale[0].subject.contains("DOD EMAIL CA-33"));
    }
}
