//! macOS trust-store backend (keychain + trust settings).
//!
//! On macOS a CA certificate is trusted by being present in a keychain *and*
//! having explicit trust settings. Fossroot uses the login keychain for the
//! per-user case ([`Location::CurrentUser`]) and the system keychain for the
//! machine-wide case ([`Location::LocalMachine`], which requires admin).
//!
//! Both the ROOT and CA logical stores map to the same keychain; a listed
//! certificate is classified as ROOT or CA by whether it is self-issued, so the
//! shared [`crate::diff`] logic still works. Root anchors additionally get
//! explicit "trust as root" settings applied.

use security_framework::certificate::SecCertificate;
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::trust_settings::{Domain, TrustSettings};

use crate::certs::CertInfo;
use crate::store::{InstalledCert, Location, StoreKind, SystemStore, TrustStore};
use crate::{Error, Result};

pub struct MacStore;

fn keychain_for(location: Location) -> Result<SecKeychain> {
    match location {
        Location::CurrentUser => {
            SecKeychain::default().map_err(|e| Error::Store(format!("open login keychain: {e}")))
        }
        Location::LocalMachine => SecKeychain::open("/Library/Keychains/System.keychain")
            .map_err(|e| Error::Store(format!("open system keychain: {e}"))),
    }
}

fn domain_for(location: Location) -> Domain {
    match location {
        Location::CurrentUser => Domain::User,
        Location::LocalMachine => Domain::Admin,
    }
}

impl TrustStore for MacStore {
    fn list(&self, store: SystemStore) -> Result<Vec<InstalledCert>> {
        // Enumerate certs that carry trust settings in this domain — i.e. the
        // ones a user (or Fossroot) has explicitly trusted.
        let settings = TrustSettings::new(domain_for(store.location));
        let iter = match settings.iter() {
            Ok(i) => i,
            Err(_) => return Ok(Vec::new()),
        };
        let mut out = Vec::new();
        for cert in iter {
            let der = cert.to_der();
            if let Ok(info) = CertInfo::from_der(&der) {
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

    fn add(&self, store: SystemStore, der: &[u8]) -> Result<()> {
        let cert =
            SecCertificate::from_der(der).map_err(|e| Error::Store(format!("parse cert: {e}")))?;
        let keychain = keychain_for(store.location)?;
        // Import into the keychain (idempotent — ignore "already exists").
        if let Err(e) = cert.add_to_keychain(Some(keychain)) {
            let msg = e.to_string();
            if !msg.contains("already") {
                return Err(Error::Store(format!("add to keychain: {e}")));
            }
        }
        // Self-issued roots need explicit trust settings; intermediates are
        // trusted transitively once their root is, so leave their settings
        // at the default.
        let info = CertInfo::from_der(der)?;
        if info.is_self_issued {
            let settings = TrustSettings::new(domain_for(store.location));
            settings
                .set_trust_settings_always(&cert)
                .map_err(|e| Error::Store(format!("set trust settings: {e}")))?;
        }
        Ok(())
    }

    fn remove_by_sha1(&self, store: SystemStore, sha1: &[u8; 20]) -> Result<bool> {
        let settings = TrustSettings::new(domain_for(store.location));
        let iter = match settings.iter() {
            Ok(i) => i,
            Err(_) => return Ok(false),
        };
        for cert in iter {
            let der = cert.to_der();
            if let Ok(info) = CertInfo::from_der(&der) {
                if &info.sha1 == sha1 {
                    cert.delete()
                        .map_err(|e| Error::Store(format!("delete cert: {e}")))?;
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn probe_write(&self, store: SystemStore) -> Result<()> {
        // Opening the target keychain is the cheapest signal we can get without
        // mutating anything; the system keychain additionally needs admin, which
        // surfaces at write time.
        keychain_for(store.location).map(|_| ())
    }
}
