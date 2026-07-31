//! macOS trust-store backend (keychain + trust settings).
//!
//! On macOS a CA certificate is trusted by being present in a keychain *and*
//! (for roots) having explicit trust settings. Fossroot uses the login keychain
//! for the per-user case ([`Location::CurrentUser`]) and the system keychain
//! for the machine-wide case ([`Location::LocalMachine`], which requires admin).
//!
//! Presence in the keychain is what counts as "installed", matching the
//! Windows and Linux backends. Both logical stores map to the same keychain; a
//! listed certificate is classified as ROOT or CA by whether it is self-issued,
//! so the shared [`crate::diff`] logic still works. Roots additionally carry
//! explicit "trust as root" settings, applied at add time and stripped again at
//! remove time; intermediates are trusted transitively once their root is and
//! carry no settings of their own.
//!
//! Enumeration and removal therefore operate on the *keychain itself*
//! (`SecItemCopyMatching` scoped to the target keychain), never on
//! `SecTrustSettingsCopyCertificates`. Trust-settings enumeration only yields
//! certificates that carry explicit settings — which intermediates never have —
//! and returns detached `SecCertificateRef`s that `SecItemDelete` rejects with
//! "the specified item is no longer valid". A keychain-scoped item search
//! returns live keychain items that enumerate and delete correctly.

use core_foundation::base::TCFType;
use core_foundation_sys::base::OSStatus;
use security_framework::certificate::SecCertificate;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
use security_framework::os::macos::keychain::SecKeychain;
use security_framework::trust_settings::{Domain, TrustSettings};
use security_framework_sys::base::{errSecItemNotFound, SecCertificateRef};
use security_framework_sys::trust_settings::SecTrustSettingsDomain;

use crate::certs::CertInfo;
use crate::store::{InstalledCert, Location, StoreKind, SystemStore, TrustStore};
use crate::{Error, Result};

pub struct MacStore;

// `SecTrustSettingsRemoveTrustSettings` has been public Security.framework API
// since macOS 10.3 but is not bound by security-framework-sys; declare it here
// so removal of a root also clears its trust-settings residue. (The Windows
// backend likewise binds platform FFI directly where safe wrappers fall short.)
extern "C" {
    fn SecTrustSettingsRemoveTrustSettings(
        certificate: SecCertificateRef,
        domain: SecTrustSettingsDomain,
    ) -> OSStatus;
}

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

/// Every certificate item in `keychain`, as live keychain-backed references.
///
/// `SecItemCopyMatching` reports an empty result set as `errSecItemNotFound`;
/// for enumeration that means "no certificates", not a failure.
fn keychain_certificates(keychain: &SecKeychain) -> Result<Vec<SecCertificate>> {
    let mut opts = ItemSearchOptions::new();
    opts.keychains(std::slice::from_ref(keychain));
    opts.class(ItemClass::certificate());
    opts.load_refs(true);
    opts.limit(Limit::All);
    let results = match opts.search() {
        Ok(results) => results,
        Err(e) if e.code() == errSecItemNotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::Store(format!("search keychain: {e}"))),
    };
    Ok(results
        .into_iter()
        .filter_map(|r| match r {
            SearchResult::Ref(Reference::Certificate(c)) => Some(c),
            _ => None,
        })
        .collect())
}

impl TrustStore for MacStore {
    fn list(&self, store: SystemStore) -> Result<Vec<InstalledCert>> {
        let keychain = keychain_for(store.location)?;
        let mut out = Vec::new();
        for cert in keychain_certificates(&keychain)? {
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
        let keychain = keychain_for(store.location)?;
        for cert in keychain_certificates(&keychain)? {
            let der = cert.to_der();
            let Ok(info) = CertInfo::from_der(&der) else {
                continue;
            };
            if &info.sha1 != sha1 {
                continue;
            }
            // Strip explicit trust settings first so removal leaves no residue
            // in the trust-settings domain. Intermediates have none, so
            // errSecItemNotFound is expected and fine.
            let status = unsafe {
                SecTrustSettingsRemoveTrustSettings(
                    cert.as_concrete_TypeRef(),
                    SecTrustSettingsDomain::from(domain_for(store.location)),
                )
            };
            if status != 0 && status != errSecItemNotFound {
                return Err(Error::Store(format!(
                    "remove trust settings: OSStatus {status}"
                )));
            }
            cert.delete()
                .map_err(|e| Error::Store(format!("delete cert: {e}")))?;
            return Ok(true);
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
