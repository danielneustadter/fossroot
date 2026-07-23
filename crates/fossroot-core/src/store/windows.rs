//! Windows CryptoAPI trust-store backend (ROOT / CA system stores).

use windows::Win32::Security::Cryptography::{
    CertAddEncodedCertificateToStore, CertCloseStore, CertDeleteCertificateFromStore,
    CertEnumCertificatesInStore, CertFindCertificateInStore,
    CertOpenStore, CERT_CONTEXT, CERT_FIND_SHA1_HASH,
    CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE, CERT_STORE_ADD_REPLACE_EXISTING,
    CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_REGISTRY_W, CERT_STORE_READONLY_FLAG,
    CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
    HCERTSTORE, HCRYPTPROV_LEGACY, X509_ASN_ENCODING,
};

use crate::certs::CertInfo;
use crate::store::{InstalledCert, Location, StoreKind, SystemStore, TrustStore};
use crate::{Error, Result};

pub struct WindowsStore;

struct OpenStore(HCERTSTORE);

impl Drop for OpenStore {
    fn drop(&mut self) {
        unsafe {
            let _ = CertCloseStore(self.0, 0);
        }
    }
}

fn open(store: SystemStore, readonly: bool) -> Result<OpenStore> {
    let name: Vec<u16> = match store.kind {
        StoreKind::Root => "ROOT",
        StoreKind::Ca => "CA",
    }
    .encode_utf16()
    .chain(std::iter::once(0))
    .collect();

    let mut flags = CERT_STORE_OPEN_EXISTING_FLAG.0
        | match store.location {
            Location::CurrentUser => CERT_SYSTEM_STORE_CURRENT_USER,
            Location::LocalMachine => CERT_SYSTEM_STORE_LOCAL_MACHINE,
        };
    if readonly {
        flags |= CERT_STORE_READONLY_FLAG.0;
    }

    // SYSTEM_REGISTRY (not SYSTEM): target the location's own physical registry
    // store. The plain SYSTEM provider opens a *collection* view — under
    // CurrentUser it includes the LocalMachine members, so a user-level remove
    // could reach through and delete machine certificates. The registry
    // provider reads and writes exactly one hive.
    let handle = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_REGISTRY_W,
            CERT_QUERY_ENCODING_TYPE(0),
            HCRYPTPROV_LEGACY::default(),
            CERT_OPEN_STORE_FLAGS(flags),
            Some(name.as_ptr() as *const core::ffi::c_void),
        )
    }
    .map_err(|e| Error::Store(format!("CertOpenStore({store:?}): {e}")))?;
    Ok(OpenStore(handle))
}

impl TrustStore for WindowsStore {
    fn list(&self, store: SystemStore) -> Result<Vec<InstalledCert>> {
        let handle = open(store, true)?;
        let mut out = Vec::new();
        let mut ctx: *const CERT_CONTEXT = std::ptr::null();
        loop {
            ctx = unsafe { CertEnumCertificatesInStore(handle.0, Some(ctx)) };
            if ctx.is_null() {
                break;
            }
            let der = unsafe {
                std::slice::from_raw_parts((*ctx).pbCertEncoded, (*ctx).cbCertEncoded as usize)
            };
            // Some stores contain non-X.509 oddities; skip anything unparseable.
            if let Ok(info) = CertInfo::from_der(der) {
                out.push(InstalledCert {
                    subject: info.subject,
                    sha1: info.sha1,
                    not_after: info.not_after,
                });
            }
        }
        Ok(out)
    }

    fn add(&self, store: SystemStore, der: &[u8]) -> Result<()> {
        let handle = open(store, false)?;
        unsafe {
            CertAddEncodedCertificateToStore(
                handle.0,
                X509_ASN_ENCODING,
                der,
                CERT_STORE_ADD_REPLACE_EXISTING,
                None,
            )
        }
        .map_err(|e| Error::Store(format!("CertAddEncodedCertificateToStore: {e}")))
    }

    fn remove_by_sha1(&self, store: SystemStore, sha1: &[u8; 20]) -> Result<bool> {
        let handle = open(store, false)?;
        let blob = CRYPT_INTEGER_BLOB {
            cbData: sha1.len() as u32,
            pbData: sha1.as_ptr() as *mut u8,
        };
        let found = unsafe {
            CertFindCertificateInStore(
                handle.0,
                X509_ASN_ENCODING,
                0,
                CERT_FIND_SHA1_HASH,
                Some(&blob as *const CRYPT_INTEGER_BLOB as *const core::ffi::c_void),
                None,
            )
        };
        if found.is_null() {
            return Ok(false);
        }
        // CertDeleteCertificateFromStore always frees the context it is given.
        unsafe { CertDeleteCertificateFromStore(found) }
            .map_err(|e| Error::Store(format!("CertDeleteCertificateFromStore: {e}")))?;
        Ok(true)
    }

    fn probe_write(&self, store: SystemStore) -> Result<()> {
        open(store, false).map(|_| ())
    }
}
