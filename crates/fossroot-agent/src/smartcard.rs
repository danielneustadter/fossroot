//! Read-only smart-card / personal-certificate status.
//!
//! Lets the CAC Reset extension tell three states apart:
//! - **No CAC detected** — no smart-card-backed cert in the user's MY store
//!   (card unplugged / reader empty).
//! - **CAC present** — a hardware-backed DoD cert is readable, so if a site
//!   still rejects it the problem is a stale browser session, not the card.
//! - **Certs but no card** — soft certs only.
//!
//! Windows only; other platforms report `supported: false`.

use serde::Serialize;

#[derive(Serialize, Default)]
pub struct ScStatus {
    pub supported: bool,
    /// A smart-card-backed certificate is readable right now.
    pub card_present: bool,
    /// Certificates in the CurrentUser "MY" store.
    pub personal_certs: usize,
    /// Of those, how many are backed by a smart-card key storage provider.
    pub smartcard_backed: usize,
    /// Of those, how many were issued under DoD PKI.
    pub dod_certs: usize,
    pub identities: Vec<Identity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Serialize)]
pub struct Identity {
    pub common_name: String,
    pub issuer: String,
    pub hardware_backed: bool,
    pub dod: bool,
    pub not_after: i64,
}

#[cfg_attr(not(windows), allow(dead_code))]
fn is_dod(subject: &str, issuer: &str) -> bool {
    let s = format!("{subject} {issuer}").to_uppercase();
    s.contains("OU=DOD") || (s.contains("O=U.S. GOVERNMENT") && s.contains("PKI"))
}

#[cfg(windows)]
pub fn status() -> ScStatus {
    imp::status()
}

#[cfg(not(windows))]
pub fn status() -> ScStatus {
    ScStatus {
        supported: false,
        note: Some("smart-card status is only available on Windows in this build".into()),
        ..Default::default()
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use fossroot_core::certs::CertInfo;
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertEnumCertificatesInStore, CertGetCertificateContextProperty,
        CertOpenStore, CERT_CONTEXT, CERT_KEY_PROV_INFO_PROP_ID, CERT_OPEN_STORE_FLAGS,
        CERT_QUERY_ENCODING_TYPE, CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_REGISTRY_W,
        CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_CURRENT_USER, CRYPT_KEY_PROV_INFO,
        HCRYPTPROV_LEGACY,
    };

    pub fn status() -> ScStatus {
        let mut out = ScStatus {
            supported: true,
            ..Default::default()
        };

        let name: Vec<u16> = "MY".encode_utf16().chain(std::iter::once(0)).collect();
        let flags = CERT_STORE_OPEN_EXISTING_FLAG.0
            | CERT_STORE_READONLY_FLAG.0
            | CERT_SYSTEM_STORE_CURRENT_USER;
        let store = match unsafe {
            CertOpenStore(
                CERT_STORE_PROV_SYSTEM_REGISTRY_W,
                CERT_QUERY_ENCODING_TYPE(0),
                HCRYPTPROV_LEGACY::default(),
                CERT_OPEN_STORE_FLAGS(flags),
                Some(name.as_ptr() as *const core::ffi::c_void),
            )
        } {
            Ok(h) => h,
            Err(e) => {
                out.note = Some(format!("could not open personal store: {e}"));
                return out;
            }
        };

        let mut ctx: *const CERT_CONTEXT = std::ptr::null();
        loop {
            ctx = unsafe { CertEnumCertificatesInStore(store, Some(ctx)) };
            if ctx.is_null() {
                break;
            }
            let der = unsafe {
                std::slice::from_raw_parts((*ctx).pbCertEncoded, (*ctx).cbCertEncoded as usize)
            };
            let Ok(info) = CertInfo::from_der(der) else {
                continue;
            };
            out.personal_certs += 1;
            let hardware = key_provider_is_smartcard(ctx);
            let dod = is_dod(&info.subject, &info.issuer);
            if hardware {
                out.smartcard_backed += 1;
            }
            if dod {
                out.dod_certs += 1;
            }
            if out.identities.len() < 16 {
                out.identities.push(Identity {
                    common_name: info.display_name(),
                    issuer: issuer_cn(&info.issuer),
                    hardware_backed: hardware,
                    dod,
                    not_after: info.not_after,
                });
            }
        }
        unsafe {
            let _ = CertCloseStore(store, 0);
        }

        out.card_present = out.smartcard_backed > 0;
        if out.card_present {
            out.note = Some("A smart-card certificate is readable.".into());
        } else if out.personal_certs == 0 {
            out.note = Some("No personal certificates found — insert your CAC.".into());
        } else {
            out.note = Some("No smart-card certificate detected — insert your CAC.".into());
        }
        out
    }

    /// Read the cert's key-provider info and decide whether it's a smart card.
    fn key_provider_is_smartcard(ctx: *const CERT_CONTEXT) -> bool {
        let mut cb = 0u32;
        // Size query.
        if unsafe {
            CertGetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, None, &mut cb)
        }
        .is_err()
            || cb == 0
        {
            return false;
        }
        let mut buf = vec![0u8; cb as usize];
        if unsafe {
            CertGetCertificateContextProperty(
                ctx,
                CERT_KEY_PROV_INFO_PROP_ID,
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                &mut cb,
            )
        }
        .is_err()
        {
            return false;
        }
        let info = unsafe { &*(buf.as_ptr() as *const CRYPT_KEY_PROV_INFO) };
        let prov = read_wide(info.pwszProvName.0);
        // Microsoft's CAC/PIV minidriver surfaces through the "Smart Card Key
        // Storage Provider"; some middleware providers also contain "Smart Card".
        prov.to_lowercase().contains("smart card")
    }

    fn read_wide(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        unsafe {
            while *ptr.add(len) != 0 {
                len += 1;
            }
        }
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        String::from_utf16_lossy(slice)
    }

    /// Pull the CN out of an issuer DN string for a compact display.
    fn issuer_cn(dn: &str) -> String {
        dn.split(',')
            .map(str::trim)
            .find_map(|p| p.strip_prefix("CN="))
            .unwrap_or(dn)
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::is_dod;

    #[test]
    fn dod_detection() {
        assert!(is_dod(
            "CN=SMITH.JOHN.A.1234567890,OU=PKI,OU=DoD,O=U.S. Government,C=US",
            "CN=DOD ID CA-59,OU=PKI,OU=DoD,O=U.S. Government,C=US"
        ));
        assert!(!is_dod(
            "CN=Acme User,O=Acme,C=US",
            "CN=Acme CA,O=Acme,C=US"
        ));
    }
}
