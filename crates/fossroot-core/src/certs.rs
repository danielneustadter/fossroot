//! Parsing PKCS#7 bundles and X.509 certificates into [`CertInfo`].

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use x509_cert::Certificate;

use crate::{Error, Result};

/// A parsed certificate plus everything Fossroot needs to reason about it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    /// Unix seconds.
    pub not_before: i64,
    /// Unix seconds.
    pub not_after: i64,
    /// SHA-1 of the DER encoding — the "thumbprint" Windows uses to identify certs.
    #[serde(serialize_with = "ser_hex")]
    pub sha1: [u8; 20],
    /// SHA-256 of the DER encoding.
    #[serde(serialize_with = "ser_hex")]
    pub sha256: [u8; 32],
    /// Subject == issuer (candidate trust anchor).
    pub is_self_issued: bool,
    #[serde(skip)]
    pub der: Vec<u8>,
}

fn ser_hex<S: serde::Serializer>(bytes: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&hex(bytes))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl CertInfo {
    pub fn from_der(der_bytes: &[u8]) -> Result<Self> {
        let cert = Certificate::from_der(der_bytes).map_err(|e| Error::Der(e.to_string()))?;
        Ok(Self::from_parsed(&cert, der_bytes))
    }

    pub fn from_parsed(cert: &Certificate, der_bytes: &[u8]) -> Self {
        let tbs = &cert.tbs_certificate;
        let subject = tbs.subject.to_string();
        let issuer = tbs.issuer.to_string();
        CertInfo {
            is_self_issued: subject == issuer,
            subject,
            issuer,
            serial: hex(tbs.serial_number.as_bytes()),
            not_before: tbs.validity.not_before.to_unix_duration().as_secs() as i64,
            not_after: tbs.validity.not_after.to_unix_duration().as_secs() as i64,
            sha1: Sha1::digest(der_bytes).into(),
            sha256: Sha256::digest(der_bytes).into(),
            der: der_bytes.to_vec(),
        }
    }

    /// Common name if present, else the full subject DN.
    pub fn display_name(&self) -> String {
        self.subject
            .split(',')
            .map(str::trim)
            .find_map(|part| part.strip_prefix("CN="))
            .unwrap_or(&self.subject)
            .to_string()
    }

    pub fn is_expired(&self, now_unix: i64) -> bool {
        self.not_after < now_unix
    }
}

/// Extract every certificate from a PKCS#7/CMS SignedData blob (DER or PEM).
pub fn parse_p7b(bytes: &[u8]) -> Result<Vec<CertInfo>> {
    let der_bytes = maybe_pem_to_der(bytes)?;
    let ci =
        ContentInfo::from_der(&der_bytes).map_err(|e| Error::Der(format!("ContentInfo: {e}")))?;
    let sd: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| Error::Der(format!("SignedData: {e}")))?;
    let Some(cert_set) = &sd.certificates else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for choice in cert_set.0.iter() {
        if let CertificateChoices::Certificate(cert) = choice {
            let der = cert.to_der().map_err(|e| Error::Der(e.to_string()))?;
            out.push(CertInfo::from_parsed(cert, &der));
        }
    }
    Ok(out)
}

/// Accept PEM ("-----BEGIN PKCS7-----" / "-----BEGIN CMS-----") or raw DER.
fn maybe_pem_to_der(bytes: &[u8]) -> Result<Vec<u8>> {
    let text = match std::str::from_utf8(bytes) {
        Ok(t) if t.contains("-----BEGIN") => t,
        _ => return Ok(bytes.to_vec()),
    };
    let b64: String = text
        .lines()
        .filter(|l| !l.starts_with("-----") && !l.trim().is_empty())
        .collect();
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| Error::Der(format!("PEM base64: {e}")))
}

pub fn format_unix(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| ts.to_string())
}
