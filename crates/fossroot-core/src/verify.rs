//! Bundle verification: pinned DoD trust anchors, certificate chain validation
//! with signature verification, and CMS signed-manifest verification.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier};
use der::asn1::OctetString;
use der::{Decode, Encode};
use rsa::signature::hazmat::PrehashVerifier;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::Certificate;

use crate::certs::{hex, CertInfo};
use crate::{Error, Result};

/// SHA-256 fingerprints of the DoD root CAs Fossroot will accept as trust anchors.
///
/// Provenance (2026-07-23): extracted from DISA's Certificates_PKCS7_v5_14_DoD
/// bundle (dl.dod.cyber.mil) and independently cross-checked against the
/// LocalMachine\Root store of a machine provisioned by DISA InstallRoot 5.6.
/// These match the fingerprints DISA publishes on cyber.mil (PKI/PKE document
/// library). If DISA ever adds a root, it must be added here deliberately.
pub const PINNED_ROOTS: &[(&str, &str)] = &[
    (
        "DoD Root CA 3",
        "b107b33f453e5510f68e513110c6f6944bacc263df0137f821c1b3c2f8f863d2",
    ),
    (
        "DoD Root CA 4",
        "559a5189452b13f8233f0022363c06f26e3c517c1d4b77445035959df3244f74",
    ),
    (
        "DoD Root CA 5",
        "1f4ede9dc2a241f6521bf518424acd49ebe84420e69daf5bac57af1f8ee294a9",
    ),
    (
        "DoD Root CA 6",
        "2a5e41aca93df7cc496d2369b7a0a037045d502f1abaaf76975fc07c6660cf93",
    ),
];

fn pinned_fingerprint(sha256: &[u8; 32]) -> Option<&'static str> {
    let fp = hex(sha256);
    PINNED_ROOTS
        .iter()
        .find(|(_, pin)| *pin == fp)
        .map(|(name, _)| *name)
}

/// The DoD root CA certificates, embedded as verification **anchors** only.
///
/// These four public root certs let Fossroot verify a bundle's DISA-signed
/// manifest even when the signing chain's root is not redelivered inside that
/// particular bundle (the case for the ECA/JITC/WCF groups, whose manifests are
/// signed by a DoD PKE credential chaining to a DoD root). Each embedded cert is
/// checked against its pinned fingerprint at load, so a tampered anchor file
/// fails the build's own invariant rather than silently widening trust.
///
/// This is the *only* certificate material Fossroot ships. It never bundles the
/// intermediate/leaf certificates it installs — those always come live from DISA.
const ANCHOR_DER: &[&[u8]] = &[
    include_bytes!("anchors/dod_root_ca_3.cer"),
    include_bytes!("anchors/dod_root_ca_4.cer"),
    include_bytes!("anchors/dod_root_ca_5.cer"),
    include_bytes!("anchors/dod_root_ca_6.cer"),
];

/// Parse the embedded anchors, asserting each matches a pinned fingerprint.
/// Panics only if the shipped anchor files were corrupted — a build-integrity
/// failure, caught by tests, never a runtime-input condition.
pub fn anchor_certs() -> Vec<CertInfo> {
    ANCHOR_DER
        .iter()
        .map(|der| {
            let c = CertInfo::from_der(der).expect("embedded anchor is valid DER");
            assert!(
                pinned_fingerprint(&c.sha256).is_some(),
                "embedded anchor {} does not match a pinned fingerprint",
                c.display_name()
            );
            c
        })
        .collect()
}

/// Outcome of verifying a full bundle.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyReport {
    /// Roots found in the bundle that matched a pin, by name.
    pub anchored_roots: Vec<String>,
    /// Number of certificates whose chain + signatures verified.
    pub chained_ok: usize,
    /// True when the CMS manifest signature verified back to a pinned root.
    pub manifest_signed: bool,
    /// CN of the manifest signer, when manifest verification succeeded.
    pub manifest_signer: Option<String>,
}

/// Verify that every certificate in `certs` chains, with valid signatures, to a
/// pinned DoD root. Self-issued certs must themselves match a pin. Fails closed.
///
/// Used for the bare-`.p7b` path, where there is no signed manifest to anchor the
/// bundle — so trust must bottom out at a pinned root directly (DoD group only).
pub fn verify_chains_pinned(certs: &[CertInfo]) -> Result<Vec<String>> {
    verify_chains_with_pool(certs, certs, true)
}

/// Verify that every certificate chains, with valid signatures, to *some*
/// self-issued root present in the bundle — internal cryptographic consistency,
/// without requiring that root to be pinned.
///
/// Safe to use only once the bundle as a whole has been anchored some other way
/// (i.e. a CMS manifest signed by a credential chaining to a pinned DoD root has
/// vouched for the checksum of the certificate file). DISA signs every group's
/// manifest — DoD, ECA, JITC, WCF — with a DoD PKE credential, so that single
/// anchor transitively covers each group's own roots. Returns the root names.
pub fn verify_chains_internal(certs: &[CertInfo]) -> Result<Vec<String>> {
    verify_chains_with_pool(certs, certs, false)
}

/// Shared chain walker. `pool` supplies candidate issuers (for CMS signer chains,
/// intermediates can live in the bundle rather than the CMS). When `require_pinned`
/// is set, every terminal root must match a pinned DoD fingerprint.
pub fn verify_chains_with_pool(
    certs: &[CertInfo],
    pool: &[CertInfo],
    require_pinned: bool,
) -> Result<Vec<String>> {
    let mut roots = Vec::new();
    for cert in certs {
        if cert.is_self_issued {
            match pinned_fingerprint(&cert.sha256) {
                Some(name) => push_unique(&mut roots, name.to_string()),
                None if require_pinned => {
                    return Err(Error::Verify(format!(
                        "self-issued certificate '{}' does not match any pinned DoD root \
                         (sha256 {})",
                        cert.display_name(),
                        hex(&cert.sha256)
                    )))
                }
                None => push_unique(&mut roots, cert.display_name()),
            }
            continue;
        }
        let root = walk_to_root(cert, pool, require_pinned)?;
        push_unique(&mut roots, root);
    }
    Ok(roots)
}

fn push_unique(v: &mut Vec<String>, s: String) {
    if !v.contains(&s) {
        v.push(s);
    }
}

/// Walk issuer links (verifying each signature) until a self-issued root is
/// reached; returns that root's display name. When `require_pinned`, the root
/// must match a pin.
fn walk_to_root(leaf: &CertInfo, pool: &[CertInfo], require_pinned: bool) -> Result<String> {
    let mut current = leaf;
    let mut hops = 0usize;
    loop {
        hops += 1;
        if hops > 10 {
            return Err(Error::Verify(format!(
                "chain for '{}' exceeded 10 hops (possible cycle)",
                leaf.display_name()
            )));
        }
        let issuer = pool
            .iter()
            .find(|c| c.subject == current.issuer && verify_signature(current, c).is_ok())
            .ok_or_else(|| {
                Error::Verify(format!(
                    "no certificate in bundle validates the signature on '{}' (issuer: {})",
                    current.display_name(),
                    current.issuer
                ))
            })?;
        if issuer.is_self_issued {
            if require_pinned && pinned_fingerprint(&issuer.sha256).is_none() {
                return Err(Error::Verify(format!(
                    "chain for '{}' terminates at unpinned root '{}'",
                    leaf.display_name(),
                    issuer.display_name()
                )));
            }
            return Ok(issuer.display_name());
        }
        current = issuer;
    }
}

// Signature algorithm OIDs.
//
// SHA-1 appears here only because DISA still signs the bundle checksum manifest
// with its SHA-1 RSA code-signing credential. Certificate chains in the bundle
// use SHA-256/384; the manifest signature is one verification layer among
// several (chain verification and pinned roots do not depend on it).
const SHA1_WITH_RSA: &str = "1.2.840.113549.1.1.5";
const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
const SHA384_WITH_RSA: &str = "1.2.840.113549.1.1.12";
const SHA512_WITH_RSA: &str = "1.2.840.113549.1.1.13";
const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
const ECDSA_WITH_SHA384: &str = "1.2.840.10045.4.3.3";

/// Verify `child`'s signature using `issuer`'s public key.
fn verify_signature(child: &CertInfo, issuer: &CertInfo) -> Result<()> {
    let cert = Certificate::from_der(&child.der).map_err(|e| Error::Der(e.to_string()))?;
    let tbs = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| Error::Der(e.to_string()))?;
    let sig = cert
        .signature
        .as_bytes()
        .ok_or_else(|| Error::Der("signature BIT STRING has unused bits".into()))?;
    let alg = cert.signature_algorithm.oid.to_string();
    verify_raw_signature(&alg, &tbs, sig, issuer)
}

/// Verify `signature` over `message` under `signer`'s SubjectPublicKeyInfo.
pub fn verify_raw_signature(
    alg_oid: &str,
    message: &[u8],
    signature: &[u8],
    signer: &CertInfo,
) -> Result<()> {
    let signer_cert = Certificate::from_der(&signer.der).map_err(|e| Error::Der(e.to_string()))?;
    let spki = &signer_cert.tbs_certificate.subject_public_key_info;
    let key_bits = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| Error::Der("SPKI BIT STRING has unused bits".into()))?;

    let fail = |e: String| {
        Error::Verify(format!(
            "signature check failed (signer '{}', alg {alg_oid}): {e}",
            signer.display_name()
        ))
    };

    match alg_oid {
        SHA1_WITH_RSA | SHA256_WITH_RSA | SHA384_WITH_RSA | SHA512_WITH_RSA => {
            use rsa::pkcs1::DecodeRsaPublicKey;
            let key =
                rsa::RsaPublicKey::from_pkcs1_der(key_bits).map_err(|e| fail(e.to_string()))?;
            let (scheme, hashed): (rsa::pkcs1v15::Pkcs1v15Sign, Vec<u8>) = match alg_oid {
                SHA1_WITH_RSA => (
                    rsa::pkcs1v15::Pkcs1v15Sign::new::<sha1::Sha1>(),
                    sha1::Sha1::digest(message).to_vec(),
                ),
                SHA256_WITH_RSA => (
                    rsa::pkcs1v15::Pkcs1v15Sign::new::<Sha256>(),
                    Sha256::digest(message).to_vec(),
                ),
                SHA384_WITH_RSA => (
                    rsa::pkcs1v15::Pkcs1v15Sign::new::<Sha384>(),
                    Sha384::digest(message).to_vec(),
                ),
                _ => (
                    rsa::pkcs1v15::Pkcs1v15Sign::new::<Sha512>(),
                    Sha512::digest(message).to_vec(),
                ),
            };
            key.verify(scheme, &hashed, signature)
                .map_err(|e| fail(e.to_string()))
        }
        ECDSA_WITH_SHA256 => {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bits)
                .map_err(|e| fail(e.to_string()))?;
            let sig =
                p256::ecdsa::Signature::from_der(signature).map_err(|e| fail(e.to_string()))?;
            key.verify_prehash(&Sha256::digest(message), &sig)
                .map_err(|e| fail(e.to_string()))
        }
        ECDSA_WITH_SHA384 => {
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bits)
                .map_err(|e| fail(e.to_string()))?;
            let sig =
                p384::ecdsa::Signature::from_der(signature).map_err(|e| fail(e.to_string()))?;
            key.verify_prehash(&Sha384::digest(message), &sig)
                .map_err(|e| fail(e.to_string()))
        }
        other => Err(Error::Verify(format!(
            "unsupported signature algorithm {other} on cert signed by '{}'",
            signer.display_name()
        ))),
    }
}

/// A verified checksum manifest: file name → lowercase hex SHA-256.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub checksums: Vec<(String, String)>,
    pub signer: String,
}

/// Verify the DISA CMS-signed `.sha256` manifest and return its checksums.
///
/// Steps (RFC 5652): extract eContent (the checksum text), check the signer's
/// message-digest signed attribute against the eContent hash, verify the
/// signature over the DER SET OF signed attributes, and require the signer's
/// certificate to chain to a pinned DoD root (intermediates may come from
/// `extra_pool`, i.e. the certificate bundle itself — trust still bottoms out
/// at the pinned fingerprints).
pub fn verify_manifest(cms_bytes: &[u8], extra_pool: &[CertInfo]) -> Result<Manifest> {
    let ci = ContentInfo::from_der(cms_bytes)
        .map_err(|e| Error::Der(format!("manifest ContentInfo: {e}")))?;
    let sd: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| Error::Der(format!("manifest SignedData: {e}")))?;

    // 1. The signed payload (checksum text file).
    let econtent = sd
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| Error::Verify("manifest has no encapsulated content".into()))?;
    let payload: OctetString = econtent
        .decode_as()
        .map_err(|e| Error::Der(format!("manifest eContent: {e}")))?;
    let payload = payload.as_bytes().to_vec();

    // 2. Certificates carried in the CMS.
    let mut cms_certs = Vec::new();
    if let Some(set) = &sd.certificates {
        for choice in set.0.iter() {
            if let CertificateChoices::Certificate(cert) = choice {
                let der = cert.to_der().map_err(|e| Error::Der(e.to_string()))?;
                cms_certs.push(CertInfo::from_parsed(cert, &der));
            }
        }
    }

    let signer_info = sd
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or_else(|| Error::Verify("manifest has no SignerInfo".into()))?;

    // 3. Locate the signer's certificate.
    let signer_cert = match &signer_info.sid {
        SignerIdentifier::IssuerAndSerialNumber(isn) => {
            let issuer = isn.issuer.to_string();
            let serial = hex(isn.serial_number.as_bytes());
            cms_certs
                .iter()
                .find(|c| c.issuer == issuer && c.serial == serial)
                .cloned()
        }
        SignerIdentifier::SubjectKeyIdentifier(_) => None,
    }
    .ok_or_else(|| Error::Verify("manifest signer certificate not found in CMS".into()))?;

    // 4. Determine what the signature covers (RFC 5652 §5.4): the DER SET OF
    // signed attributes when present (with a message-digest cross-check), or
    // the eContent octets directly when absent.
    let digest_alg = signer_info.digest_alg.oid.to_string();
    let signed_message: Vec<u8> = match signer_info.signed_attrs.as_ref() {
        Some(signed_attrs) => {
            const ID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
            let digest_attr = signed_attrs
                .iter()
                .find(|a| a.oid.to_string() == ID_MESSAGE_DIGEST)
                .ok_or_else(|| Error::Verify("manifest missing message-digest attribute".into()))?;
            let attr_digest: OctetString = digest_attr
                .values
                .iter()
                .next()
                .ok_or_else(|| Error::Verify("empty message-digest attribute".into()))?
                .decode_as()
                .map_err(|e| Error::Der(format!("message-digest attribute: {e}")))?;
            let payload_digest: Vec<u8> = match digest_alg.as_str() {
                "1.3.14.3.2.26" => sha1::Sha1::digest(&payload).to_vec(),
                "2.16.840.1.101.3.4.2.1" => Sha256::digest(&payload).to_vec(),
                "2.16.840.1.101.3.4.2.2" => Sha384::digest(&payload).to_vec(),
                "2.16.840.1.101.3.4.2.3" => Sha512::digest(&payload).to_vec(),
                other => {
                    return Err(Error::Verify(format!(
                        "unsupported manifest digest {other}"
                    )))
                }
            };
            if attr_digest.as_bytes() != payload_digest.as_slice() {
                return Err(Error::Verify(
                    "manifest message-digest attribute does not match eContent".into(),
                ));
            }
            signed_attrs
                .to_der()
                .map_err(|e| Error::Der(format!("signed attrs re-encode: {e}")))?
        }
        None => payload.clone(),
    };

    // 5. Verify the signature.
    let sig_alg = match signer_info.signature_algorithm.oid.to_string().as_str() {
        // Bare rsaEncryption in SignerInfo means PKCS#1 v1.5 with the digest alg.
        "1.2.840.113549.1.1.1" => match digest_alg.as_str() {
            "1.3.14.3.2.26" => SHA1_WITH_RSA.to_string(),
            "2.16.840.1.101.3.4.2.1" => SHA256_WITH_RSA.to_string(),
            "2.16.840.1.101.3.4.2.2" => SHA384_WITH_RSA.to_string(),
            "2.16.840.1.101.3.4.2.3" => SHA512_WITH_RSA.to_string(),
            other => other.to_string(),
        },
        other => other.to_string(),
    };
    verify_raw_signature(
        &sig_alg,
        &signed_message,
        signer_info.signature.as_bytes(),
        &signer_cert,
    )?;

    // 6. The signer must chain to a pinned DoD root. Draw candidate issuers from
    // the CMS, the bundle, and the embedded DoD root anchors — the last ensures
    // the chain can terminate at a pinned root even when that root is not
    // redelivered in this group's bundle (ECA/JITC/WCF).
    let mut pool = cms_certs.clone();
    pool.extend_from_slice(extra_pool);
    pool.extend(anchor_certs());
    verify_chains_with_pool(std::slice::from_ref(&signer_cert), &pool, true)?;

    // 7. Parse "hash  filename" lines.
    let text = String::from_utf8_lossy(&payload);
    let mut checksums = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        if let (Some(hash), Some(name)) = (parts.next(), parts.next()) {
            checksums.push((name.to_string(), hash.to_lowercase()));
        }
    }
    if checksums.is_empty() {
        return Err(Error::Verify("manifest contained no checksums".into()));
    }
    Ok(Manifest {
        checksums,
        signer: signer_cert.display_name(),
    })
}
