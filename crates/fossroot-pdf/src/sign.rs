//! CMS `adbe.pkcs7.detached` signing of an AcroForm signature field, applied as
//! an incremental update so any prior signatures stay valid.
//!
//! Flow (the standard PAdES approach):
//! 1. Append a revision that sets the field's `/V` to a new signature dict whose
//!    `/Contents` is a fixed-width hex placeholder and `/ByteRange` is a
//!    fixed-width numeric placeholder — written *before* `/Contents` is filled.
//! 2. Locate `/Contents` in the serialized bytes, compute the real `/ByteRange`
//!    (everything except the Contents hex), and rewrite it in place (same width).
//! 3. SHA-256 the ByteRange bytes, build a detached CMS SignedData over that
//!    digest via [`Signer`], hex-encode it, and splice it into the placeholder.
//!
//! The private-key operation is abstracted by [`Signer`] so the identical
//! pipeline serves the cardless test key and the real CAC (CNG, in the agent).

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use const_oid::db::rfc5911::{ID_DATA, ID_SIGNED_DATA};
use const_oid::db::rfc5912::{ID_SHA_256, RSA_ENCRYPTION};
use const_oid::db::rfc6268::{ID_CONTENT_TYPE, ID_MESSAGE_DIGEST, ID_SIGNING_TIME};
use der::asn1::{SetOfVec, UtcTime};
use der::{Any, Decode, Encode, Tag};
use lopdf::{Dictionary, Document, IncrementalDocument, Object};
use sha2::{Digest, Sha256};
use x509_cert::attr::{Attribute, AttributeValue};
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::time::Time;
use x509_cert::Certificate;

use crate::{Error, Result};

/// ECDSA-with-SHA-256 signature OID.
const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";

/// Signing algorithm of the signer's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAlg {
    RsaPkcs1Sha256,
    EcdsaP256Sha256,
}

/// Abstracts the private-key operation so the same signing pipeline serves the
/// cardless test key (ephemeral RSA) and the real CAC (Windows CNG in the agent).
pub trait Signer {
    /// The signer's own certificate, DER-encoded.
    fn certificate_der(&self) -> Vec<u8>;
    /// Any intermediate CA certificates, DER-encoded, leaf-first.
    fn chain_der(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }
    /// Sign `message` — the signer computes the digest per [`Self::algorithm`]
    /// (RSA PKCS#1 v1.5 over SHA-256, or ECDSA over SHA-256) and returns the
    /// raw signature bytes.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;
    fn algorithm(&self) -> SigAlg;
}

/// Hex placeholder length for `/Contents` (in hex chars). 16384 chars = 8192
/// signature bytes — comfortably fits an RSA-4096 CMS with a full chain.
const CONTENTS_HEX_LEN: usize = 16384;
/// Fixed width for each `/ByteRange` slot (10 digits covers files to ~10 GB).
const BR_WIDTH: usize = 10;

/// Sign `field_name` in `pdf` and return the new (incrementally updated) PDF.
pub fn sign_into_field(
    pdf: &[u8],
    field_name: &str,
    signer: &dyn Signer,
    reason: Option<&str>,
) -> Result<Vec<u8>> {
    let field = crate::fields::find(pdf, field_name)?;
    if field.signed {
        return Err(Error::AlreadySigned(field_name.to_string()));
    }

    let prev = Document::load_mem(pdf).map_err(|e| Error::Pdf(e.to_string()))?;
    let field_id = find_field_id(&prev, field_name)
        .ok_or_else(|| Error::FieldNotFound(field_name.to_string()))?;
    let sig_id = (prev.max_id + 1, 0);

    let mut inc = IncrementalDocument::create_from(pdf.to_vec(), prev);

    // Clone the field object into the new revision and point it at the sig dict.
    inc.opt_clone_object_to_new_document(field_id)
        .map_err(|e| Error::Pdf(e.to_string()))?;
    inc.new_document
        .get_object_mut(field_id)
        .and_then(Object::as_dict_mut)
        .map_err(|e| Error::Pdf(e.to_string()))?
        .set("V", Object::Reference(sig_id));

    // Build the signature dictionary. /Contents is inserted *before* /ByteRange
    // so filling Contents never shifts the ByteRange bytes, and vice-versa.
    let mut sig = Dictionary::new();
    sig.set("Type", Object::Name(b"Sig".to_vec()));
    sig.set("Filter", Object::Name(b"Adobe.PPKLite".to_vec()));
    sig.set("SubFilter", Object::Name(b"adbe.pkcs7.detached".to_vec()));
    sig.set(
        "Contents",
        Object::String(
            vec![0u8; CONTENTS_HEX_LEN / 2],
            lopdf::StringFormat::Hexadecimal,
        ),
    );
    // Placeholder max-width slots; slot 0 stays 0, slots 1..3 get rewritten.
    let nines: i64 = 9_999_999_999;
    sig.set(
        "ByteRange",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(nines),
            Object::Integer(nines),
            Object::Integer(nines),
        ]),
    );
    sig.set("M", Object::string_literal(pdf_date_now()));
    if let Some(r) = reason {
        sig.set("Reason", Object::string_literal(r.to_string()));
    }
    inc.new_document.set_object(sig_id, Object::Dictionary(sig));

    // Serialize the appended revision.
    let mut out = Vec::new();
    inc.save_to(&mut out)
        .map_err(|e| Error::Pdf(e.to_string()))?;

    // Locate the Contents hex string `<...>` we just wrote (a long run of "00").
    let (c_lt, c_gt) = locate_contents(&out)?;
    // ByteRange excludes the Contents value including the enclosing < >.
    let a = c_lt; // offset of '<'
    let b = c_gt + 1; // offset just past '>'
    let c = out.len() - b;
    rewrite_byte_range(&mut out, a as i64, b as i64, c as i64)?;

    // Digest everything except the Contents hex, then build the CMS.
    let mut hasher = Sha256::new();
    hasher.update(&out[..a]);
    hasher.update(&out[b..]);
    let digest: [u8; 32] = hasher.finalize().into();

    let cms = build_cms(&digest, signer)?;
    let hex = to_hex(&cms);
    if hex.len() > CONTENTS_HEX_LEN {
        return Err(Error::ContentsTooSmall {
            need: hex.len(),
            have: CONTENTS_HEX_LEN,
        });
    }
    // Fill the placeholder zeros between < and > with the signature hex (the
    // remainder stays '0', valid padding inside a PDF hex string).
    out[c_lt + 1..c_lt + 1 + hex.len()].copy_from_slice(hex.as_bytes());

    Ok(out)
}

/// Find the object id of a signature field by fully-qualified name.
fn find_field_id(doc: &Document, name: &str) -> Option<lopdf::ObjectId> {
    fn walk(
        doc: &Document,
        id: lopdf::ObjectId,
        parent: Option<&str>,
        target: &str,
    ) -> Option<lopdf::ObjectId> {
        let dict = doc.get_dictionary(id).ok()?;
        let partial = dict
            .get(b"T")
            .ok()
            .and_then(|o| o.as_str().ok())
            .map(|s| String::from_utf8_lossy(s).into_owned());
        let full = match (parent, &partial) {
            (Some(p), Some(t)) => format!("{p}.{t}"),
            (None, Some(t)) => t.clone(),
            (Some(p), None) => p.to_string(),
            (None, None) => String::new(),
        };
        if let Ok(Object::Array(kids)) = dict.get(b"Kids") {
            for k in kids {
                if let Object::Reference(kid) = k {
                    if let Some(found) = walk(doc, *kid, Some(&full), target) {
                        return Some(found);
                    }
                }
            }
            return None;
        }
        if full == target && dict.get(b"FT").ok().and_then(|o| o.as_name().ok()) == Some(b"Sig") {
            return Some(id);
        }
        None
    }

    let acroform = doc
        .catalog()
        .ok()?
        .get(b"AcroForm")
        .ok()
        .and_then(|o| match o {
            Object::Dictionary(d) => Some(d.clone()),
            Object::Reference(id) => doc.get_dictionary(*id).ok().cloned(),
            _ => None,
        })?;
    if let Ok(Object::Array(fields)) = acroform.get(b"Fields") {
        for f in fields {
            if let Object::Reference(id) = f {
                if let Some(found) = walk(doc, *id, None, name) {
                    return Some(found);
                }
            }
        }
    }
    None
}

/// Find the `<`/`>` byte offsets of the signature `/Contents` hex string.
fn locate_contents(bytes: &[u8]) -> Result<(usize, usize)> {
    let key = b"/Contents";
    // Search from the end — the signature dict is in the appended revision.
    let start =
        find_last(bytes, key).ok_or_else(|| Error::Sign("no /Contents in output".into()))?;
    let lt = start
        + key.len()
        + bytes[start + key.len()..]
            .iter()
            .position(|&b| b == b'<')
            .ok_or_else(|| Error::Sign("no '<' after /Contents".into()))?;
    let gt = lt
        + bytes[lt..]
            .iter()
            .position(|&b| b == b'>')
            .ok_or_else(|| Error::Sign("no '>' after /Contents".into()))?;
    Ok((lt, gt))
}

/// Overwrite the three non-zero ByteRange slots (fixed width) in place.
fn rewrite_byte_range(bytes: &mut [u8], a: i64, b: i64, c: i64) -> Result<()> {
    let key = b"/ByteRange";
    let ks = find_last(bytes, key).ok_or_else(|| Error::Sign("no /ByteRange in output".into()))?;
    let lb = ks
        + bytes[ks..]
            .iter()
            .position(|&b| b == b'[')
            .ok_or_else(|| Error::Sign("no '[' after /ByteRange".into()))?;
    let rb = lb
        + bytes[lb..]
            .iter()
            .position(|&b| b == b']')
            .ok_or_else(|| Error::Sign("no ']' after /ByteRange".into()))?;
    let formatted = format!(
        "[0 {a:0BR_WIDTH$} {b:0BR_WIDTH$} {c:0BR_WIDTH$}]",
        BR_WIDTH = BR_WIDTH
    );
    let slot = &mut bytes[lb..=rb];
    if formatted.len() != slot.len() {
        return Err(Error::Sign(format!(
            "ByteRange width mismatch: placeholder {} vs formatted {}",
            slot.len(),
            formatted.len()
        )));
    }
    slot.copy_from_slice(formatted.as_bytes());
    Ok(())
}

fn find_last(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .rev()
        .find(|&i| &haystack[i..i + needle.len()] == needle)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn pdf_date_now() -> String {
    chrono::Utc::now().format("D:%Y%m%d%H%M%SZ").to_string()
}

/// Build a detached CMS SignedData (DER) over `digest`, signed via `signer`.
fn build_cms(digest: &[u8; 32], signer: &dyn Signer) -> Result<Vec<u8>> {
    let cert_der = signer.certificate_der();
    let cert = Certificate::from_der(&cert_der).map_err(|e| Error::Sign(e.to_string()))?;

    let sha256_alg = AlgorithmIdentifierOwned {
        oid: ID_SHA_256,
        parameters: None,
    };

    // Signed attributes: contentType, messageDigest, signingTime.
    let content_type_attr = attribute(ID_CONTENT_TYPE, Any::from(ID_DATA))?;
    let md_attr = attribute(
        ID_MESSAGE_DIGEST,
        Any::new(Tag::OctetString, digest.as_slice()).map_err(|e| Error::Sign(e.to_string()))?,
    )?;
    let now = UtcTime::from_unix_duration(std::time::Duration::from_secs(
        chrono::Utc::now().timestamp() as u64,
    ))
    .map_err(|e| Error::Sign(e.to_string()))?;
    let time_attr = attribute(
        ID_SIGNING_TIME,
        Any::encode_from(&Time::UtcTime(now)).map_err(|e| Error::Sign(e.to_string()))?,
    )?;

    let mut attrs: SetOfVec<Attribute> = SetOfVec::new();
    for a in [content_type_attr, md_attr, time_attr] {
        attrs.insert(a).map_err(|e| Error::Sign(e.to_string()))?;
    }
    // Signature is over the DER SET OF signed attributes.
    let attrs_der = attrs.to_der().map_err(|e| Error::Sign(e.to_string()))?;
    let signature = signer.sign(&attrs_der)?;

    let sig_alg = match signer.algorithm() {
        SigAlg::RsaPkcs1Sha256 => AlgorithmIdentifierOwned {
            oid: RSA_ENCRYPTION,
            parameters: Some(Any::null()),
        },
        SigAlg::EcdsaP256Sha256 => AlgorithmIdentifierOwned {
            oid: ECDSA_WITH_SHA256.parse().unwrap(),
            parameters: None,
        },
    };

    let signer_info = SignerInfo {
        version: cms::content_info::CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
            issuer: cert.tbs_certificate.issuer.clone(),
            serial_number: cert.tbs_certificate.serial_number.clone(),
        }),
        digest_alg: sha256_alg.clone(),
        signed_attrs: Some(attrs),
        signature_algorithm: sig_alg,
        signature: der::asn1::OctetString::new(signature)
            .map_err(|e| Error::Sign(e.to_string()))?,
        unsigned_attrs: None,
    };

    // Certificate set: signer leaf + any chain.
    let mut cert_choices = vec![CertificateChoices::Certificate(cert)];
    for extra in signer.chain_der() {
        let c = Certificate::from_der(&extra).map_err(|e| Error::Sign(e.to_string()))?;
        cert_choices.push(CertificateChoices::Certificate(c));
    }
    let cert_set =
        CertificateSet(SetOfVec::from_iter(cert_choices).map_err(|e| Error::Sign(e.to_string()))?);

    let signed_data = SignedData {
        version: cms::content_info::CmsVersion::V1,
        digest_algorithms: SetOfVec::try_from(vec![sha256_alg])
            .map_err(|e| Error::Sign(e.to_string()))?,
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: ID_DATA,
            econtent: None,
        },
        certificates: Some(cert_set),
        crls: None,
        signer_infos: SignerInfos(
            SetOfVec::try_from(vec![signer_info]).map_err(|e| Error::Sign(e.to_string()))?,
        ),
    };

    let ci = ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: Any::encode_from(&signed_data).map_err(|e| Error::Sign(e.to_string()))?,
    };
    ci.to_der().map_err(|e| Error::Sign(e.to_string()))
}

fn attribute(oid: der::asn1::ObjectIdentifier, value: AttributeValue) -> Result<Attribute> {
    let mut values: SetOfVec<AttributeValue> = SetOfVec::new();
    values
        .insert(value)
        .map_err(|e| Error::Sign(e.to_string()))?;
    Ok(Attribute { oid, values })
}
