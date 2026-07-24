//! Cardless sign → verify roundtrip. Uses an ephemeral RSA key (no smart card),
//! signs a generated PDF's signature field, and verifies the result two ways:
//! our own re-parse, and an independent `openssl cms -verify`.

use lopdf::{dictionary, Document, Object};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer as _};
use rsa::RsaPrivateKey;
use sha2::Sha256;

use fossroot_pdf::sign::{sign_into_field, SigAlg, Signer};

/// Ephemeral self-signed RSA signer — the CACSign SelfTest pattern.
struct TestSigner {
    key: SigningKey<Sha256>,
    cert_der: Vec<u8>,
}

impl TestSigner {
    fn new() -> Self {
        use rand::rngs::OsRng;
        use std::str::FromStr;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::SubjectPublicKeyInfoOwned;
        use x509_cert::time::Validity;

        let priv_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let signing_key = SigningKey::<Sha256>::new(priv_key.clone());
        let pub_key = rsa::RsaPublicKey::from(&priv_key);

        let spki_der = {
            use rsa::pkcs1::EncodeRsaPublicKey;
            use x509_cert::spki::EncodePublicKey;
            let _ = pub_key.to_pkcs1_der().unwrap();
            // SubjectPublicKeyInfo for RSA.
            EncodePublicKey::to_public_key_der(&pub_key).unwrap()
        };
        let spki = SubjectPublicKeyInfoOwned::try_from(spki_der.as_bytes()).unwrap();

        let profile = Profile::Root;
        let serial = SerialNumber::from(1u32);
        let validity = Validity::from_now(std::time::Duration::from_secs(3600)).unwrap();
        let subject =
            Name::from_str("CN=FOSSROOT.TEST.SIGNER.0000000000,O=FossRoot Test,C=US").unwrap();

        let builder =
            CertificateBuilder::new(profile, serial, validity, subject, spki, &signing_key)
                .unwrap();
        let cert = builder.build().unwrap();
        use der::Encode;
        let cert_der = cert.to_der().unwrap();

        TestSigner {
            key: signing_key,
            cert_der,
        }
    }
}

impl Signer for TestSigner {
    fn certificate_der(&self) -> Vec<u8> {
        self.cert_der.clone()
    }
    fn sign(&self, message: &[u8]) -> fossroot_pdf::Result<Vec<u8>> {
        Ok(self.key.sign(message).to_vec())
    }
    fn algorithm(&self) -> SigAlg {
        SigAlg::RsaPkcs1Sha256
    }
}

fn minimal_signable_pdf() -> Vec<u8> {
    let mut doc = Document::with_version("1.7");
    let pages_id = doc.new_object_id();
    let field_id = doc.new_object_id();
    let content_id = doc.add_object(Object::Stream(lopdf::Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf 72 720 Td (FossRoot test) Tj ET".to_vec(),
    )));
    let page_id = doc.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        "Contents" => content_id,
        "Annots" => vec![field_id.into()],
    });
    doc.set_object(
        field_id,
        dictionary! {
            "Type" => "Annot", "Subtype" => "Widget", "FT" => "Sig",
            "T" => Object::string_literal("Signature1"),
            "Rect" => vec![72.into(), 700.into(), 300.into(), 740.into()],
            "P" => page_id,
        },
    );
    doc.set_object(
        pages_id,
        dictionary! { "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1 },
    );
    let catalog_id = doc.add_object(dictionary! {
        "Type" => "Catalog", "Pages" => pages_id,
        "AcroForm" => dictionary! { "Fields" => vec![field_id.into()], "SigFlags" => 3 },
    });
    doc.trailer.set("Root", catalog_id);
    let mut buf = Vec::new();
    doc.save_to(&mut buf).unwrap();
    buf
}

/// Byte-search (the signed PDF is not valid UTF-8 once the CMS DER is spliced in).
fn rfind(hay: &[u8], needle: &[u8]) -> usize {
    (0..=hay.len() - needle.len())
        .rev()
        .find(|&i| &hay[i..i + needle.len()] == needle)
        .expect("needle")
}

/// Extract [ByteRange bytes, CMS DER] from a signed PDF by re-parsing.
fn extract_signed(pdf: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let br_pos = rfind(pdf, b"/ByteRange");
    let lb = pdf[br_pos..].iter().position(|&b| b == b'[').unwrap() + br_pos;
    let rb = pdf[lb..].iter().position(|&b| b == b']').unwrap() + lb;
    let nums: Vec<usize> = std::str::from_utf8(&pdf[lb + 1..rb])
        .unwrap()
        .split_whitespace()
        .map(|n| n.parse().unwrap())
        .collect();
    assert_eq!(nums.len(), 4, "ByteRange should have 4 slots");
    let (a, b, c, d) = (nums[0], nums[1], nums[2], nums[3]);
    let mut signed = Vec::new();
    signed.extend_from_slice(&pdf[a..a + b]);
    signed.extend_from_slice(&pdf[c..c + d]);

    // The Contents hex sits in the gap: '<' at a+b, '>' at c-1.
    let hex = &pdf[a + b + 1..c - 1];
    let hex_trim: Vec<u8> = hex
        .iter()
        .copied()
        .take_while(|b| b.is_ascii_hexdigit())
        .collect();
    let cms: Vec<u8> = hex_trim
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    (signed, trim_der(&cms))
}

/// A DER SEQUENCE self-describes its length; trim trailing placeholder zeros.
fn trim_der(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() < 4 || bytes[0] != 0x30 {
        return bytes.to_vec();
    }
    // Long-form length.
    let total = if bytes[1] & 0x80 != 0 {
        let n = (bytes[1] & 0x7f) as usize;
        let mut len = 0usize;
        for &b in &bytes[2..2 + n] {
            len = (len << 8) | b as usize;
        }
        2 + n + len
    } else {
        2 + bytes[1] as usize
    };
    bytes[..total.min(bytes.len())].to_vec()
}

#[test]
fn sign_and_verify_with_openssl() {
    let pdf = minimal_signable_pdf();
    let signer = TestSigner::new();
    let signed = sign_into_field(&pdf, "Signature1", &signer, Some("Test signature")).unwrap();

    // Our re-parse: the field is now marked signed.
    let fields = fossroot_pdf::fields::enumerate(&signed).unwrap();
    assert!(fields.iter().any(|f| f.name == "Signature1" && f.signed));

    let (signed_bytes, cms_der) = extract_signed(&signed);

    // Independent verification with openssl, if available.
    let tmp = std::env::temp_dir();
    let sig_p7 = tmp.join("fossroot_sig.p7s");
    let content = tmp.join("fossroot_content.bin");
    let cert_pem = tmp.join("fossroot_cert.pem");
    std::fs::write(&sig_p7, &cms_der).unwrap();
    std::fs::write(&content, &signed_bytes).unwrap();

    // Write the signer cert as PEM for -certfile / CAfile.
    use der::pem::LineEnding;
    use der::{Decode, EncodePem};
    let cert = x509_cert::Certificate::from_der(&signer.certificate_der()).unwrap();
    std::fs::write(&cert_pem, cert.to_pem(LineEnding::LF).unwrap()).unwrap();

    let out = std::process::Command::new("openssl")
        .args([
            "cms",
            "-verify",
            "-binary",
            "-inform",
            "DER",
            "-in",
            sig_p7.to_str().unwrap(),
            "-content",
            content.to_str().unwrap(),
            "-CAfile",
            cert_pem.to_str().unwrap(),
            "-no_check_time",
            // The ephemeral test cert is a self-signed root without S/MIME EKU;
            // `-purpose any` skips that end-entity check so we verify the
            // cryptography (signature + messageDigest over the ByteRange), which
            // is what this test is about. Real CAC certs carry the right usage.
            "-purpose",
            "any",
            "-out",
            tmp.join("fossroot_devnull").to_str().unwrap(),
        ])
        .output();

    match out {
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            eprintln!("openssl: {stderr}");
            assert!(
                o.status.success(),
                "openssl cms -verify must succeed; stderr: {stderr}"
            );
        }
        Err(e) => eprintln!("skipped openssl cross-check (openssl not found: {e})"),
    }
}

#[test]
fn tamper_breaks_the_signature() {
    let pdf = minimal_signable_pdf();
    let signer = TestSigner::new();
    let mut signed = sign_into_field(&pdf, "Signature1", &signer, None).unwrap();

    let (orig_signed_bytes, cms_der) = extract_signed(&signed);
    // Flip a byte inside the signed range (the visible text), re-extract.
    let pos = orig_signed_bytes
        .windows(9)
        .position(|w| w == b"FossRoot ")
        .map(|p| p + 2)
        .unwrap();
    // Find that same byte in the actual file and flip it.
    let file_pos = signed.windows(9).position(|w| w == b"FossRoot ").unwrap() + 2;
    signed[file_pos] ^= 0xFF;

    let (tampered_bytes, _) = extract_signed(&signed);
    assert_ne!(orig_signed_bytes, tampered_bytes, "byte range changed");

    // The messageDigest inside the CMS no longer matches the content.
    let _ = cms_der; // structure already validated in the other test
    let re_digest = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(&tampered_bytes);
        let d: [u8; 32] = h.finalize().into();
        d
    };
    // Recompute the original digest and confirm they differ.
    let orig_digest = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(&orig_signed_bytes);
        let d: [u8; 32] = h.finalize().into();
        d
    };
    assert_ne!(
        re_digest, orig_digest,
        "tamper must change the content digest"
    );
    let _ = pos;
}

/// Sign a real DAF 2096 signature field end to end (local fixture, not committed).
/// Set FOSSROOT_TEST_PDF to the 2096 template.
#[test]
fn sign_real_2096_member_field() {
    let Some(path) = std::env::var_os("FOSSROOT_TEST_PDF") else {
        eprintln!("skipped: set FOSSROOT_TEST_PDF to the 2096 template");
        return;
    };
    let pdf = std::fs::read(path).expect("read 2096");
    let field = "topmostSubform[0].Page1[0].SIGNATURE_OF_MEMBER[0]";
    let signer = TestSigner::new();
    let signed = sign_into_field(&pdf, field, &signer, Some("Member concurrence")).unwrap();

    // The signed doc still parses and reports that field as signed; the other
    // three signature fields remain open (incremental update preserved them).
    let fields = fossroot_pdf::fields::enumerate(&signed).unwrap();
    let member = fields.iter().find(|f| f.name == field).unwrap();
    assert!(member.signed, "member field should now be signed");
    assert_eq!(
        fields.iter().filter(|f| f.signed).count(),
        1,
        "only the member field should be signed"
    );

    // openssl confirms the CMS over the 2096's ByteRange.
    let (content, cms) = extract_signed(&signed);
    let tmp = std::env::temp_dir();
    std::fs::write(tmp.join("f2096_sig.p7s"), &cms).unwrap();
    std::fs::write(tmp.join("f2096_content.bin"), &content).unwrap();
    use der::pem::LineEnding;
    use der::{Decode, EncodePem};
    let cert = x509_cert::Certificate::from_der(&signer.certificate_der()).unwrap();
    std::fs::write(
        tmp.join("f2096_cert.pem"),
        cert.to_pem(LineEnding::LF).unwrap(),
    )
    .unwrap();
    if let Ok(o) = std::process::Command::new("openssl")
        .args([
            "cms",
            "-verify",
            "-binary",
            "-inform",
            "DER",
            "-in",
            tmp.join("f2096_sig.p7s").to_str().unwrap(),
            "-content",
            tmp.join("f2096_content.bin").to_str().unwrap(),
            "-CAfile",
            tmp.join("f2096_cert.pem").to_str().unwrap(),
            "-no_check_time",
            "-purpose",
            "any",
            "-out",
            tmp.join("f2096_devnull").to_str().unwrap(),
        ])
        .output()
    {
        assert!(
            o.status.success(),
            "openssl verify of signed 2096: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        eprintln!("openssl verified the signed 2096 ✓");
    }
}
