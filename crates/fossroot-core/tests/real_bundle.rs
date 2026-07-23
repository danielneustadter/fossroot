//! Integration tests against a real DISA bundle zip.
//!
//! The bundle is never committed to the repo (see trust design in the README).
//! Point FOSSROOT_TEST_BUNDLE at a downloaded unclass-certificates_pkcs7_DoD.zip
//! to run these; they are skipped otherwise.

use fossroot_core::Bundle;

fn fixture() -> Option<Vec<u8>> {
    let path = std::env::var_os("FOSSROOT_TEST_BUNDLE")?;
    Some(std::fs::read(path).expect("FOSSROOT_TEST_BUNDLE not readable"))
}

#[test]
fn parses_and_verifies_official_zip() {
    let Some(raw) = fixture() else {
        eprintln!("skipped: set FOSSROOT_TEST_BUNDLE to run");
        return;
    };
    let bundle = Bundle::from_zip_bytes(&raw, "test-fixture").expect("bundle should verify");
    assert!(
        bundle.certs.len() >= 40,
        "expected a full bundle, got {}",
        bundle.certs.len()
    );
    assert!(
        bundle.verify.manifest_signed,
        "manifest must be CMS-verified"
    );
    assert!(
        bundle
            .verify
            .anchored_roots
            .iter()
            .any(|r| r.contains("Root CA 3")),
        "DoD Root CA 3 should anchor the bundle"
    );
    assert!(!bundle.version.is_empty() && bundle.version != "unknown");
    // Roots go to ROOT, intermediates to CA — sanity check both exist.
    assert!(bundle.certs.iter().any(|c| c.is_self_issued));
    assert!(bundle.certs.iter().any(|c| !c.is_self_issued));
}

/// Rebuild the official zip with one entry's bytes altered.
fn rezip_with_tamper(raw: &[u8], target_suffix: &str) -> Vec<u8> {
    use std::io::{Cursor, Read, Write};
    let mut src = zip::ZipArchive::new(Cursor::new(raw)).unwrap();
    let mut out = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for i in 0..src.len() {
        let mut entry = src.by_index(i).unwrap();
        let name = entry.name().to_string();
        let mut data = Vec::new();
        entry.read_to_end(&mut data).unwrap();
        if name.ends_with(target_suffix) {
            let mid = data.len() / 2;
            data[mid] ^= 0xFF;
        }
        out.start_file::<_, ()>(name, zip::write::FileOptions::default())
            .unwrap();
        out.write_all(&data).unwrap();
    }
    out.finish().unwrap().into_inner()
}

#[test]
fn rejects_tampered_certificates() {
    let Some(raw) = fixture() else {
        eprintln!("skipped: set FOSSROOT_TEST_BUNDLE to run");
        return;
    };
    // Corrupting the certificate payload must trip the signed-manifest checksum
    // (or DER parsing) — either way, fail closed.
    let tampered = rezip_with_tamper(&raw, ".der.p7b");
    assert!(
        Bundle::from_zip_bytes(&tampered, "tampered-p7b").is_err(),
        "tampered certificate payload must be rejected"
    );
}

#[test]
fn rejects_tampered_manifest() {
    let Some(raw) = fixture() else {
        eprintln!("skipped: set FOSSROOT_TEST_BUNDLE to run");
        return;
    };
    let tampered = rezip_with_tamper(&raw, ".sha256");
    assert!(
        Bundle::from_zip_bytes(&tampered, "tampered-manifest").is_err(),
        "tampered manifest must be rejected"
    );
}
