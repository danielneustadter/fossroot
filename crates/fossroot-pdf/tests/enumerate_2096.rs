//! Enumeration against the real DAF 2096 template (local fixture, not committed).
//! Point FOSSROOT_TEST_PDF at daf2096_blank.pdf to run.

use fossroot_pdf::fields;

#[test]
fn enumerate_real_2096() {
    let Some(path) = std::env::var_os("FOSSROOT_TEST_PDF") else {
        eprintln!("skipped: set FOSSROOT_TEST_PDF to the 2096 template");
        return;
    };
    let pdf = std::fs::read(path).expect("read 2096");
    let fields = fields::enumerate(&pdf).expect("enumerate");
    for f in &fields {
        eprintln!(
            "  {:50} page={} signed={} rect={:?}",
            f.name, f.page, f.signed, f.rect
        );
    }
    // The exploration confirmed the 2096 has exactly 4 /Sig fields.
    assert_eq!(fields.len(), 4, "expected 4 signature fields on the 2096");
    assert!(fields
        .iter()
        .any(|f| f.name.contains("SIGNATURE_OF_MEMBER")));
    assert!(
        fields.iter().all(|f| !f.signed),
        "blank template is unsigned"
    );
}
