//! Windows CurrentUser store add/remove roundtrip.
//!
//! Mutates the current user's CA (intermediate) store — never ROOT, so no
//! Windows security prompt is involved — and cleans up after itself.
//! Gated behind FOSSROOT_STORE_TEST=1 in addition to the bundle fixture,
//! so plain `cargo test` stays side-effect free.

#![cfg(windows)]

use fossroot_core::store::{platform, Location, StoreKind, SystemStore, TrustStore};
use fossroot_core::Bundle;

#[test]
fn current_user_ca_roundtrip() {
    if std::env::var_os("FOSSROOT_STORE_TEST").is_none() {
        eprintln!("skipped: set FOSSROOT_STORE_TEST=1 (and FOSSROOT_TEST_BUNDLE) to run");
        return;
    }
    let raw = std::fs::read(std::env::var_os("FOSSROOT_TEST_BUNDLE").expect("fixture env"))
        .expect("fixture readable");
    let bundle = Bundle::from_zip_bytes(&raw, "fixture").expect("bundle verifies");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let cert = bundle
        .certs
        .iter()
        .find(|c| !c.is_self_issued && !c.is_expired(now))
        .expect("bundle has a live intermediate");

    let store = platform();
    let target = SystemStore {
        location: Location::CurrentUser,
        kind: StoreKind::Ca,
    };

    let present = |s: &dyn Fn() -> Vec<fossroot_core::InstalledCert>| {
        s().iter().any(|i| i.sha1 == cert.sha1)
    };
    let listing = || store.list(target).expect("list CA store");

    // If a previous failed run left it behind, clean first.
    let _ = store.remove_by_sha1(target, &cert.sha1);
    assert!(!present(&listing), "precondition: cert absent");

    store.add(target, &cert.der).expect("add to CurrentUser CA");
    assert!(present(&listing), "cert present after add");

    assert!(store.remove_by_sha1(target, &cert.sha1).expect("remove"));
    assert!(!present(&listing), "cert gone after remove");
    assert!(
        !store.remove_by_sha1(target, &cert.sha1).expect("second remove"),
        "second remove reports not found"
    );
}
