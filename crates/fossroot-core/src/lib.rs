//! Fossroot core: fetch, verify, parse, and diff DoD PKI CA certificate bundles.
//!
//! Trust model:
//! - Certificate bundles are always fetched live from DISA's official distribution
//!   point (or supplied by the user as a file). No certificates ship in this crate.
//! - The bundle's CMS-signed checksum manifest is verified against DoD root CAs
//!   whose SHA-256 fingerprints are pinned in [`verify`].
//! - Every certificate in a bundle must chain (with signature verification) to a
//!   pinned root, or the bundle is rejected.

pub mod bundle;
pub mod certs;
pub mod diff;
pub mod store;
pub mod verify;

pub use bundle::{Bundle, Group, DOD_BUNDLE_URL};
pub use certs::CertInfo;
pub use diff::{CertStatus, DiffEntry, DiffReport};
pub use store::{InstalledCert, Location, StoreKind, SystemStore, TrustStore};

/// Errors produced by fossroot-core.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("network error fetching bundle: {0}")]
    Network(String),
    #[error("bundle zip error: {0}")]
    Zip(String),
    #[error("bundle is missing expected file: {0}")]
    MissingFile(String),
    #[error("ASN.1/DER parse error: {0}")]
    Der(String),
    #[error("bundle verification failed: {0}")]
    Verify(String),
    #[error("certificate store error: {0}")]
    Store(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
