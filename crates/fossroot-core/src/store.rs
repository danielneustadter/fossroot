//! Platform trust-store abstraction. Windows now; macOS/Linux later.

use crate::Result;

#[cfg(windows)]
pub mod windows;

/// Which physical store location to operate on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Location {
    CurrentUser,
    LocalMachine,
}

/// Which logical store: trusted roots or intermediate CAs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreKind {
    /// Windows "ROOT" store (trusted root certification authorities).
    Root,
    /// Windows "CA" store (intermediate certification authorities).
    Ca,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemStore {
    pub location: Location,
    pub kind: StoreKind,
}

/// A certificate as found in a platform store.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InstalledCert {
    pub subject: String,
    #[serde(serialize_with = "ser_hex")]
    pub sha1: [u8; 20],
    pub not_after: i64,
}

fn ser_hex<S: serde::Serializer>(b: &[u8; 20], s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&crate::certs::hex(b))
}

/// Read/write access to a platform trust store.
pub trait TrustStore {
    fn list(&self, store: SystemStore) -> Result<Vec<InstalledCert>>;
    fn add(&self, store: SystemStore, der: &[u8]) -> Result<()>;
    /// Returns true if a certificate was found and removed.
    fn remove_by_sha1(&self, store: SystemStore, sha1: &[u8; 20]) -> Result<bool>;
}

/// The trust store implementation for the current platform.
#[cfg(windows)]
pub fn platform() -> impl TrustStore {
    windows::WindowsStore
}
