//! PDF signature support for the FossRoot Signer.
//!
//! Two capabilities:
//! - [`fields`] — read-only enumeration of AcroForm signature fields (name,
//!   page, rectangle, already-signed?), powering the extension's field overlay
//!   and the agent's `pdf_sig_fields` RPC.
//! - [`sign`] — apply a CMS `adbe.pkcs7.detached` signature into an existing
//!   signature field as an **incremental update**, so any prior signatures stay
//!   valid. The private-key operation is abstracted behind [`sign::Signer`] so
//!   the same code path serves the cardless test key and the real CAC (CNG).

pub mod fields;
pub mod sign;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("PDF parse error: {0}")]
    Pdf(String),
    #[error("no signature field named '{0}'")]
    FieldNotFound(String),
    #[error("signature field '{0}' is already signed")]
    AlreadySigned(String),
    #[error("the document has no AcroForm signature fields")]
    NoSignatureFields,
    #[error("signing error: {0}")]
    Sign(String),
    #[error("reserved /Contents space too small: need {need}, have {have}")]
    ContentsTooSmall { need: usize, have: usize },
}

pub type Result<T> = std::result::Result<T, Error>;
