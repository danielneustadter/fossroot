//! CMS `adbe.pkcs7.detached` incremental-update signing. (Implementation lands
//! after field enumeration is verified.)

/// Signing algorithm of the signer's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAlg {
    RsaPkcs1Sha256,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
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
    /// Sign `message` (the signer computes the digest per [`Self::algorithm`]).
    fn sign(&self, message: &[u8]) -> crate::Result<Vec<u8>>;
    fn algorithm(&self) -> SigAlg;
}
