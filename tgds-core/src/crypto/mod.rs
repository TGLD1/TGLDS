//! TGLDS cryptographic engine.
//!
//! Initial primitives:
//! - Argon2id key derivation
//! - XChaCha20-Poly1305 authenticated encryption
//! - Secure random generation

mod encryption;
mod kdf;

pub use encryption::{open, seal, SealedData};
pub use kdf::{derive_key, generate_salt, KEY_SIZE, SALT_SIZE};

#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    InvalidParameters,
    KeyDerivationFailed,
    RandomGenerationFailed,
    EncryptionFailed,
    AuthenticationFailed,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TGDS cryptographic operation failed: {:?}", self)
    }
}

impl std::error::Error for CryptoError {}
