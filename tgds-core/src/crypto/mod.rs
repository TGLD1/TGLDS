//! Moteur cryptographique de TGLDS.
//!
//! Primitives initiales :
//! - Dérivation des clés avec Argon2id.
//! - Chiffrement authentifié avec XChaCha20-Poly1305.
//! - Génération cryptographique de nombres aléatoires.

mod encryption;
mod kdf;

pub use encryption::{open, seal, SealedData};
pub use kdf::{derive_key, generate_salt, KEY_SIZE, SALT_SIZE};

/// Erreurs possibles du moteur cryptographique.
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
        write!(f, "Échec d'une opération cryptographique TGDS : {:?}", self)
    }
}

impl std::error::Error for CryptoError {}
