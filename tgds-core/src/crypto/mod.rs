//! Moteur cryptographique de TGLDS.
//!
//! Primitives initiales :
//! - Dérivation des clés avec Argon2id.
//! - Chiffrement authentifié avec XChaCha20-Poly1305.
//! - Génération cryptographique de nombres aléatoires.
//! - Protection de la clé de données avec une enveloppe cryptographique.

mod encryption;
mod key_envelope;
mod kdf;

pub use encryption::{open, seal, SealedData};
pub use key_envelope::{
    change_password, create_key_envelope, unlock_data_key, KeyEnvelope,
};
pub use kdf::{derive_key, generate_salt, KEY_SIZE, SALT_SIZE};

/// Erreurs possibles du moteur cryptographique.
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    InvalidParameters,
    InvalidEnvelope,
    KeyDerivationFailed,
    RandomGenerationFailed,
    EncryptionFailed,
    AuthenticationFailed,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Échec d'une opération cryptographique TGLDS : {:?}", self)
    }
}

impl std::error::Error for CryptoError {}
