//! Chiffrement authentifié des données avec XChaCha20-Poly1305.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroizing;

use super::CryptoError;

/// Taille du nonce en octets : 192 bits.
pub const NONCE_SIZE: usize = 24;

/// Données chiffrées et nonce associé.
#[derive(Debug)]
pub struct SealedData {
    pub nonce: [u8; NONCE_SIZE],
    pub ciphertext: Vec<u8>,
}

/// Chiffre des données avec un nonce aléatoire.
///
/// Les données associées sont authentifiées, mais non chiffrées.
pub fn seal(
    key: &[u8; 32],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<SealedData, CryptoError> {
    let mut nonce = [0u8; NONCE_SIZE];

    getrandom::fill(&mut nonce).map_err(|_| CryptoError::RandomGenerationFailed)?;

    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidParameters)?;

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(SealedData { nonce, ciphertext })
}

/// Déchiffre et authentifie les données.
///
/// Aucun texte clair n'est retourné si l'authentification échoue.
/// Le résultat est automatiquement effacé lors de sa destruction.
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidParameters)?;

    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_and_decryption_roundtrip() {
        let key = [7u8; 32];
        let message = b"Confidential TGLDS document";
        let aad = b"TGDS-TEST-V1";

        let encrypted = seal(&key, message, aad).unwrap();
        let decrypted = open(&key, &encrypted.nonce, &encrypted.ciphertext, aad).unwrap();

        assert_eq!(&*decrypted, message);
    }

    #[test]
    fn different_encryptions_use_different_nonces() {
        let key = [7u8; 32];

        let first = seal(&key, b"Same message", b"test").unwrap();
        let second = seal(&key, b"Same message", b"test").unwrap();

        assert_ne!(first.nonce, second.nonce);
    }

    #[test]
    fn wrong_key_is_rejected() {
        let key = [7u8; 32];
        let wrong_key = [8u8; 32];

        let encrypted = seal(&key, b"secret", b"metadata").unwrap();

        assert_eq!(
            open(
                &wrong_key,
                &encrypted.nonce,
                &encrypted.ciphertext,
                b"metadata"
            )
            .unwrap_err(),
            CryptoError::AuthenticationFailed
        );
    }

    #[test]
    fn modified_ciphertext_is_rejected() {
        let key = [7u8; 32];
        let mut encrypted = seal(&key, b"secret data", b"metadata").unwrap();

        encrypted.ciphertext[0] ^= 1;

        assert_eq!(
            open(&key, &encrypted.nonce, &encrypted.ciphertext, b"metadata").unwrap_err(),
            CryptoError::AuthenticationFailed
        );
    }

    #[test]
    fn wrong_associated_data_is_rejected() {
        let key = [7u8; 32];

        let encrypted = seal(&key, b"secret", b"correct metadata").unwrap();

        assert_eq!(
            open(
                &key,
                &encrypted.nonce,
                &encrypted.ciphertext,
                b"wrong metadata"
            )
            .unwrap_err(),
            CryptoError::AuthenticationFailed
        );
    }
}
