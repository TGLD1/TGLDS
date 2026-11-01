//! Gestion de la clé de données et de son enveloppe cryptographique.

use zeroize::Zeroizing;

use super::{
    derive_key, generate_salt, open, seal, CryptoError, KEY_SIZE, SALT_SIZE,
};

/// Données authentifiées utilisées pour protéger la clé de données.
const KEY_ENVELOPE_AAD: &[u8] = b"TGLDS-KEY-ENVELOPE-V1";

/// Taille attendue de la clé protégée, avec son tag d'authentification.
const WRAPPED_KEY_SIZE: usize = KEY_SIZE + 16;

/// Enveloppe contenant les éléments nécessaires à la récupération de la DEK.
#[derive(Debug, PartialEq, Eq)]
pub struct KeyEnvelope {
    pub salt: [u8; SALT_SIZE],
    pub nonce: [u8; 24],
    pub wrapped_key: Vec<u8>,
}

/// Génère une DEK aléatoire et la protège avec le mot de passe.
pub fn create_key_envelope(
    password: &[u8],
) -> Result<(Zeroizing<[u8; KEY_SIZE]>, KeyEnvelope), CryptoError> {
    let mut data_key = Zeroizing::new([0u8; KEY_SIZE]);

    getrandom::fill(&mut *data_key)
        .map_err(|_| CryptoError::RandomGenerationFailed)?;

    let salt = generate_salt()?;
    let kek = derive_key(password, &salt)?;

    let sealed = seal(&kek, &data_key[..], KEY_ENVELOPE_AAD)?;

    let envelope = KeyEnvelope {
        salt,
        nonce: sealed.nonce,
        wrapped_key: sealed.ciphertext,
    };

    Ok((data_key, envelope))
}

/// Récupère et authentifie la DEK à partir du mot de passe.
pub fn unlock_data_key(
    password: &[u8],
    envelope: &KeyEnvelope,
) -> Result<Zeroizing<[u8; KEY_SIZE]>, CryptoError> {
    if envelope.wrapped_key.len() != WRAPPED_KEY_SIZE {
        return Err(CryptoError::InvalidEnvelope);
    }

    let kek = derive_key(password, &envelope.salt)?;

    let plaintext = open(
        &kek,
        &envelope.nonce,
        &envelope.wrapped_key,
        KEY_ENVELOPE_AAD,
    )?;

    let key_bytes: [u8; KEY_SIZE] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidEnvelope)?;

    Ok(Zeroizing::new(key_bytes))
}

/// Change le mot de passe sans modifier la DEK ni rechiffrer les fichiers.
pub fn change_password(
    old_password: &[u8],
    new_password: &[u8],
    envelope: &KeyEnvelope,
) -> Result<KeyEnvelope, CryptoError> {
    let data_key = unlock_data_key(old_password, envelope)?;

    let new_salt = generate_salt()?;
    let new_kek = derive_key(new_password, &new_salt)?;

    let sealed = seal(&new_kek, &data_key[..], KEY_ENVELOPE_AAD)?;

    Ok(KeyEnvelope {
        salt: new_salt,
        nonce: sealed.nonce,
        wrapped_key: sealed.ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_data_key_can_be_recovered() {
        let (original_key, envelope) =
            create_key_envelope(b"mot-de-passe-solide").unwrap();

        let recovered_key =
            unlock_data_key(b"mot-de-passe-solide", &envelope).unwrap();

        assert_eq!(&*original_key, &*recovered_key);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let (_, envelope) =
            create_key_envelope(b"mot-de-passe-correct").unwrap();

        let result = unlock_data_key(b"mauvais-mot-de-passe", &envelope);

        assert_eq!(
            result.unwrap_err(),
            CryptoError::AuthenticationFailed
        );
    }

    #[test]
    fn modified_envelope_is_rejected() {
        let (_, mut envelope) =
            create_key_envelope(b"mot-de-passe-solide").unwrap();

        envelope.wrapped_key[0] ^= 1;

        let result = unlock_data_key(b"mot-de-passe-solide", &envelope);

        assert_eq!(
            result.unwrap_err(),
            CryptoError::AuthenticationFailed
        );
    }

    #[test]
    fn password_change_preserves_the_data_key() {
        let (original_key, old_envelope) =
            create_key_envelope(b"ancien-mot-de-passe").unwrap();

        let new_envelope = change_password(
            b"ancien-mot-de-passe",
            b"nouveau-mot-de-passe",
            &old_envelope,
        )
        .unwrap();

        let recovered_key =
            unlock_data_key(b"nouveau-mot-de-passe", &new_envelope).unwrap();

        assert_eq!(&*original_key, &*recovered_key);

        assert_eq!(
            unlock_data_key(b"ancien-mot-de-passe", &new_envelope)
                .unwrap_err(),
            CryptoError::AuthenticationFailed
        );
    }

    #[test]
    fn empty_new_password_is_rejected() {
        let (_, envelope) =
            create_key_envelope(b"ancien-mot-de-passe").unwrap();

        let result = change_password(
            b"ancien-mot-de-passe",
            b"",
            &envelope,
        );

        assert_eq!(
            result.unwrap_err(),
            CryptoError::InvalidParameters
        );
    }
}
