use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use super::CryptoError;

pub const KEY_SIZE: usize = 32;
pub const SALT_SIZE: usize = 16;

const MEMORY_KIB: u32 = 64 * 1024;
const ITERATIONS: u32 = 3;
const PARALLELISM: u32 = 1;

pub fn generate_salt() -> Result<[u8; SALT_SIZE], CryptoError> {
    let mut salt = [0u8; SALT_SIZE];

    getrandom::fill(&mut salt)
        .map_err(|_| CryptoError::RandomGenerationFailed)?;

    Ok(salt)
}

pub fn derive_key(
    password: &[u8],
    salt: &[u8; SALT_SIZE],
) -> Result<Zeroizing<[u8; KEY_SIZE]>, CryptoError> {

    if password.is_empty() {
        return Err(CryptoError::InvalidParameters);
    }

    let params = Params::new(
        MEMORY_KIB,
        ITERATIONS,
        PARALLELISM,
        Some(KEY_SIZE),
    )
    .map_err(|_| CryptoError::InvalidParameters)?;

    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        params,
    );

    let mut key = Zeroizing::new([0u8; KEY_SIZE]);

    argon2
        .hash_password_into(password, salt, &mut *key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_password_and_salt_produce_same_key() {
        let salt = [42u8; SALT_SIZE];

        let key1 = derive_key(b"test-password", &salt).unwrap();
        let key2 = derive_key(b"test-password", &salt).unwrap();

        assert_eq!(&*key1, &*key2);
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let salt1 = [1u8; SALT_SIZE];
        let salt2 = [2u8; SALT_SIZE];

        let key1 = derive_key(b"test-password", &salt1).unwrap();
        let key2 = derive_key(b"test-password", &salt2).unwrap();

        assert_ne!(&*key1, &*key2);
    }

    #[test]
    fn empty_password_is_rejected() {
        let salt = [1u8; SALT_SIZE];

        assert_eq!(
            derive_key(b"", &salt).unwrap_err(),
            CryptoError::InvalidParameters
        );
    }

    #[test]
    fn generated_salts_are_distinct() {
        let salt1 = generate_salt().unwrap();
        let salt2 = generate_salt().unwrap();

        assert_ne!(salt1, salt2);
    }
}
