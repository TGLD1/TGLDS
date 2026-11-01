//! Validation structurelle de l'enveloppe cryptographique TGDS v1.

/// Taille exacte de l'enveloppe.
pub const ENVELOPE_LENGTH: usize = 112;

/// Version prise en charge.
pub const ENVELOPE_VERSION: u16 = 1;

/// Identifiant du profil Argon2id.
pub const KDF_ARGON2ID: u16 = 1;

/// Mémoire Argon2id en Kio.
pub const ARGON2_MEMORY_KIB: u32 = 65_536;

/// Nombre d'itérations Argon2id.
pub const ARGON2_ITERATIONS: u32 = 3;

/// Parallélisme Argon2id.
pub const ARGON2_PARALLELISM: u32 = 1;

/// Taille du sel Argon2id.
pub const SALT_LENGTH: usize = 16;

/// Taille du nonce XChaCha20-Poly1305.
pub const NONCE_LENGTH: usize = 24;

/// Taille de la clé enveloppée avec son authentificateur.
pub const WRAPPED_KEY_LENGTH: usize = 48;

/// Enveloppe cryptographique validée.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Octets originaux de l'enveloppe.
    pub raw: [u8; ENVELOPE_LENGTH],
    /// Sel Argon2id.
    pub salt: [u8; SALT_LENGTH],
    /// Nonce XChaCha20-Poly1305.
    pub nonce: [u8; NONCE_LENGTH],
    /// Clé de données protégée et authentificateur.
    pub wrapped_key: [u8; WRAPPED_KEY_LENGTH],
}

/// Erreurs de validation de l'enveloppe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    InvalidLength,
    UnsupportedVersion,
    UnsupportedKdf,
    InvalidMemoryCost,
    InvalidIterations,
    InvalidParallelism,
    NonZeroReserved,
}

/// Valide et décode une enveloppe de 112 octets.
///
/// Aucun calcul Argon2id et aucun déchiffrement ne sont effectués.
pub fn parse_envelope(bytes: &[u8]) -> Result<Envelope, EnvelopeError> {
    if bytes.len() != ENVELOPE_LENGTH {
        return Err(EnvelopeError::InvalidLength);
    }

    let version = u16::from_le_bytes([bytes[0], bytes[1]]);
    if version != ENVELOPE_VERSION {
        return Err(EnvelopeError::UnsupportedVersion);
    }

    let kdf_id = u16::from_le_bytes([bytes[2], bytes[3]]);
    if kdf_id != KDF_ARGON2ID {
        return Err(EnvelopeError::UnsupportedKdf);
    }

    let memory = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if memory != ARGON2_MEMORY_KIB {
        return Err(EnvelopeError::InvalidMemoryCost);
    }

    let iterations = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if iterations != ARGON2_ITERATIONS {
        return Err(EnvelopeError::InvalidIterations);
    }

    let parallelism = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    if parallelism != ARGON2_PARALLELISM {
        return Err(EnvelopeError::InvalidParallelism);
    }

    if bytes[104..112].iter().any(|byte| *byte != 0) {
        return Err(EnvelopeError::NonZeroReserved);
    }

    let mut raw = [0u8; ENVELOPE_LENGTH];
    raw.copy_from_slice(bytes);

    let mut salt = [0u8; SALT_LENGTH];
    salt.copy_from_slice(&bytes[16..32]);

    let mut nonce = [0u8; NONCE_LENGTH];
    nonce.copy_from_slice(&bytes[32..56]);

    let mut wrapped_key = [0u8; WRAPPED_KEY_LENGTH];
    wrapped_key.copy_from_slice(&bytes[56..104]);

    Ok(Envelope {
        raw,
        salt,
        nonce,
        wrapped_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_envelope() -> [u8; ENVELOPE_LENGTH] {
        let mut bytes = [0u8; ENVELOPE_LENGTH];

        bytes[0..2].copy_from_slice(&ENVELOPE_VERSION.to_le_bytes());
        bytes[2..4].copy_from_slice(&KDF_ARGON2ID.to_le_bytes());
        bytes[4..8].copy_from_slice(&ARGON2_MEMORY_KIB.to_le_bytes());
        bytes[8..12].copy_from_slice(&ARGON2_ITERATIONS.to_le_bytes());
        bytes[12..16].copy_from_slice(&ARGON2_PARALLELISM.to_le_bytes());
        bytes[16..32].copy_from_slice(&[1u8; SALT_LENGTH]);
        bytes[32..56].copy_from_slice(&[2u8; NONCE_LENGTH]);
        bytes[56..104].copy_from_slice(&[3u8; WRAPPED_KEY_LENGTH]);

        bytes
    }

    #[test]
    fn valid_envelope_is_accepted() {
        let bytes = valid_envelope();
        let envelope = parse_envelope(&bytes).unwrap();

        assert_eq!(envelope.raw, bytes);
        assert_eq!(envelope.salt, [1u8; SALT_LENGTH]);
        assert_eq!(envelope.nonce, [2u8; NONCE_LENGTH]);
        assert_eq!(envelope.wrapped_key, [3u8; WRAPPED_KEY_LENGTH]);
    }

    #[test]
    fn incorrect_length_is_rejected() {
        assert_eq!(
            parse_envelope(&[0u8; ENVELOPE_LENGTH - 1]),
            Err(EnvelopeError::InvalidLength)
        );
    }

    #[test]
    fn additional_bytes_are_rejected() {
        assert_eq!(
            parse_envelope(&[0u8; ENVELOPE_LENGTH + 1]),
            Err(EnvelopeError::InvalidLength)
        );
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let mut bytes = valid_envelope();
        bytes[0..2].copy_from_slice(&2u16.to_le_bytes());

        assert_eq!(
            parse_envelope(&bytes),
            Err(EnvelopeError::UnsupportedVersion)
        );
    }

    #[test]
    fn unsupported_kdf_is_rejected() {
        let mut bytes = valid_envelope();
        bytes[2..4].copy_from_slice(&2u16.to_le_bytes());

        assert_eq!(
            parse_envelope(&bytes),
            Err(EnvelopeError::UnsupportedKdf)
        );
    }

    #[test]
    fn incorrect_memory_cost_is_rejected() {
        let mut bytes = valid_envelope();
        bytes[4..8].copy_from_slice(&32_768u32.to_le_bytes());

        assert_eq!(
            parse_envelope(&bytes),
            Err(EnvelopeError::InvalidMemoryCost)
        );
    }

    #[test]
    fn incorrect_iterations_are_rejected() {
        let mut bytes = valid_envelope();
        bytes[8..12].copy_from_slice(&2u32.to_le_bytes());

        assert_eq!(
            parse_envelope(&bytes),
            Err(EnvelopeError::InvalidIterations)
        );
    }

    #[test]
    fn incorrect_parallelism_is_rejected() {
        let mut bytes = valid_envelope();
        bytes[12..16].copy_from_slice(&2u32.to_le_bytes());

        assert_eq!(
            parse_envelope(&bytes),
            Err(EnvelopeError::InvalidParallelism)
        );
    }

    #[test]
    fn nonzero_reserved_bytes_are_rejected() {
        let mut bytes = valid_envelope();
        bytes[111] = 1;

        assert_eq!(
            parse_envelope(&bytes),
            Err(EnvelopeError::NonZeroReserved)
        );
    }
}
