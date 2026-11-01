//! Identification et validation de l'en-tête binaire TGDS.

/// Signature binaire de quatre octets.
pub const MAGIC: [u8; 4] = *b"TGDS";

/// Version initiale du format.
pub const FORMAT_VERSION: u16 = 1;

/// Version actuelle du développement.
pub const DEVELOPMENT_VERSION: &str = "0.1.0";

/// Taille exacte de l'en-tête principal.
pub const HEADER_SIZE: usize = 64;

/// Taille normative de l'enveloppe cryptographique.
pub const ENVELOPE_SIZE: u32 = 112;

/// Taille maximale du manifeste en clair.
pub const MAX_MANIFEST_SIZE: u64 = 64 * 1024 * 1024;

/// Taille de l'authentificateur AEAD.
pub const AEAD_TAG_SIZE: u64 = 16;

/// Taille maximale du manifeste chiffré, authentificateur inclus.
pub const MAX_MANIFEST_CIPHERTEXT_SIZE: u64 =
    MAX_MANIFEST_SIZE + AEAD_TAG_SIZE;

/// Taille minimale du manifeste chiffré.
pub const MIN_MANIFEST_CIPHERTEXT_SIZE: u64 = AEAD_TAG_SIZE;

/// Taille maximale originale d'un bloc.
pub const MAX_CHUNK_SIZE: u32 = 1_048_576;

/// Nombre maximal de blocs.
pub const MAX_CHUNK_COUNT: u32 = 1_048_576;

/// En-tête principal validé d'une archive TGDS v1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Octets originaux de l'en-tête, conservés pour l'authentification.
    pub raw: [u8; HEADER_SIZE],
    /// Identifiant aléatoire de l'archive.
    pub archive_id: [u8; 16],
    /// Taille du texte chiffré du manifeste, authentificateur inclus.
    pub manifest_ciphertext_size: u64,
    /// Nombre total de blocs de données.
    pub chunk_count: u32,
}

/// Erreurs de validation de l'en-tête.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    InvalidFlags,
    InvalidHeaderSize,
    InvalidEnvelopeSize,
    InvalidManifestSize,
    InvalidChunkCount,
    InvalidMaxChunkSize,
    NonZeroReserved,
}

/// Lit un entier u16 en little-endian à un décalage connu.
fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

/// Lit un entier u32 en little-endian à un décalage connu.
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Lit un entier u64 en little-endian à un décalage connu.
fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

/// Valide et décode un en-tête principal de 64 octets.
///
/// Cette fonction n'effectue aucune allocation dynamique.
pub fn parse_header(bytes: &[u8]) -> Result<Header, HeaderError> {
    if bytes.len() != HEADER_SIZE {
        return Err(HeaderError::InvalidLength);
    }

    if bytes[0..4] != MAGIC {
        return Err(HeaderError::InvalidMagic);
    }

    if read_u16(bytes, 4) != FORMAT_VERSION {
        return Err(HeaderError::UnsupportedVersion);
    }

    if read_u16(bytes, 6) != 0 {
        return Err(HeaderError::InvalidFlags);
    }

    if read_u32(bytes, 8) != HEADER_SIZE as u32 {
        return Err(HeaderError::InvalidHeaderSize);
    }

    if read_u32(bytes, 28) != ENVELOPE_SIZE {
        return Err(HeaderError::InvalidEnvelopeSize);
    }

    let manifest_ciphertext_size = read_u64(bytes, 32);

    if !(MIN_MANIFEST_CIPHERTEXT_SIZE..=MAX_MANIFEST_CIPHERTEXT_SIZE)
        .contains(&manifest_ciphertext_size)
    {
        return Err(HeaderError::InvalidManifestSize);
    }

    let chunk_count = read_u32(bytes, 40);

    if chunk_count > MAX_CHUNK_COUNT {
        return Err(HeaderError::InvalidChunkCount);
    }

    if read_u32(bytes, 44) != MAX_CHUNK_SIZE {
        return Err(HeaderError::InvalidMaxChunkSize);
    }

    if bytes[48..64].iter().any(|byte| *byte != 0) {
        return Err(HeaderError::NonZeroReserved);
    }

    let mut raw = [0u8; HEADER_SIZE];
    raw.copy_from_slice(bytes);

    let mut archive_id = [0u8; 16];
    archive_id.copy_from_slice(&bytes[12..28]);

    Ok(Header {
        raw,
        archive_id,
        manifest_ciphertext_size,
        chunk_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_header() -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];

        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[4..6].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[6..8].copy_from_slice(&0u16.to_le_bytes());
        bytes[8..12].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        bytes[12..28].copy_from_slice(&[7u8; 16]);
        bytes[28..32].copy_from_slice(&ENVELOPE_SIZE.to_le_bytes());
        bytes[32..40].copy_from_slice(&16u64.to_le_bytes());
        bytes[40..44].copy_from_slice(&0u32.to_le_bytes());
        bytes[44..48].copy_from_slice(&MAX_CHUNK_SIZE.to_le_bytes());

        bytes
    }

    #[test]
    fn archive_signature_is_correct() {
        assert_eq!(MAGIC, *b"TGDS");
    }

    #[test]
    fn initial_format_version_is_correct() {
        assert_eq!(FORMAT_VERSION, 1);
    }

    #[test]
    fn valid_header_is_accepted() {
        let bytes = valid_header();
        let header = parse_header(&bytes).unwrap();

        assert_eq!(header.archive_id, [7u8; 16]);
        assert_eq!(header.manifest_ciphertext_size, 16);
        assert_eq!(header.chunk_count, 0);
        assert_eq!(header.raw, bytes);
    }

    #[test]
    fn incorrect_header_length_is_rejected() {
        assert_eq!(
            parse_header(&[0u8; HEADER_SIZE - 1]),
            Err(HeaderError::InvalidLength)
        );
    }

    #[test]
    fn additional_header_bytes_are_rejected() {
        assert_eq!(
            parse_header(&[0u8; HEADER_SIZE + 1]),
            Err(HeaderError::InvalidLength)
        );
    }

    #[test]
    fn incorrect_magic_is_rejected() {
        let mut bytes = valid_header();
        bytes[0] = b'X';

        assert_eq!(
            parse_header(&bytes),
            Err(HeaderError::InvalidMagic)
        );
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let mut bytes = valid_header();
        bytes[4..6].copy_from_slice(&2u16.to_le_bytes());

        assert_eq!(
            parse_header(&bytes),
            Err(HeaderError::UnsupportedVersion)
        );
    }

    #[test]
    fn nonzero_flags_are_rejected() {
        let mut bytes = valid_header();
        bytes[6..8].copy_from_slice(&1u16.to_le_bytes());

        assert_eq!(
            parse_header(&bytes),
            Err(HeaderError::InvalidFlags)
        );
    }

    #[test]
    fn incorrect_header_size_is_rejected() {
        let mut bytes = valid_header();
        bytes[8..12].copy_from_slice(&63u32.to_le_bytes());

        assert_eq!(
            parse_header(&bytes),
            Err(HeaderError::InvalidHeaderSize)
        );
    }

    #[test]
    fn incorrect_envelope_size_is_rejected() {
        let mut bytes = valid_header();
        bytes[28..32].copy_from_slice(&111u32.to_le_bytes());

        assert_eq!(
            parse_header(&bytes),
            Err(HeaderError::InvalidEnvelopeSize)
        );
    }

    #[test]
    fn undersized_manifest_is_rejected() {
        let mut bytes = valid_header();
        bytes[32..40].copy_from_slice(&15u64.to_le_bytes());

        assert_eq!(
            parse_header(&bytes),
            Err(HeaderError::InvalidManifestSize)
        );
    }

    #[test]
    fn oversized_manifest_is_rejected() {
        let mut bytes = valid_header();
        let size = MAX_MANIFEST_CIPHERTEXT_SIZE + 1;
        bytes[32..40].copy_from_slice(&size.to_le_bytes());

        assert_eq!(
            parse_header(&bytes),
            Err(HeaderError::InvalidManifestSize)
        );
    }

    #[test]
    fn excessive_chunk_count_is_rejected() {
        let mut bytes = valid_header();
        let count = MAX_CHUNK_COUNT + 1;
        bytes[40..44].copy_from_slice(&count.to_le_bytes());

        assert_eq!(
            parse_header(&bytes),
            Err(HeaderError::InvalidChunkCount)
        );
    }

    #[test]
    fn incorrect_maximum_chunk_size_is_rejected() {
        let mut bytes = valid_header();
        bytes[44..48].copy_from_slice(&1024u32.to_le_bytes());

        assert_eq!(
            parse_header(&bytes),
            Err(HeaderError::InvalidMaxChunkSize)
        );
    }

    #[test]
    fn nonzero_reserved_bytes_are_rejected() {
        let mut bytes = valid_header();
        bytes[63] = 1;

        assert_eq!(
            parse_header(&bytes),
            Err(HeaderError::NonZeroReserved)
        );
    }
}
