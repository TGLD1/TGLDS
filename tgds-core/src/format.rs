//! Identification du format binaire TGDS.

/// Signature binaire de quatre octets.
pub const MAGIC: [u8; 4] = *b"TGDS";

/// Version initiale du format.
pub const FORMAT_VERSION: u16 = 1;

/// Version actuelle du développement.
pub const DEVELOPMENT_VERSION: &str = "0.1.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_signature_is_correct() {
        assert_eq!(MAGIC, *b"TGDS");
    }

    #[test]
    fn initial_format_version_is_correct() {
        assert_eq!(FORMAT_VERSION, 1);
    }
}
