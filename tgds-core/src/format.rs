//! TGDS binary format identification.

/// Four-byte archive signature.
pub const MAGIC: [u8; 4] = *b"TGDS";

/// Initial format version.
pub const FORMAT_VERSION: u16 = 1;

/// Current development version.
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
