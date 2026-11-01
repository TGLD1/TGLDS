//! TGLD Secure Archive Core
//!
//! Core engine for the TGDS encrypted archive format.

pub mod format;

pub const PROJECT_NAME: &str = "TGLD Secure Archive";
pub const FORMAT_EXTENSION: &str = "tgds";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_identity_is_valid() {
        assert_eq!(PROJECT_NAME, "TGLD Secure Archive");
        assert_eq!(FORMAT_EXTENSION, "tgds");
    }
}
