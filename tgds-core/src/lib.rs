//! TGLD Secure Archive Core.

pub mod crypto;
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
