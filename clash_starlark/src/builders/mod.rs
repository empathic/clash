pub mod base;
pub mod rule;

/// Unpack an optional effect string, returning a default if None.
pub fn unpack_effect_or_default(s: Option<&str>, default: &str) -> String {
    s.unwrap_or(default).to_string()
}
