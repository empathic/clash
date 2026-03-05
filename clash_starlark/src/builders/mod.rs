pub mod base;
pub mod net;
pub mod path;
pub mod rule;
pub mod sandbox;

/// Validate that a string is a valid effect name.
pub fn effect_str_valid(s: &str) -> anyhow::Result<()> {
    match s {
        "allow" | "deny" | "ask" => Ok(()),
        _ => anyhow::bail!("invalid effect: {s:?} (expected allow, deny, or ask)"),
    }
}

/// Unpack an optional effect string, returning a default if None.
pub fn unpack_effect_or_default(s: Option<&str>, default: &str) -> String {
    s.unwrap_or(default).to_string()
}
