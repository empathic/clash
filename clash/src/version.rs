use std::sync::OnceLock;

/// Semver version with git build metadata when available.
///
/// Returns formats like:
/// - `0.3.4+abc1234` — clean build from a known commit
/// - `0.3.4+abc1234-dirty` — uncommitted changes present
/// - `0.3.4` — git info unavailable (e.g. tarball build)
pub fn version_long() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| match option_env!("CLASH_GIT_HASH") {
        Some(hash) => format!("{}+{}", env!("CARGO_PKG_VERSION"), hash),
        None => env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// User-Agent header value: `clash/{version_long}`.
pub fn user_agent() -> &'static str {
    static UA: OnceLock<String> = OnceLock::new();
    UA.get_or_init(|| format!("clash/{}", version_long()))
}
