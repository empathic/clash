//! Environment variable checks for clash mode control.

/// The environment variable that disables all clash hooks.
///
/// When set to any non-empty value (except `"0"` or `"false"`), clash becomes a
/// pass-through — all hooks return immediately without evaluating policy.
/// This is naturally session-scoped when set in the shell that launches Claude Code.
pub const CLASH_DISABLE_ENV: &str = "CLASH_DISABLE";

/// The environment variable that enables passthrough mode.
///
/// When set, clash defers all permission decisions to Claude Code's native permission
/// system — hooks return `continue_execution()` ("no opinion") instead of evaluating policy.
/// Tracing still syncs conversation turns, but there are no policy decisions, audit logs,
/// or session stats (since clash doesn't know what Claude decided).
/// If both `CLASH_DISABLE` and `CLASH_PASSTHROUGH` are set, `CLASH_DISABLE` takes priority.
pub const CLASH_PASSTHROUGH_ENV: &str = "CLASH_PASSTHROUGH";

/// Check whether clash is disabled via the [`CLASH_DISABLE`](CLASH_DISABLE_ENV) environment variable.
///
/// Returns `true` when the variable is set to any non-empty value except `"0"` or `"false"`.
pub fn is_disabled() -> bool {
    std::env::var(CLASH_DISABLE_ENV)
        .ok()
        .is_some_and(|v| is_truthy_disable_value(&v))
}

/// Check whether clash is in passthrough mode via the [`CLASH_PASSTHROUGH`](CLASH_PASSTHROUGH_ENV)
/// environment variable.
///
/// Returns `true` when the variable is set to any non-empty value except `"0"` or `"false"`.
pub fn is_passthrough() -> bool {
    std::env::var(CLASH_PASSTHROUGH_ENV)
        .ok()
        .is_some_and(|v| is_truthy_disable_value(&v))
}

/// Environment variable to disable harness default permissions.
///
/// When set to any non-empty value (except `"0"` or `"false"`), harness default
/// rules are not injected into the evaluated policy.
pub const CLASH_NO_HARNESS_DEFAULTS_ENV: &str = "CLASH_NO_HARNESS_DEFAULTS";

/// Check whether harness defaults are disabled via the
/// [`CLASH_NO_HARNESS_DEFAULTS`](CLASH_NO_HARNESS_DEFAULTS_ENV) environment variable.
///
/// Returns `true` when the variable is set to any non-empty value except `"0"` or `"false"`.
pub fn is_harness_defaults_disabled() -> bool {
    std::env::var(CLASH_NO_HARNESS_DEFAULTS_ENV)
        .ok()
        .is_some_and(|v| is_truthy_disable_value(&v))
}

/// Returns `true` when `value` should be interpreted as "disabled".
///
/// A non-empty string that is not `"0"` or `"false"` means disabled.
pub(crate) fn is_truthy_disable_value(value: &str) -> bool {
    !value.is_empty() && value != "0" && value != "false"
}

#[cfg(test)]
mod test {
    use super::*;

    //
    // These test `is_truthy_disable_value` directly to avoid env var races.
    // `env::set_var` is process-wide and Rust runs tests on parallel threads,
    // so multiple tests mutating the same env var is inherently racy.

    #[test]
    fn is_truthy_disable_value_not_set() {
        // Empty string = not disabled (matches env var missing or empty).
        assert!(!is_truthy_disable_value(""));
    }

    #[test]
    fn is_truthy_disable_value_falsy() {
        assert!(!is_truthy_disable_value("0"));
        assert!(!is_truthy_disable_value("false"));
    }

    #[test]
    fn is_truthy_disable_value_truthy() {
        assert!(is_truthy_disable_value("1"));
        assert!(is_truthy_disable_value("true"));
        assert!(is_truthy_disable_value("yes"));
        assert!(is_truthy_disable_value("anything"));
    }
}
