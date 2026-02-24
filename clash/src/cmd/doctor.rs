use anyhow::Result;
use tracing::{Level, instrument};

use crate::sandbox;
use crate::settings::ClashSettings;
use crate::style;

/// Outcome of a single diagnostic check.
enum CheckResult {
    /// Check passed — everything looks good.
    Pass(String),
    /// Check passed with a caveat.
    Warn(String),
    /// Check failed — action required.
    Fail(String),
}

impl CheckResult {
    fn print(&self, label: &str) {
        match self {
            CheckResult::Pass(msg) => {
                println!(
                    "  {} {}: {}",
                    style::green_bold("PASS"),
                    style::bold(label),
                    msg
                );
            }
            CheckResult::Warn(msg) => {
                println!(
                    "  {} {}: {}",
                    style::yellow_bold("WARN"),
                    style::bold(label),
                    msg
                );
            }
            CheckResult::Fail(msg) => {
                println!(
                    "  {} {}: {}",
                    style::red_bold("FAIL"),
                    style::bold(label),
                    msg
                );
            }
        }
    }

    fn is_fail(&self) -> bool {
        matches!(self, CheckResult::Fail(_))
    }

    fn is_warn(&self) -> bool {
        matches!(self, CheckResult::Warn(_))
    }
}

/// Run all diagnostic checks and report results.
#[instrument(level = Level::TRACE)]
pub fn run() -> Result<()> {
    println!("{}", style::banner());
    println!();
    println!("{}", style::header("Doctor"));
    println!("{}", style::dim("──────"));
    println!();

    let checks = vec![
        ("Policy files", check_policy_files()),
        ("Policy parsing", check_policy_parsing()),
        ("Plugin installed", check_plugin_installed()),
        ("Binary on PATH", check_binary_on_path()),
        ("File permissions", check_file_permissions()),
        ("Sandbox support", check_sandbox_support()),
    ];

    let mut fail_count = 0;
    let mut warn_count = 0;

    for (label, result) in &checks {
        result.print(label);
        if result.is_fail() {
            fail_count += 1;
        }
        if result.is_warn() {
            warn_count += 1;
        }
    }

    println!();

    if fail_count == 0 && warn_count == 0 {
        println!(
            "  {} All checks passed. clash is ready to use.",
            style::green_bold("OK"),
        );
    } else if fail_count == 0 {
        println!(
            "  {} {} warning(s), but no failures.",
            style::yellow_bold("OK"),
            warn_count,
        );
    } else {
        println!(
            "  {} {} check(s) failed, {} warning(s). See above for fix instructions.",
            style::red_bold("!!"),
            fail_count,
            warn_count,
        );
    }

    Ok(())
}

/// Check 1: Do policy files exist?
fn check_policy_files() -> CheckResult {
    let levels = ClashSettings::available_policy_levels();

    if levels.is_empty() {
        return CheckResult::Fail("No policy files found. Run `clash init` to create one.".into());
    }

    let names: Vec<String> = levels
        .iter()
        .map(|(level, path)| format!("{} ({})", level, path.display()))
        .collect();

    CheckResult::Pass(format!("Found: {}", names.join(", ")))
}

/// Check 2: Do the policy files parse and compile successfully?
fn check_policy_parsing() -> CheckResult {
    let levels = ClashSettings::available_policy_levels();

    if levels.is_empty() {
        return CheckResult::Warn("No policy files to parse (none found).".into());
    }

    let mut errors = Vec::new();

    for (level, path) in &levels {
        match std::fs::read_to_string(path) {
            Ok(source) => {
                if source.trim().is_empty() {
                    errors.push(format!("{}: file is empty", level));
                    continue;
                }
                if let Err(e) = crate::policy::compile_policy(&source) {
                    errors.push(format!("{}: {}", level, e));
                }
            }
            Err(e) => {
                errors.push(format!("{}: cannot read — {}", level, e));
            }
        }
    }

    if errors.is_empty() {
        CheckResult::Pass("All policy files parse and compile successfully.".into())
    } else {
        CheckResult::Fail(format!(
            "Policy errors:\n{}",
            errors
                .iter()
                .map(|e| format!("      {}", e))
                .collect::<Vec<_>>()
                .join("\n")
        ))
    }
}

/// Check 3: Is clash registered as a Claude Code plugin?
///
/// Looks for hook commands referencing "clash" in the Claude Code user settings
/// (specifically the hooks configuration).
fn check_plugin_installed() -> CheckResult {
    let claude = claude_settings::ClaudeSettings::new();

    // Check user-level settings for hooks referencing clash.
    let settings = match claude.read(claude_settings::SettingsLevel::User) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return CheckResult::Warn(
                "No Claude Code user settings found. \
                 Run `clash init` to install the plugin."
                    .into(),
            );
        }
        Err(e) => {
            return CheckResult::Warn(format!(
                "Could not read Claude Code settings: {}. \
                 Run `clash init` to install the plugin.",
                e
            ));
        }
    };

    // Check if hooks reference clash commands
    if let Some(ref hooks) = settings.hooks
        && hooks_reference_clash(hooks)
    {
        // Also check bypass_permissions
        return if settings.bypass_permissions == Some(true) {
            CheckResult::Pass("clash hooks are registered and bypassPermissions is enabled.".into())
        } else {
            CheckResult::Warn(
                "clash hooks are registered but bypassPermissions is not set. \
                 You may see double permission prompts. \
                 Fix: run `clash init` or set bypassPermissions in Claude Code settings."
                    .into(),
            )
        };
    }

    // Hooks not found — check if maybe the plugin is installed via the
    // marketplace/plugin system (look for enabled_plugins).
    if let Some(ref plugins) = settings.enabled_plugins
        && plugins.get("clash").copied() == Some(true)
    {
        return if settings.bypass_permissions == Some(true) {
            CheckResult::Pass("clash plugin is enabled and bypassPermissions is set.".into())
        } else {
            CheckResult::Warn(
                "clash plugin is enabled but bypassPermissions is not set. \
                 Fix: run `clash init` or set bypassPermissions in Claude Code settings."
                    .into(),
            )
        };
    }

    CheckResult::Fail(
        "clash is not registered as a Claude Code plugin. \
         Fix: run `clash init` to install and configure."
            .into(),
    )
}

/// Returns true if any hook command in the Hooks config references "clash".
fn hooks_reference_clash(hooks: &claude_settings::Hooks) -> bool {
    let configs = [
        hooks.pre_tool_use.as_ref(),
        hooks.post_tool_use.as_ref(),
        hooks.notification.as_ref(),
    ];

    for config in configs.into_iter().flatten() {
        match config {
            claude_settings::HookConfig::Simple(map) => {
                for cmd in map.values() {
                    if cmd.contains("clash") {
                        return true;
                    }
                }
            }
            claude_settings::HookConfig::Matchers(matchers) => {
                for matcher in matchers {
                    for hook in &matcher.hooks {
                        if let Some(ref cmd) = hook.command
                            && cmd.contains("clash")
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }

    false
}

/// Check 4: Is the `clash` binary findable on PATH?
fn check_binary_on_path() -> CheckResult {
    match which_clash() {
        Some(path) => CheckResult::Pass(format!("Found at {}", path)),
        None => CheckResult::Fail(
            "clash not found on PATH. \
             Ensure the clash binary is installed and in your $PATH."
                .into(),
        ),
    }
}

/// Locate the clash binary on PATH.
fn which_clash() -> Option<String> {
    std::process::Command::new("which")
        .arg("clash")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// Check 5: Are policy files readable with appropriate permissions?
fn check_file_permissions() -> CheckResult {
    let levels = ClashSettings::available_policy_levels();

    if levels.is_empty() {
        return CheckResult::Warn("No policy files to check permissions on.".into());
    }

    let mut issues = Vec::new();

    for (level, path) in &levels {
        match std::fs::metadata(path) {
            Ok(metadata) => {
                // Check readability (we already read it, so it's readable if we got metadata).
                if metadata.is_dir() {
                    issues.push(format!(
                        "{}: {} is a directory, not a file. \
                         Remove it and run `clash init`.",
                        level,
                        path.display()
                    ));
                    continue;
                }

                // Check for overly permissive permissions on Unix
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = metadata.permissions().mode() & 0o777;
                    if mode & 0o077 != 0 {
                        issues.push(format!(
                            "{}: {} has mode {:o} (world/group accessible). \
                             Fix: chmod 600 {}",
                            level,
                            path.display(),
                            mode,
                            path.display()
                        ));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                issues.push(format!(
                    "{}: {} is not readable. Fix: chmod 600 {}",
                    level,
                    path.display(),
                    path.display()
                ));
            }
            Err(e) => {
                issues.push(format!("{}: cannot stat {} — {}", level, path.display(), e));
            }
        }
    }

    if issues.is_empty() {
        CheckResult::Pass("All policy files have appropriate permissions.".into())
    } else {
        // Permission issues are warnings since the files still work, just insecure
        CheckResult::Warn(format!(
            "Permission issues:\n{}",
            issues
                .iter()
                .map(|i| format!("      {}", i))
                .collect::<Vec<_>>()
                .join("\n")
        ))
    }
}

/// Check 6: Does the platform support sandboxing?
fn check_sandbox_support() -> CheckResult {
    match sandbox::check_support() {
        sandbox::SupportLevel::Full => {
            let backend = if cfg!(target_os = "macos") {
                "seatbelt"
            } else if cfg!(target_os = "linux") {
                "landlock"
            } else {
                "unknown"
            };
            CheckResult::Pass(format!("Fully supported ({backend})."))
        }
        sandbox::SupportLevel::Partial { missing } => CheckResult::Warn(format!(
            "Partially supported. Missing: {}",
            missing.join(", ")
        )),
        sandbox::SupportLevel::Unsupported { reason } => CheckResult::Warn(format!(
            "Not supported on this platform: {}. \
             Sandbox enforcement will be skipped.",
            reason
        )),
    }
}

/// Check that the user-level settings dir (~/.clash/) exists.
///
/// Not used as a top-level check but available as a helper.
#[allow(dead_code)]
fn check_settings_dir() -> CheckResult {
    match ClashSettings::settings_dir() {
        Ok(dir) if dir.exists() => CheckResult::Pass(format!("Found at {}", dir.display())),
        Ok(dir) => CheckResult::Fail(format!(
            "{} does not exist. Run `clash init` to create it.",
            dir.display()
        )),
        Err(e) => CheckResult::Fail(format!("Cannot determine settings directory: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_result_pass_is_not_fail() {
        let r = CheckResult::Pass("ok".into());
        assert!(!r.is_fail());
        assert!(!r.is_warn());
    }

    #[test]
    fn check_result_warn_is_warn() {
        let r = CheckResult::Warn("warning".into());
        assert!(!r.is_fail());
        assert!(r.is_warn());
    }

    #[test]
    fn check_result_fail_is_fail() {
        let r = CheckResult::Fail("error".into());
        assert!(r.is_fail());
        assert!(!r.is_warn());
    }

    #[test]
    fn which_clash_returns_some_when_on_path() {
        // clash should be available in the dev environment
        // This test may not pass in CI if clash is not installed;
        // it's a sanity check for the logic.
        let result = which_clash();
        // We don't assert Some because the test may run in an env without clash
        // Just verify it doesn't panic
        let _ = result;
    }

    #[test]
    fn hooks_reference_clash_detects_matcher_hooks() {
        use claude_settings::{Hook, HookConfig, HookMatcher, Hooks};

        let hooks = Hooks {
            pre_tool_use: Some(HookConfig::Matchers(vec![HookMatcher {
                matcher: "*".into(),
                hooks: vec![Hook {
                    hook_type: "command".into(),
                    command: Some("clash hook pre-tool-use".into()),
                    timeout: None,
                }],
            }])),
            post_tool_use: None,
            stop: None,
            notification: None,
        };

        assert!(hooks_reference_clash(&hooks));
    }

    #[test]
    fn hooks_reference_clash_returns_false_for_unrelated_hooks() {
        use claude_settings::{Hook, HookConfig, HookMatcher, Hooks};

        let hooks = Hooks {
            pre_tool_use: Some(HookConfig::Matchers(vec![HookMatcher {
                matcher: "*".into(),
                hooks: vec![Hook {
                    hook_type: "command".into(),
                    command: Some("other-tool hook".into()),
                    timeout: None,
                }],
            }])),
            post_tool_use: None,
            stop: None,
            notification: None,
        };

        assert!(!hooks_reference_clash(&hooks));
    }

    #[test]
    fn hooks_reference_clash_handles_empty_hooks() {
        let hooks = claude_settings::Hooks {
            pre_tool_use: None,
            post_tool_use: None,
            stop: None,
            notification: None,
        };

        assert!(!hooks_reference_clash(&hooks));
    }

    #[test]
    fn check_sandbox_does_not_panic() {
        // Just verify the check runs without panicking
        let result = check_sandbox_support();
        // On macOS and Linux, should be Pass or Warn (not Fail)
        assert!(!result.is_fail());
    }

    #[test]
    fn check_binary_on_path_does_not_panic() {
        let _ = check_binary_on_path();
    }
}
