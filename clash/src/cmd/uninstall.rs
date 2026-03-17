use anyhow::Result;
use tracing::{Level, info, instrument, warn};

use crate::dialog;
use crate::settings::ClashSettings;
use crate::ui;

/// Run the uninstall command.
///
/// Reverses everything `clash init` does: removes bypass permissions, disables
/// the plugin, removes the status line, and optionally removes policy files
/// and the binary itself.
#[instrument(level = Level::TRACE)]
pub fn run(yes: bool) -> Result<()> {
    ui::banner_section("Uninstall");

    if !dialog::confirm(
        "Uninstall clash? This will remove all clash configuration from Claude Code",
        yes,
    )
    .unwrap_or(false)
    {
        ui::skip("Cancelled.");
        return Ok(());
    }

    // 1. Remove bypass permissions (the thing the user keeps forgetting).
    remove_bypass_permissions();

    // 2. Remove the status line.
    remove_status_line();

    // 3. Disable the plugin in Claude Code settings.
    disable_plugin();

    // 4. Uninstall the Claude Code plugin via CLI.
    uninstall_plugin();

    // 5. Remove ~/.clash/ directory.
    remove_settings_dir(yes);

    // 6. Remove the binary.
    remove_binary(yes);

    println!();
    ui::success("Clash has been uninstalled. To reinstall, run:");
    println!(
        "  {}",
        crate::style::dim(
            "curl -fsSL https://raw.githubusercontent.com/empathic/clash/main/install.sh | bash"
        )
    );
    println!(
        "  {}",
        crate::style::dim("# or: cargo install clash, or: just install")
    );

    Ok(())
}

/// Remove `bypassPermissions` and reset `permissions.defaultMode` in Claude Code settings.
fn remove_bypass_permissions() {
    let claude = claude_settings::ClaudeSettings::new();

    // Check current state first.
    let has_bypass = claude
        .read(claude_settings::SettingsLevel::User)
        .ok()
        .flatten()
        .is_some_and(|s| s.bypass_permissions == Some(true));

    if !has_bypass {
        ui::skip("bypassPermissions is not set, nothing to remove.");
        return;
    }

    let mut ok = true;
    if let Err(e) = claude.set_bypass_permissions(claude_settings::SettingsLevel::User, false) {
        warn!(error = %e, "failed to unset bypassPermissions");
        ui::warn(&format!("Could not unset bypassPermissions: {e}"));
        ok = false;
    }

    if let Err(e) =
        claude.set_default_permission_mode(claude_settings::SettingsLevel::User, "default")
    {
        warn!(error = %e, "failed to reset defaultMode");
        ui::warn(&format!("Could not reset permissions.defaultMode: {e}"));
        ok = false;
    }

    if ok {
        ui::success("Removed bypassPermissions from Claude Code settings.");
    }
}

/// Remove the clash status line from Claude Code settings.
fn remove_status_line() {
    match super::statusline::uninstall_for_teardown() {
        Ok(true) => {
            ui::success("Removed status line from Claude Code settings.");
        }
        Ok(false) => {
            ui::skip("No clash status line configured.");
        }
        Err(e) => {
            warn!(error = %e, "failed to remove status line");
            ui::warn(&format!("Could not remove status line: {e}"));
        }
    }
}

/// Disable the clash plugin in Claude Code settings.
fn disable_plugin() {
    let claude = claude_settings::ClaudeSettings::new();

    let is_enabled = claude
        .read(claude_settings::SettingsLevel::User)
        .ok()
        .flatten()
        .and_then(|s| s.enabled_plugins)
        .and_then(|p| p.get("clash").copied())
        .unwrap_or(false);

    if !is_enabled {
        ui::skip("clash plugin is not enabled in settings.");
        return;
    }

    if let Err(e) = claude.set_plugin_enabled(claude_settings::SettingsLevel::User, "clash", false)
    {
        warn!(error = %e, "failed to disable plugin in settings");
        ui::warn(&format!("Could not disable clash plugin: {e}"));
        return;
    }

    ui::success("Disabled clash plugin in Claude Code settings.");
}

/// Uninstall the Claude Code plugin via the `claude` CLI.
fn uninstall_plugin() {
    let output = std::process::Command::new("claude")
        .args(["plugin", "uninstall", "clash"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            info!("claude plugin uninstall succeeded");
            ui::success("Uninstalled clash plugin from Claude Code.");
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            // "not installed" / "not found" is fine — nothing to uninstall.
            if stderr.contains("not") {
                info!("plugin was not installed, skipping");
                ui::skip("clash plugin was not installed in Claude Code.");
            } else {
                warn!(stderr = %stderr, "claude plugin uninstall failed");
                ui::warn(&format!("Could not uninstall plugin: {stderr}"));
            }
        }
        Err(e) => {
            warn!(error = %e, "claude CLI not found");
            ui::warn(&format!("Could not run `claude plugin uninstall`: {e}"));
        }
    }
}

/// Remove the `~/.clash/` settings directory.
fn remove_settings_dir(yes: bool) {
    let dir = match ClashSettings::settings_dir() {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "could not determine settings directory");
            return;
        }
    };

    if !dir.exists() {
        ui::skip(&format!(
            "{} does not exist, nothing to remove.",
            dir.display()
        ));
        return;
    }

    if !dialog::confirm(
        &format!("Remove {}? (contains your policy files)", dir.display()),
        yes,
    )
    .unwrap_or(false)
    {
        ui::skip(&format!("Kept {}.", dir.display()));
        return;
    }

    if let Err(e) = std::fs::remove_dir_all(&dir) {
        warn!(error = %e, path = %dir.display(), "failed to remove settings directory");
        ui::warn(&format!("Could not remove {}: {e}", dir.display()));
        return;
    }

    ui::success(&format!("Removed {}.", dir.display()));
}

/// Find and remove the clash binary.
fn remove_binary(yes: bool) {
    let binary_path = match find_clash_binary() {
        Some(p) => p,
        None => {
            ui::skip("clash binary not found on PATH.");
            return;
        }
    };

    // Don't remove the binary we're currently running from if it's a dev build
    // (e.g., inside a cargo target directory).
    if binary_path.contains("/target/") {
        ui::skip(&format!(
            "Skipping binary removal (looks like a development build at {}).",
            binary_path,
        ));
        return;
    }

    if !dialog::confirm(&format!("Remove clash binary at {}?", binary_path), yes).unwrap_or(false) {
        ui::skip(&format!("Kept binary at {}.", binary_path));
        return;
    }

    if let Err(e) = std::fs::remove_file(&binary_path) {
        warn!(error = %e, path = %binary_path, "failed to remove binary");
        ui::warn(&format!("Could not remove {}: {e}", binary_path));
        return;
    }

    ui::success(&format!("Removed {}.", binary_path));
}

/// Locate the clash binary on PATH.
fn find_clash_binary() -> Option<String> {
    std::process::Command::new("which")
        .arg("clash")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_clash_binary_does_not_panic() {
        let _ = find_clash_binary();
    }
}
