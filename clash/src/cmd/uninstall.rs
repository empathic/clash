use anyhow::Result;
use tracing::{Level, info, instrument, warn};

use crate::settings::ClashSettings;
use crate::style;

/// Run the uninstall command.
///
/// Reverses everything `clash init` does: removes bypass permissions, disables
/// the plugin, removes the status line, and optionally removes policy files
/// and the binary itself.
#[instrument(level = Level::TRACE)]
pub fn run(yes: bool) -> Result<()> {
    println!("{}", style::banner());
    println!();
    println!("{}", style::header("Uninstall"));
    println!("{}", style::dim("──────────"));
    println!();

    if !yes
        && !dialoguer::Confirm::new()
            .with_prompt(
                "Uninstall clash? This will remove all clash configuration from Claude Code",
            )
            .default(true)
            .interact()
            .unwrap_or(false)
    {
        println!("{} Cancelled.", style::dim("·"));
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
    println!(
        "{} Clash has been uninstalled. To reinstall, run:",
        style::green_bold("✓"),
    );
    println!(
        "  {}",
        style::dim(
            "curl -fsSL https://raw.githubusercontent.com/empathic/clash/main/install.sh | bash"
        )
    );
    println!(
        "  {}",
        style::dim("# or: cargo install clash, or: just install")
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
        println!(
            "{} bypassPermissions is not set, nothing to remove.",
            style::dim("·"),
        );
        return;
    }

    let mut ok = true;
    if let Err(e) = claude.set_bypass_permissions(claude_settings::SettingsLevel::User, false) {
        warn!(error = %e, "failed to unset bypassPermissions");
        eprintln!(
            "  {} Could not unset bypassPermissions: {e}",
            style::yellow("!"),
        );
        ok = false;
    }

    if let Err(e) =
        claude.set_default_permission_mode(claude_settings::SettingsLevel::User, "default")
    {
        warn!(error = %e, "failed to reset defaultMode");
        eprintln!(
            "  {} Could not reset permissions.defaultMode: {e}",
            style::yellow("!"),
        );
        ok = false;
    }

    if ok {
        println!(
            "{} Removed bypassPermissions from Claude Code settings.",
            style::green_bold("✓"),
        );
    }
}

/// Remove the clash status line from Claude Code settings.
fn remove_status_line() {
    match super::statusline::uninstall_for_teardown() {
        Ok(true) => {
            println!(
                "{} Removed status line from Claude Code settings.",
                style::green_bold("✓"),
            );
        }
        Ok(false) => {
            println!("{} No clash status line configured.", style::dim("·"),);
        }
        Err(e) => {
            warn!(error = %e, "failed to remove status line");
            eprintln!("  {} Could not remove status line: {e}", style::yellow("!"),);
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
        println!(
            "{} clash plugin is not enabled in settings.",
            style::dim("·"),
        );
        return;
    }

    if let Err(e) = claude.set_plugin_enabled(claude_settings::SettingsLevel::User, "clash", false)
    {
        warn!(error = %e, "failed to disable plugin in settings");
        eprintln!(
            "  {} Could not disable clash plugin: {e}",
            style::yellow("!"),
        );
        return;
    }

    println!(
        "{} Disabled clash plugin in Claude Code settings.",
        style::green_bold("✓"),
    );
}

/// Uninstall the Claude Code plugin via the `claude` CLI.
fn uninstall_plugin() {
    let output = std::process::Command::new("claude")
        .args(["plugin", "uninstall", "clash"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            info!("claude plugin uninstall succeeded");
            println!(
                "{} Uninstalled clash plugin from Claude Code.",
                style::green_bold("✓"),
            );
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            // "not installed" / "not found" is fine — nothing to uninstall.
            if stderr.contains("not") {
                info!("plugin was not installed, skipping");
                println!(
                    "{} clash plugin was not installed in Claude Code.",
                    style::dim("·"),
                );
            } else {
                warn!(stderr = %stderr, "claude plugin uninstall failed");
                eprintln!(
                    "  {} Could not uninstall plugin: {stderr}",
                    style::yellow("!"),
                );
            }
        }
        Err(e) => {
            warn!(error = %e, "claude CLI not found");
            eprintln!(
                "  {} Could not run `claude plugin uninstall`: {e}",
                style::yellow("!"),
            );
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
        println!(
            "{} {} does not exist, nothing to remove.",
            style::dim("·"),
            dir.display(),
        );
        return;
    }

    if !yes
        && !dialoguer::Confirm::new()
            .with_prompt(format!(
                "Remove {}? (contains your policy files)",
                dir.display()
            ))
            .default(true)
            .interact()
            .unwrap_or(false)
    {
        println!("{} Kept {}.", style::dim("·"), dir.display(),);
        return;
    }

    if let Err(e) = std::fs::remove_dir_all(&dir) {
        warn!(error = %e, path = %dir.display(), "failed to remove settings directory");
        eprintln!(
            "  {} Could not remove {}: {e}",
            style::yellow("!"),
            dir.display(),
        );
        return;
    }

    println!("{} Removed {}.", style::green_bold("✓"), dir.display(),);
}

/// Find and remove the clash binary.
fn remove_binary(yes: bool) {
    let binary_path = match find_clash_binary() {
        Some(p) => p,
        None => {
            println!("{} clash binary not found on PATH.", style::dim("·"),);
            return;
        }
    };

    // Don't remove the binary we're currently running from if it's a dev build
    // (e.g., inside a cargo target directory).
    if binary_path.contains("/target/") {
        println!(
            "{} Skipping binary removal (looks like a development build at {}).",
            style::dim("·"),
            binary_path,
        );
        return;
    }

    if !yes
        && !dialoguer::Confirm::new()
            .with_prompt(format!("Remove clash binary at {}?", binary_path))
            .default(true)
            .interact()
            .unwrap_or(false)
    {
        println!("{} Kept binary at {}.", style::dim("·"), binary_path,);
        return;
    }

    if let Err(e) = std::fs::remove_file(&binary_path) {
        warn!(error = %e, path = %binary_path, "failed to remove binary");
        eprintln!(
            "  {} Could not remove {}: {e}",
            style::yellow("!"),
            binary_path,
        );
        return;
    }

    println!("{} Removed {}.", style::green_bold("✓"), binary_path,);
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
