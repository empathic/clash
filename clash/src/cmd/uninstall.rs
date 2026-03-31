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

    // 1. Remove the status line.
    remove_status_line();

    // 2. Remove clash hooks and markers from Claude Code settings.
    remove_hooks_and_plugin();

    // 4. Remove ~/.clash/ directory.
    remove_settings_dir(yes);

    // 5. Remove the binary.
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

/// Remove clash hooks and plugin markers from Claude Code settings.
fn remove_hooks_and_plugin() {
    let claude = claude_settings::ClaudeSettings::new();

    match claude.update(claude_settings::SettingsLevel::User, |settings| {
        // Remove hooks.
        let hooks_removed = settings
            .hooks
            .as_mut()
            .map(|h| super::init::uninstall_clash_hooks(h))
            .unwrap_or(false);

        if hooks_removed {
            info!("removed clash hooks from settings");
        }

        // Clear empty hooks object.
        if let Some(ref h) = settings.hooks {
            if h.pre_tool_use.is_none()
                && h.post_tool_use.is_none()
                && h.permission_request.is_none()
                && h.session_start.is_none()
                && h.stop.is_none()
                && h.notification.is_none()
            {
                settings.hooks = None;
            }
        }

        // Remove plugin enabled flag.
        if let Some(ref mut plugins) = settings.enabled_plugins {
            plugins.remove("clash");
            if plugins.is_empty() {
                settings.enabled_plugins = None;
            }
        }

        // Remove clash installed marker.
        settings.clear_clash_installed();
    }) {
        Ok(()) => {
            ui::success("Removed clash hooks from Claude Code settings.");
        }
        Err(e) => {
            warn!(error = %e, "failed to remove hooks from settings");
            ui::warn(&format!("Could not update Claude Code settings: {e}"));
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
