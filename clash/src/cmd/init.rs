use anyhow::{Context, Result};
use tracing::{Level, error, info, instrument, warn};

use crate::cmd::wizard;
use crate::dialog;
use crate::settings::ClashSettings;
use crate::ui;

/// GitHub repository used to install the clash plugin marketplace.
const GITHUB_MARKETPLACE: &str = "empathic/clash";

/// Initialize clash at the chosen scope.
///
/// When `scope` is provided ("user" or "project"), initializes that scope
/// directly. When omitted, runs the interactive wizard.
/// Only one scope is initialized per invocation.
#[instrument(level = Level::TRACE)]
pub fn run(no_bypass: Option<bool>, scope: Option<String>) -> Result<()> {
    match scope.as_deref() {
        Some("project") => run_init_project(),
        _ => run_init_user(no_bypass),
    }
}

/// Initialize or reconfigure the user-level policy via the wizard.
fn run_init_user(no_bypass: Option<bool>) -> Result<()> {
    wizard::wiz()?;

    // Always ensure settings.json records clash as an enabled plugin.
    let claude = claude_settings::ClaudeSettings::new();
    if let Err(e) = claude.set_plugin_enabled(claude_settings::SettingsLevel::User, "clash", true) {
        warn!(error = %e, "Could not set enabledPlugins in Claude Code settings");
    }

    // Install the Claude Code plugin from GitHub.
    let plugin_installed = match install_plugin() {
        Ok(()) => true,
        Err(e) => {
            error!(error = %e, "Could not install clash plugin");
            ui::warn(&format!(
                "Could not install the clash plugin: {e}\n  \
                 You can install it manually later:\n    \
                 claude plugin marketplace add {GITHUB_MARKETPLACE}\n    \
                 claude plugin install clash"
            ));
            false
        }
    };

    if plugin_installed {
        // Plugin is installed, so bypassPermissions is safe.
        let skip_bypass = no_bypass.unwrap_or_else(|| {
            !dialog::confirm(
                "Use clash as your default permissions provider in Claude Code? \
                 (This sets bypassPermissions so clash handles all permission decisions)",
                false,
            )
            .unwrap_or(true)
        });

        if !skip_bypass && let Err(e) = set_bypass_permissions() {
            warn!(error = %e, "Could not set bypassPermissions in Claude Code settings");
            eprintln!(
                "warning: could not configure Claude Code to use clash as sole permission handler.\n\
                 You may see double prompts. Run with --dangerously-skip-permissions to avoid this."
            );
        }
    } else {
        ui::skip("Skipping bypassPermissions — the clash plugin must be installed first.");
    }

    // Install the status line so the user gets ambient policy visibility.
    if let Err(e) = super::statusline::install() {
        warn!(error = %e, "Could not install status line");
    }

    Ok(())
}

/// Initialize a project-level policy in the project root's `.clash/` directory.
fn run_init_project() -> Result<()> {
    let project_root = ClashSettings::project_root()
        .context("could not find project root — are you inside a git repository?")?;

    let clash_dir = project_root.join(".clash");
    let policy_path = clash_dir.join("policy.star");

    if policy_path.exists() {
        ui::skip(&format!(
            "Project policy already exists at {}",
            policy_path.display()
        ));
        return Ok(());
    }

    std::fs::create_dir_all(&clash_dir)
        .with_context(|| format!("failed to create {}", clash_dir.display()))?;

    let project_policy = "def main():\n    return policy(default = deny, rules = [])\n";
    std::fs::write(&policy_path, project_policy)
        .with_context(|| format!("failed to write {}", policy_path.display()))?;

    ui::success(&format!(
        "Project policy initialized at {}",
        policy_path.display()
    ));
    Ok(())
}

/// Configure Claude Code to let Clash handle all permission decisions.
fn set_bypass_permissions() -> Result<()> {
    let claude = claude_settings::ClaudeSettings::new();
    claude.set_bypass_permissions(claude_settings::SettingsLevel::User, true)?;
    claude
        .set_default_permission_mode(claude_settings::SettingsLevel::User, "bypassPermissions")?;
    ui::success("Configured Claude Code to use clash as the sole permission handler.");
    Ok(())
}

/// Install the clash plugin into Claude Code from the GitHub marketplace.
fn install_plugin() -> Result<()> {
    ui::progress(&format!(
        "Installing clash plugin from {}...",
        GITHUB_MARKETPLACE,
    ));

    // Register the marketplace.
    let add_output = std::process::Command::new("claude")
        .args(["plugin", "marketplace", "add", GITHUB_MARKETPLACE])
        .output()
        .context("failed to run `claude plugin marketplace add` — is claude on PATH?")?;

    if !add_output.status.success() {
        let stderr = String::from_utf8_lossy(&add_output.stderr);
        // "already exists" is fine — marketplace was previously registered.
        if !stderr.contains("already") {
            anyhow::bail!("claude plugin marketplace add failed: {stderr}");
        }
        info!("marketplace already registered, continuing");
    }

    // Install the plugin.
    let install_output = std::process::Command::new("claude")
        .args(["plugin", "install", "clash"])
        .output()
        .context("failed to run `claude plugin install`")?;

    if !install_output.status.success() {
        let stderr = String::from_utf8_lossy(&install_output.stderr);
        // "already installed" is fine.
        if !stderr.contains("already") {
            anyhow::bail!("claude plugin install failed: {stderr}");
        }
        info!("plugin already installed");
    }

    ui::success("Clash plugin installed in Claude Code.");
    Ok(())
}
