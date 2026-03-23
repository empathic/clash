use anyhow::{Context, Result};
use tracing::{Level, error, info, instrument, warn};

use crate::cmd::wizard;
use crate::dialog;
use crate::settings::ClashSettings;
use crate::style;
use crate::ui;

#[derive(Default)]
struct InitActions {
    policy_created: bool,
    plugin_installed: bool,
    bypass_set: bool,
    statusline_installed: bool,
}

/// GitHub repository used to install the clash plugin marketplace.
const GITHUB_MARKETPLACE: &str = "empathic/clash";

/// Initialize clash at the chosen scope.
///
/// When `scope` is provided ("user" or "project"), initializes that scope
/// directly. When omitted, runs the interactive wizard.
/// Only one scope is initialized per invocation.
#[instrument(level = Level::TRACE)]
pub fn run(no_bypass: Option<bool>, scope: Option<String>, quick: bool) -> Result<()> {
    match scope.as_deref() {
        Some("project") => run_init_project(),
        _ if quick => run_init_quick(no_bypass),
        _ => run_init_user(no_bypass),
    }
}

/// Initialize or reconfigure the user-level policy via the wizard.
fn run_init_user(no_bypass: Option<bool>) -> Result<()> {
    let mut actions = InitActions::default();

    wizard::wiz()?;
    actions.policy_created = true;

    // Always ensure settings.json records clash as an enabled plugin.
    let claude = claude_settings::ClaudeSettings::new();
    if let Err(e) = claude.set_plugin_enabled(claude_settings::SettingsLevel::User, "clash", true) {
        warn!(error = %e, "Could not set enabledPlugins in Claude Code settings");
    }

    // Install the Claude Code plugin from GitHub.
    let plugin_installed = match install_plugin() {
        Ok(()) => {
            actions.plugin_installed = true;
            true
        }
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

        if !skip_bypass {
            if let Err(e) = set_bypass_permissions() {
                warn!(error = %e, "Could not set bypassPermissions in Claude Code settings");
                eprintln!(
                    "warning: could not configure Claude Code to use clash as sole permission handler.\n\
                     You may see double prompts. Run with --dangerously-skip-permissions to avoid this."
                );
            } else {
                actions.bypass_set = true;
            }
        }
    } else {
        ui::skip("Skipping bypassPermissions — the clash plugin must be installed first.");
    }

    // Install the status line so the user gets ambient policy visibility.
    if let Err(e) = super::statusline::install() {
        warn!(error = %e, "Could not install status line");
    } else {
        actions.statusline_installed = true;
    }

    print_user_summary(&actions);

    Ok(())
}

/// Quick-init: skip the wizard and write a sensible default policy directly.
fn run_init_quick(no_bypass: Option<bool>) -> Result<()> {
    let settings_dir = ClashSettings::settings_dir()
        .context("could not determine clash settings directory")?;

    std::fs::create_dir_all(&settings_dir)
        .with_context(|| format!("failed to create {}", settings_dir.display()))?;

    let policy_path = settings_dir.join("policy.star");

    let quick_policy = r#"load("@clash//std.star", "exe", "tool", "policy", "allow", "ask")

def main():
    return policy(
        default = ask(),
        rules = [
            exe("git").allow(),
            exe("cargo").allow(),
            exe("npm").allow(),
            exe("npx").allow(),
            exe("node").allow(),
            exe("bun").allow(),
            exe("python").allow(),
            exe("pip").allow(),
            exe("uv").allow(),
            tool("Read").allow(),
            tool("Glob").allow(),
            tool("Grep").allow(),
        ],
    )
"#;

    std::fs::write(&policy_path, quick_policy)
        .with_context(|| format!("failed to write {}", policy_path.display()))?;

    ui::success(&format!(
        "Quick setup: policy created at {}",
        policy_path.display()
    ));

    // Ensure settings.json records clash as an enabled plugin.
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

    let project_policy = "load(\"@clash//std.star\", \"policy\", \"deny\")\ndef main():\n    return policy(default = deny(), rules = [])\n";
    std::fs::write(&policy_path, project_policy)
        .with_context(|| format!("failed to write {}", policy_path.display()))?;

    ui::success(&format!(
        "Project policy initialized at {}",
        policy_path.display()
    ));

    println!();
    println!("{}", style::bold("Setup complete!"));
    println!();
    ui::success(&format!("Project policy created at {}", policy_path.display()));
    println!();
    println!("{}:", style::bold("Next steps"));
    println!("  {}  {}", style::dim("clash policy show"), style::dim("# view the compiled policy"));
    println!("  {}  {}", style::dim("clash policy validate"), style::dim("# check for errors"));

    Ok(())
}

/// Configure Claude Code to let Clash handle all permission decisions.
pub fn set_bypass_permissions() -> Result<()> {
    let claude = claude_settings::ClaudeSettings::new();
    claude.set_bypass_permissions(claude_settings::SettingsLevel::User, true)?;
    claude
        .set_default_permission_mode(claude_settings::SettingsLevel::User, "bypassPermissions")?;
    ui::success("Configured Claude Code to use clash as the sole permission handler.");
    Ok(())
}

fn print_user_summary(actions: &InitActions) {
    let any_action = actions.policy_created || actions.plugin_installed
        || actions.bypass_set || actions.statusline_installed;
    if !any_action { return; }

    println!();
    println!("{}", style::bold("Setup complete! Here's what was configured:"));
    println!();

    if actions.policy_created {
        ui::success("Policy created");
    }
    if actions.plugin_installed {
        ui::success("Clash plugin installed in Claude Code");
    }
    if actions.bypass_set {
        ui::success("bypassPermissions enabled (clash handles all permissions)");
    }
    if actions.statusline_installed {
        ui::success("Status line installed");
    }

    println!();
    println!("{}:", style::bold("To undo"));
    println!("  {}  {}", style::dim("clash uninstall"), style::dim("# remove everything"));
    if actions.policy_created {
        println!("  {}  {}", style::dim("clash policy edit"), style::dim("# modify your policy"));
    }
    if actions.bypass_set {
        println!("  {}  {}", style::dim("clash init --no-bypass"), style::dim("# re-run without bypassPermissions"));
    }

    println!();
    println!("{}:", style::bold("Next steps"));
    println!("  {}  {}", style::dim("claude"), style::dim("# start a session with clash active"));
    println!("  {}  {}", style::dim("/clash:status"), style::dim("# check policy status inside a session"));
    println!("  {}  {}", style::dim("/clash:edit"), style::dim("# interactively edit your policy"));
}

/// Install the clash plugin into Claude Code from the GitHub marketplace.
pub fn install_plugin() -> Result<()> {
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
