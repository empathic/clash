use anyhow::{Context, Result};
use serde_json::json;
use tracing::{Level, error, info, instrument, warn};

use crate::agents::AgentKind;
use crate::settings::ClashSettings;
use crate::style;
use crate::ui;

#[derive(Default)]
struct InitActions {
    policy_created: bool,
    plugin_installed: bool,
    statusline_installed: bool,
}

/// GitHub repository used to install the clash plugin marketplace.
const GITHUB_MARKETPLACE: &str = "empathic/clash";

/// Embedded agent plugin files — compiled into the binary so `clash init --agent <name>`
/// can install them without needing the source repo.
const OPENCODE_PLUGIN_TS: &str = include_str!("../../clash-opencode/plugin.ts");
const COPILOT_HOOKS_JSON: &str =
    include_str!("../../clash-copilot/.github/hooks/pre-tool-use.json");
const CODEX_HOOKS_TOML: &str = include_str!("../../clash-codex/hooks.toml");
const AMAZONQ_AGENT_JSON: &str = include_str!("../../clash-amazonq/agent.json");
const GEMINI_EXTENSION_JSON: &str = include_str!("../../clash-gemini-ext/gemini-extension.json");
const GEMINI_HOOKS_JSON: &str = include_str!("../../clash-gemini-ext/hooks/hooks.json");

/// Initialize clash at the chosen scope.
///
/// All agents share the same onboarding flow: agent selection (if not
/// specified), policy setup (interactive, quick, or project), then
/// agent-specific plugin installation.
/// Install just the agent plugin/hooks, skipping policy setup.
pub fn run_install(agent: Option<AgentKind>) -> Result<()> {
    let agent = match agent {
        Some(a) => a,
        None => *crate::dialog::select::<AgentKind>("Which coding agent are you installing for?")?,
    };

    let installed = install_agent_plugin(agent)?;
    if installed {
        println!();
        println!(
            "  Run: {}",
            style::bold(&format!("clash doctor --agent {agent}"))
        );
        println!("  to verify the setup is correct.");
    }
    Ok(())
}

#[instrument(level = Level::TRACE)]
pub fn run(agent: Option<AgentKind>) -> Result<()> {
    let agent = match agent {
        Some(a) => a,
        None => *crate::dialog::select::<AgentKind>("Which coding agent are you using?")?,
    };

    let mut actions = InitActions::default();

    let policy_path = write_starter_policy()?;
    actions.plugin_installed = install_agent_plugin(agent)?;
    if agent == AgentKind::Claude {
        if let Err(e) = super::statusline::install() {
            warn!(error = %e, "Could not install status line");
        } else {
            actions.statusline_installed = true;
        }
    }
    crate::tui::run_with_options(&policy_path, false, true)?;
    actions.policy_created = true;
    print_summary(&actions, agent);

    Ok(())
}

/// Write the starter policy.star for onboarding.
///
/// Writes the default policy template as a `.star` file, and compiles it to
/// a `.json` sibling for the runtime to consume.
pub fn write_starter_policy() -> Result<std::path::PathBuf> {
    use crate::settings::compile_default_policy_to_json;

    let policy_path = ClashSettings::policy_file()?;
    let json_path = policy_path.with_extension("json");
    let dir = json_path
        .parent()
        .context("policy file path has no parent directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;

    let json = compile_default_policy_to_json().context("compiling default policy")?;
    std::fs::write(&json_path, &json)
        .with_context(|| format!("failed to write {}", json_path.display()))?;

    Ok(json_path)
}

// ---------------------------------------------------------------------------
// Agent plugin installation
// ---------------------------------------------------------------------------

/// Install the agent-specific plugin/hooks. Returns true if installation succeeded.
fn install_agent_plugin(agent: AgentKind) -> Result<bool> {
    println!();
    style::header(&format!("Installing {agent} plugin"));
    println!();

    match agent {
        AgentKind::Claude => install_claude_plugin(),
        AgentKind::Gemini => install_gemini_plugin(),
        AgentKind::Codex => install_codex_plugin(),
        AgentKind::AmazonQ => install_amazonq_plugin(),
        AgentKind::OpenCode => install_opencode_plugin(),
        AgentKind::Copilot => install_copilot_plugin(),
    }
}

fn install_claude_plugin() -> Result<bool> {
    // Ensure settings.json records clash as an enabled plugin.
    let claude = claude_settings::ClaudeSettings::new();
    if let Err(e) = claude.set_plugin_enabled(claude_settings::SettingsLevel::User, "clash", true) {
        warn!(error = %e, "Could not set enabledPlugins in Claude Code settings");
    }

    match install_plugin_from_marketplace() {
        Ok(()) => Ok(true),
        Err(e) => {
            error!(error = %e, "Could not install clash plugin");
            ui::warn(&format!(
                "Could not install the clash plugin: {e}\n  \
                 You can install it manually later:\n    \
                 claude plugin marketplace add {GITHUB_MARKETPLACE}\n    \
                 claude plugin install clash"
            ));
            Ok(false)
        }
    }
}

fn install_gemini_plugin() -> Result<bool> {
    let ext_dir = std::env::temp_dir().join("clash-gemini-ext");
    let hooks_dir = ext_dir.join("hooks");
    std::fs::create_dir_all(&hooks_dir)
        .context("failed to create hooks directory in temp extension")?;
    std::fs::write(ext_dir.join("gemini-extension.json"), GEMINI_EXTENSION_JSON)
        .context("failed to write gemini-extension.json")?;
    std::fs::write(hooks_dir.join("hooks.json"), GEMINI_HOOKS_JSON)
        .context("failed to write hooks/hooks.json")?;

    let output = std::process::Command::new("gemini")
        .args(["extensions", "install", &ext_dir.display().to_string()])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            ui::success("Clash extension installed in Gemini CLI");
            Ok(true)
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            ui::warn(&format!(
                "Could not install Gemini extension: {stderr}\n  \
                 You can install it manually later:\n    \
                 gemini extensions install <path-to-extension-dir>"
            ));
            Ok(false)
        }
        Err(e) => {
            ui::warn(&format!(
                "Could not run gemini CLI: {e}\n  \
                 Install the Gemini CLI, then run:\n    \
                 clash init --agent gemini"
            ));
            Ok(false)
        }
    }
}

fn install_codex_plugin() -> Result<bool> {
    let codex_dir = dirs::home_dir()
        .context("could not determine home directory")?
        .join(".codex");
    std::fs::create_dir_all(&codex_dir)
        .with_context(|| format!("failed to create {}", codex_dir.display()))?;
    let dest = codex_dir.join("config.toml");
    let clash_hooks: toml::Value =
        toml::from_str(CODEX_HOOKS_TOML).context("failed to parse embedded Codex hooks TOML")?;
    if dest.exists() {
        let existing = std::fs::read_to_string(&dest)
            .with_context(|| format!("failed to read {}", dest.display()))?;
        let mut config: toml::Value = toml::from_str(&existing)
            .with_context(|| format!("failed to parse {}", dest.display()))?;
        // Merge clash hooks into the existing [hooks] table.
        let hooks_table = config
            .as_table_mut()
            .context("codex config is not a TOML table")?
            .entry("hooks")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        if let (Some(dst), Some(src)) = (
            hooks_table.as_table_mut(),
            clash_hooks.get("hooks").and_then(|h| h.as_table()),
        ) {
            for (key, value) in src {
                dst.insert(key.clone(), value.clone());
            }
        }
        std::fs::write(&dest, toml::to_string_pretty(&config)?)
            .with_context(|| format!("failed to write {}", dest.display()))?;
        ui::success(&format!("Clash hooks merged into {}", dest.display()));
    } else {
        std::fs::write(&dest, CODEX_HOOKS_TOML)
            .with_context(|| format!("failed to write {}", dest.display()))?;
        ui::success(&format!("Hooks config installed at {}", dest.display()));
    }
    Ok(true)
}

fn install_amazonq_plugin() -> Result<bool> {
    let amazonq_dir = dirs::home_dir()
        .context("could not determine home directory")?
        .join(".amazonq");
    std::fs::create_dir_all(&amazonq_dir)
        .with_context(|| format!("failed to create {}", amazonq_dir.display()))?;
    let dest = amazonq_dir.join("agent.json");
    let clash_hooks: serde_json::Value = serde_json::from_str(AMAZONQ_AGENT_JSON)
        .context("failed to parse embedded Amazon Q hooks JSON")?;
    if dest.exists() {
        let existing = std::fs::read_to_string(&dest)
            .with_context(|| format!("failed to read {}", dest.display()))?;
        let mut config: serde_json::Value = serde_json::from_str(&existing)
            .with_context(|| format!("failed to parse {}", dest.display()))?;
        // Merge clash hook arrays into the existing "hooks" object.
        let dst_hooks = config
            .as_object_mut()
            .context("amazonq config is not a JSON object")?
            .entry("hooks")
            .or_insert_with(|| json!({}));
        if let (Some(dst), Some(src)) = (
            dst_hooks.as_object_mut(),
            clash_hooks.get("hooks").and_then(|h| h.as_object()),
        ) {
            for (key, value) in src {
                dst.insert(key.clone(), value.clone());
            }
        }
        std::fs::write(&dest, serde_json::to_string_pretty(&config)?)
            .with_context(|| format!("failed to write {}", dest.display()))?;
        ui::success(&format!("Clash hooks merged into {}", dest.display()));
    } else {
        std::fs::write(&dest, AMAZONQ_AGENT_JSON)
            .with_context(|| format!("failed to write {}", dest.display()))?;
        ui::success(&format!("Hooks config installed at {}", dest.display()));
    }
    Ok(true)
}

fn install_opencode_plugin() -> Result<bool> {
    let plugins_dir = dirs::home_dir()
        .context("could not determine home directory")?
        .join(".opencode")
        .join("plugins");
    std::fs::create_dir_all(&plugins_dir)
        .context("failed to create ~/.opencode/plugins directory")?;
    let dest = plugins_dir.join("clash.ts");
    std::fs::write(&dest, OPENCODE_PLUGIN_TS)
        .with_context(|| format!("failed to write {}", dest.display()))?;
    ui::success(&format!("Plugin installed at {}", dest.display()));
    Ok(true)
}

fn install_copilot_plugin() -> Result<bool> {
    let hooks_dir = std::path::Path::new(".github/hooks");
    std::fs::create_dir_all(hooks_dir).context("failed to create .github/hooks directory")?;
    let dest = hooks_dir.join("pre-tool-use.json");
    std::fs::write(&dest, COPILOT_HOOKS_JSON)
        .with_context(|| format!("failed to write {}", dest.display()))?;
    ui::success(&format!("Hooks installed at {}", dest.display()));
    Ok(true)
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

fn print_summary(actions: &InitActions, agent: AgentKind) {
    let any_action =
        actions.policy_created || actions.plugin_installed || actions.statusline_installed;
    if !any_action {
        return;
    }

    println!();
    println!(
        "{}",
        style::bold("Setup complete! Here's what was configured:")
    );
    println!();

    if actions.policy_created {
        ui::success("Policy created");
    }
    if actions.plugin_installed {
        ui::success(&format!("Clash plugin installed for {agent}"));
    }
    if actions.statusline_installed {
        ui::success("Status line installed");
    }

    println!();
    println!("{}:", style::bold("To undo"));
    println!(
        "  {}  {}",
        style::dim("clash uninstall"),
        style::dim("# remove everything")
    );
    if actions.policy_created {
        println!(
            "  {}  {}",
            style::dim("clash policy edit"),
            style::dim("# modify your policy")
        );
    }

    println!();
    println!("{}:", style::bold("Next steps"));
    println!(
        "  {}  {}",
        style::dim(&format!("clash doctor --agent {agent}")),
        style::dim("# verify the setup is correct")
    );
    println!(
        "  {}  {}",
        style::dim("clash policy show"),
        style::dim("# view the compiled policy")
    );
}

// ---------------------------------------------------------------------------
// Claude marketplace helpers
// ---------------------------------------------------------------------------

/// Install the clash plugin into Claude Code from the GitHub marketplace.
pub fn install_plugin_from_marketplace() -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starter_policy_compiles() {
        use crate::settings::compile_default_policy_to_json;
        let json_str = compile_default_policy_to_json().expect("compile default policy");
        crate::policy::compile::compile_to_tree(&json_str)
            .expect("starter policy must compile without errors");
    }
}
