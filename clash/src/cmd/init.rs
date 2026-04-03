use anyhow::{Context, Result};
use serde_json::json;
use tracing::{Level, instrument, warn};

use crate::agents::AgentKind;
use crate::settings::ClashSettings;
use crate::style;
use crate::ui;

#[derive(Default)]
struct InitActions {
    /// Whether a new policy file was created (false when one already existed).
    policy_created: bool,
    /// Whether the policy was reviewed/edited via the TUI (true even for existing policies).
    policy_reviewed: bool,
    plugin_installed: bool,
    statusline_installed: bool,
}

/// Command prefix used for all clash hooks installed into Claude Code settings.
const HOOK_CMD_PREFIX: &str = "clash hook";

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

/// Minimal init: install hooks/plugin only, no policy generation.
pub fn run_no_import(agent: Option<AgentKind>) -> Result<()> {
    let agent = match agent {
        Some(a) => a,
        None => *crate::dialog::select::<AgentKind>("Which coding agent are you using?")?,
    };

    install_agent_plugin(agent)?;

    if agent == AgentKind::Claude {
        if let Err(e) = super::statusline::install() {
            warn!(error = %e, "Could not install status line");
        }
    }

    println!();
    ui::success("Clash hooks installed.");
    println!();
    println!(
        "  Run {} to configure your policy.",
        style::bold("clash policy edit")
    );
    println!(
        "  Run {} to verify the setup.",
        style::bold(&format!("clash doctor --agent {agent}"))
    );

    Ok(())
}

#[instrument(level = Level::TRACE)]
pub fn run(agent: Option<AgentKind>) -> Result<()> {
    let agent = match agent {
        Some(a) => a,
        None => *crate::dialog::select::<AgentKind>("Which coding agent are you using?")?,
    };

    let mut actions = InitActions::default();

    let (policy_path, created_new) = match detect_and_generate_policy()? {
        Some(policy_content) => {
            let path = write_detected_policy(&policy_content)?;
            (path, true)
        }
        None => ensure_starter_policy()?,
    };
    let outcome = crate::tui::run_with_options(&policy_path, false, true)?;
    if outcome == crate::tui::TuiOutcome::Aborted {
        if created_new {
            let _ = std::fs::remove_file(&policy_path);
        }
        println!();
        ui::warn("Setup cancelled. Run `clash init` to try again.");
        return Ok(());
    }
    actions.policy_created = created_new;
    actions.policy_reviewed = true;

    actions.plugin_installed = install_agent_plugin(agent)?;
    if agent == AgentKind::Claude {
        if let Err(e) = super::statusline::install() {
            warn!(error = %e, "Could not install status line");
        } else {
            actions.statusline_installed = true;
        }
    }
    print_summary(&actions, agent);

    Ok(())
}

/// Run ecosystem detection and return a generated policy, or None if the user
/// declines or no ecosystems are detected.
fn detect_and_generate_policy() -> Result<Option<String>> {
    println!();
    let scan = crate::dialog::confirm(
        "Scan your project and command history to recommend sandboxes?",
        false,
    )?;
    if !scan {
        return Ok(None);
    }

    let cwd = std::env::current_dir().context("getting current directory")?;
    let observed = crate::cmd::from_trace::mine_binaries_from_history();
    let observed_refs: Vec<&str> = observed.iter().map(|s| s.as_str()).collect();
    let detected = crate::ecosystem::detect_ecosystems(&cwd, &observed_refs);

    if detected.is_empty() {
        ui::info("No ecosystems detected.");
        return Ok(None);
    }

    println!();
    ui::info("Detected ecosystems:");
    println!();
    for eco in &detected {
        let mut reasons = Vec::new();
        for m in eco.markers {
            if cwd.join(m).exists() {
                reasons.push(format!("found {m}"));
            }
        }
        for m in eco.dir_markers {
            if cwd.join(m).is_dir() {
                reasons.push(format!("found {m}/"));
            }
        }
        for bin in eco.binaries {
            if observed.contains(*bin) {
                reasons.push(format!("observed: {bin}"));
            }
        }
        let reason_str = if reasons.is_empty() {
            String::new()
        } else {
            format!("  ({})", reasons.join(", "))
        };
        ui::success(&format!("  {:<12}{}", eco.name, reason_str));
    }
    println!();

    let include = crate::dialog::confirm("Include these sandboxes in your policy?", false)?;
    if !include {
        return Ok(None);
    }

    Ok(Some(crate::ecosystem::generate_policy(&detected)))
}

/// Write a detected/generated policy to the policy file location.
fn write_detected_policy(content: &str) -> Result<std::path::PathBuf> {
    let policy_path = ClashSettings::policy_file()?;
    let star_path = policy_path.with_extension("star");
    let dir = star_path
        .parent()
        .context("policy file path has no parent directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    std::fs::write(&star_path, content)
        .with_context(|| format!("failed to write {}", star_path.display()))?;
    Ok(star_path)
}

/// Ensure a policy file exists, writing the starter template only if one
/// doesn't already exist. Returns `(path, created_new)`.
pub fn ensure_starter_policy() -> Result<(std::path::PathBuf, bool)> {
    let policy_path = ClashSettings::policy_file()?;
    let star_path = policy_path.with_extension("star");
    if star_path.exists() {
        return Ok((star_path, false));
    }
    let path = write_starter_policy()?;
    Ok((path, true))
}

/// Write the starter policy.star for onboarding.
///
/// Copies the embedded default policy template to `~/.clash/policy.star`.
pub fn write_starter_policy() -> Result<std::path::PathBuf> {
    let policy_path = ClashSettings::policy_file()?;
    let star_path = policy_path.with_extension("star");
    let dir = star_path
        .parent()
        .context("policy file path has no parent directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;

    let source = include_str!("../default_policy.star");
    std::fs::write(&star_path, source)
        .with_context(|| format!("failed to write {}", star_path.display()))?;

    Ok(star_path)
}

// ---------------------------------------------------------------------------
// Agent plugin installation
// ---------------------------------------------------------------------------

/// Install the agent-specific plugin/hooks. Returns true if installation succeeded.
pub(crate) fn install_agent_plugin(agent: AgentKind) -> Result<bool> {
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
    let claude = claude_settings::ClaudeSettings::new();

    // Write hooks directly into ~/.claude/settings.json.
    // This is more reliable than the plugin marketplace flow, which requires
    // Claude Code to resolve plugin directories at runtime.
    claude
        .update(claude_settings::SettingsLevel::User, |settings| {
            let hooks = settings.hooks.get_or_insert_with(Default::default);
            install_clash_hook_config(hooks);
            settings.mark_clash_installed();
        })
        .context("writing clash hooks to Claude Code settings")?;

    ui::success("Clash hooks installed in Claude Code settings.");
    Ok(true)
}

/// Install clash hook commands into a `Hooks` config.
///
/// Public so `doctor.rs` can reuse it for the fix-up flow.
///
/// Each hook event gets a `clash hook <event>` command with a wildcard matcher.
/// Existing non-clash hooks are preserved.
pub fn install_clash_hook_config(hooks: &mut claude_settings::Hooks) {
    use claude_settings::{Hook, HookMatcher};

    let cmd_hook = |subcommand: &str| HookMatcher {
        matcher: String::new(),
        hooks: vec![Hook {
            hook_type: "command".into(),
            command: Some(format!("{HOOK_CMD_PREFIX} {subcommand}")),
            timeout: None,
        }],
    };

    let cmd_hook_matched = |subcommand: &str| HookMatcher {
        matcher: "*".into(),
        hooks: vec![Hook {
            hook_type: "command".into(),
            command: Some(format!("{HOOK_CMD_PREFIX} {subcommand}")),
            timeout: None,
        }],
    };

    // For config types that use HookConfig (matcher-based), merge with existing hooks.
    let merge_hook_config = |existing: &mut Option<claude_settings::HookConfig>,
                             subcommand: &str| {
        let clash_cmd = format!("{HOOK_CMD_PREFIX} {subcommand}");
        match existing {
            Some(config) => {
                // Check if clash hook is already present.
                let already_installed = match config {
                    claude_settings::HookConfig::Simple(map) => {
                        map.values().any(|v| v.contains(HOOK_CMD_PREFIX))
                    }
                    claude_settings::HookConfig::Matchers(matchers) => matchers.iter().any(|m| {
                        m.hooks.iter().any(|h| {
                            h.command
                                .as_deref()
                                .is_some_and(|c| c.contains(HOOK_CMD_PREFIX))
                        })
                    }),
                };
                if !already_installed {
                    *config = config.clone().insert("*", &clash_cmd);
                }
            }
            None => {
                *existing = Some(claude_settings::HookConfig::Matchers(vec![
                    cmd_hook_matched(subcommand),
                ]));
            }
        }
    };

    merge_hook_config(&mut hooks.pre_tool_use, "pre-tool-use");
    merge_hook_config(&mut hooks.post_tool_use, "post-tool-use");
    merge_hook_config(&mut hooks.permission_request, "permission-request");
    merge_hook_config(&mut hooks.notification, "notification");

    // SessionStart uses Vec<HookMatcher> directly (no matcher pattern needed).
    let session_already = hooks.session_start.as_ref().is_some_and(|matchers| {
        matchers.iter().any(|m| {
            m.hooks.iter().any(|h| {
                h.command
                    .as_deref()
                    .is_some_and(|c| c.contains(HOOK_CMD_PREFIX))
            })
        })
    });
    if !session_already {
        hooks
            .session_start
            .get_or_insert_with(Vec::new)
            .push(cmd_hook("session-start"));
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
    let any_action = actions.policy_created
        || actions.policy_reviewed
        || actions.plugin_installed
        || actions.statusline_installed;
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
    } else if actions.policy_reviewed {
        ui::success("Policy reviewed");
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

/// Remove clash hooks from a `Hooks` config, preserving non-clash hooks.
///
/// Returns `true` if any hooks were removed.
pub fn uninstall_clash_hooks(hooks: &mut claude_settings::Hooks) -> bool {
    let mut changed = false;
    changed |= remove_clash_from_config(&mut hooks.pre_tool_use);
    changed |= remove_clash_from_config(&mut hooks.post_tool_use);
    changed |= remove_clash_from_config(&mut hooks.permission_request);
    changed |= remove_clash_from_config(&mut hooks.notification);
    changed |= remove_clash_from_vec(&mut hooks.session_start);
    changed |= remove_clash_from_vec(&mut hooks.stop);
    changed
}

fn is_clash_hook(h: &claude_settings::Hook) -> bool {
    h.command
        .as_deref()
        .is_some_and(|c| c.contains(HOOK_CMD_PREFIX))
}

fn remove_clash_from_config(config: &mut Option<claude_settings::HookConfig>) -> bool {
    let Some(c) = config.take() else {
        return false;
    };
    match c {
        claude_settings::HookConfig::Simple(mut map) => {
            let before = map.len();
            map.retain(|_, v| !v.contains(HOOK_CMD_PREFIX));
            let removed = map.len() != before;
            if !map.is_empty() {
                *config = Some(claude_settings::HookConfig::Simple(map));
            }
            removed
        }
        claude_settings::HookConfig::Matchers(mut matchers) => {
            let before = matchers.len();
            for m in &mut matchers {
                m.hooks.retain(|h| !is_clash_hook(h));
            }
            matchers.retain(|m| !m.hooks.is_empty());
            let removed = matchers.len() != before;
            if !matchers.is_empty() {
                *config = Some(claude_settings::HookConfig::Matchers(matchers));
            }
            removed
        }
    }
}

fn remove_clash_from_vec(opt: &mut Option<Vec<claude_settings::HookMatcher>>) -> bool {
    let Some(mut v) = opt.take() else {
        return false;
    };
    let before = v.len();
    for m in &mut v {
        m.hooks.retain(|h| !is_clash_hook(h));
    }
    v.retain(|m| !m.hooks.is_empty());
    let removed = v.len() != before;
    if !v.is_empty() {
        *opt = Some(v);
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detected_policy_compiles() {
        let ecosystems: Vec<&crate::ecosystem::EcosystemDef> = crate::ecosystem::ECOSYSTEMS
            .iter()
            .filter(|e| e.name == "rust" || e.name == "git")
            .collect();
        let starlark = crate::ecosystem::generate_policy(&ecosystems);
        let output = clash_starlark::evaluate(&starlark, "<test>", std::path::Path::new("."))
            .expect("detected policy must evaluate");
        crate::policy::compile::compile_to_tree(&output.json)
            .expect("detected policy must compile");
    }

    #[test]
    fn starter_policy_compiles() {
        use crate::settings::compile_default_policy_to_json;
        let json_str = compile_default_policy_to_json().expect("compile default policy");
        crate::policy::compile::compile_to_tree(&json_str)
            .expect("starter policy must compile without errors");
    }

    #[test]
    fn rust_sandbox_compiles() {
        let source = "load(\"@clash//rust.star\", \"rust_safe\", \"rust_full\")\n\npolicy(\"test\", {Tool(\"Bash\"): {(\"cargo\", \"rustc\", \"rustup\"): {glob(\"**\"): allow(sandbox=rust_safe)}}})";
        let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
            .expect("rust sandbox starlark evaluation");
        crate::policy::compile::compile_to_tree(&output.json).expect("rust sandbox must compile");
    }

    #[test]
    fn python_sandbox_compiles() {
        let source = "load(\"@clash//python.star\", \"python_full\")\n\npolicy(\"test\", {Tool(\"Bash\"): {(\"python\", \"python3\"): {glob(\"**\"): allow(sandbox=python_full)}}})";
        let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
            .expect("python sandbox starlark evaluation");
        crate::policy::compile::compile_to_tree(&output.json).expect("python sandbox must compile");
    }

    #[test]
    fn node_sandbox_compiles() {
        let source = "load(\"@clash//node.star\", \"node_full\")\n\npolicy(\"test\", {Tool(\"Bash\"): {(\"node\", \"npm\"): {glob(\"**\"): allow(sandbox=node_full)}}})";
        let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
            .expect("node sandbox starlark evaluation");
        crate::policy::compile::compile_to_tree(&output.json).expect("node sandbox must compile");
    }

    #[test]
    fn go_sandbox_compiles() {
        let source = "load(\"@clash//go.star\", \"go_safe\", \"go_full\")\n\npolicy(\"test\", {Tool(\"Bash\"): {\"go\": {glob(\"**\"): allow(sandbox=go_safe)}}})";
        let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
            .expect("go sandbox starlark evaluation");
        crate::policy::compile::compile_to_tree(&output.json).expect("go sandbox must compile");
    }

    #[test]
    fn java_sandbox_compiles() {
        let source = "load(\"@clash//java.star\", \"java_full\")\n\npolicy(\"test\", {Tool(\"Bash\"): {(\"gradle\", \"mvn\"): {glob(\"**\"): allow(sandbox=java_full)}}})";
        let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
            .expect("java sandbox starlark evaluation");
        crate::policy::compile::compile_to_tree(&output.json).expect("java sandbox must compile");
    }

    #[test]
    fn ruby_sandbox_compiles() {
        let source = "load(\"@clash//ruby.star\", \"ruby_full\")\n\npolicy(\"test\", {Tool(\"Bash\"): {(\"ruby\", \"gem\", \"bundle\"): {glob(\"**\"): allow(sandbox=ruby_full)}}})";
        let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
            .expect("ruby sandbox starlark evaluation");
        crate::policy::compile::compile_to_tree(&output.json).expect("ruby sandbox must compile");
    }

    #[test]
    fn docker_sandbox_compiles() {
        let source = "load(\"@clash//docker.star\", \"docker_safe\", \"docker_full\")\n\npolicy(\"test\", {Tool(\"Bash\"): {(\"docker\", \"podman\"): {glob(\"**\"): allow(sandbox=docker_safe)}}})";
        let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
            .expect("docker sandbox starlark evaluation");
        crate::policy::compile::compile_to_tree(&output.json).expect("docker sandbox must compile");
    }

    #[test]
    fn swift_sandbox_compiles() {
        let source = "load(\"@clash//swift.star\", \"swift_full\")\n\npolicy(\"test\", {Tool(\"Bash\"): {(\"swift\", \"xcodebuild\"): {glob(\"**\"): allow(sandbox=swift_full)}}})";
        let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
            .expect("swift sandbox starlark evaluation");
        crate::policy::compile::compile_to_tree(&output.json).expect("swift sandbox must compile");
    }

    #[test]
    fn dotnet_sandbox_compiles() {
        let source = "load(\"@clash//dotnet.star\", \"dotnet_full\")\n\npolicy(\"test\", {Tool(\"Bash\"): {(\"dotnet\", \"msbuild\"): {glob(\"**\"): allow(sandbox=dotnet_full)}}})";
        let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
            .expect("dotnet sandbox starlark evaluation");
        crate::policy::compile::compile_to_tree(&output.json).expect("dotnet sandbox must compile");
    }

    #[test]
    fn make_sandbox_compiles() {
        let source = "load(\"@clash//make.star\", \"make_full\")\n\npolicy(\"test\", {Tool(\"Bash\"): {(\"make\", \"cmake\", \"just\"): {glob(\"**\"): allow(sandbox=make_full)}}})";
        let output = clash_starlark::evaluate(source, "<test>", std::path::Path::new("."))
            .expect("make sandbox starlark evaluation");
        crate::policy::compile::compile_to_tree(&output.json).expect("make sandbox must compile");
    }
}
