//! Sandbox enforcement inspection.
//!
//! Shows what a sandbox would enforce for a given command: the policy,
//! platform-specific compiled profile, effective capabilities per path,
//! and network restrictions.

use std::path::Path;

use anyhow::{Context, Result};

use crate::display;
use crate::policy::sandbox_types::{Cap, NetworkPolicy, SandboxPolicy};
use crate::settings::ClashSettings;
use crate::style;

/// Detailed inspection of a sandbox enforcement.
pub struct SandboxReport {
    /// The tool name evaluated.
    pub tool_name: String,
    /// The full tool input arguments.
    pub tool_input: serde_json::Value,
    /// The sandbox policy (if the command would be sandboxed).
    pub sandbox: Option<SandboxPolicy>,
    /// Platform-specific compiled profile (SBPL on macOS).
    pub compiled_profile: Option<String>,
    /// Effective capabilities for notable paths.
    pub path_caps: Vec<(String, Cap)>,
    /// The overall policy effect for this command.
    pub effect: crate::policy::Effect,
}

impl SandboxReport {
    /// Render as human-readable text.
    pub fn format_human(&self) -> String {
        let mut lines =
            display::format_tool_header("Sandbox inspection:", &self.tool_name, &self.tool_input);
        lines.push(format!(
            "  {} {}",
            style::cyan("effect:"),
            style::effect(&self.effect.to_string())
        ));
        lines.push(String::new());

        match &self.sandbox {
            Some(sandbox) => {
                lines.push(style::header("Sandbox policy:").to_string());
                lines.push(format!(
                    "  {}: {}",
                    style::cyan("default caps"),
                    sandbox.default.display()
                ));
                lines.push(format!(
                    "  {}:    {}",
                    style::cyan("network"),
                    format_network(&sandbox.network),
                ));

                if !sandbox.rules.is_empty() {
                    lines.push(String::new());
                    lines.push(format!("  {}:", style::cyan("rules")));
                    for rule in &sandbox.rules {
                        let eff = match rule.effect {
                            crate::policy::sandbox_types::RuleEffect::Allow => {
                                style::green("allow")
                            }
                            crate::policy::sandbox_types::RuleEffect::Deny => style::red("deny"),
                        };
                        lines.push(format!(
                            "    {} {} in {} ({})",
                            eff,
                            rule.caps.short(),
                            rule.path,
                            format!("{:?}", rule.path_match).to_lowercase(),
                        ));
                    }
                }

                // Effective capabilities for notable paths
                if !self.path_caps.is_empty() {
                    lines.push(String::new());
                    lines.push(style::header("Effective capabilities:").to_string());
                    for (path, caps) in &self.path_caps {
                        let caps_str = if caps.is_empty() {
                            style::red("none")
                        } else {
                            caps.short()
                        };
                        lines.push(format!("  {:<40}  {}", path, caps_str));
                    }
                }

                // Compiled profile
                if let Some(ref profile) = self.compiled_profile {
                    lines.push(String::new());
                    lines.push(style::header("Compiled profile:").to_string());
                    for line in profile.lines() {
                        lines.push(format!("  {}", style::dim(line)));
                    }
                }
            }
            None => {
                if self.effect == crate::policy::Effect::Allow {
                    lines.push(format!(
                        "  {}",
                        style::dim("This command is allowed without sandbox enforcement.")
                    ));
                    lines.push(format!(
                        "  {}",
                        style::dim(
                            "To add sandbox restrictions, use :sandbox in your policy rules."
                        )
                    ));
                } else {
                    lines.push(format!(
                        "  {}",
                        style::dim("This command is denied by policy — sandbox does not apply.")
                    ));
                }
            }
        }

        lines.join("\n")
    }

    /// Render as JSON.
    pub fn format_json(&self) -> Result<String> {
        let output = serde_json::json!({
            "tool_name": self.tool_name,
            "tool_input": self.tool_input,
            "effect": format!("{}", self.effect),
            "sandbox": self.sandbox.as_ref().map(|s| serde_json::to_value(s).ok()),
            "compiled_profile": self.compiled_profile,
            "effective_caps": self.path_caps.iter().map(|(path, caps)| {
                serde_json::json!({
                    "path": path,
                    "caps": caps.short(),
                })
            }).collect::<Vec<_>>(),
        });
        serde_json::to_string_pretty(&output).context("failed to serialize sandbox report")
    }
}

/// Inspect sandbox enforcement for an audit log entry identified by its short hash.
pub fn inspect_hash(hash: &str) -> Result<SandboxReport> {
    let entry = crate::debug::log::find_by_hash(hash)?;
    inspect_with_mode(
        &entry.tool_name,
        Some(&entry.tool_input_summary),
        entry.mode.as_deref(),
    )
}

/// Execute a command under sandbox enforcement, resolved from an audit log entry.
///
/// Delegates to `clash shell -c <cmd>` which handles sandbox enforcement
/// itself, avoiding double-nesting of sandbox wrappers. Passes `--sandbox`
/// so the correct sandbox policy is applied.
pub fn exec_entry(entry: &super::AuditLogEntry) -> Result<()> {
    let (tool_name, tool_input) = crate::debug::replay::resolve_tool_input(
        &entry.tool_name,
        Some(&entry.tool_input_summary),
    )?;

    let cmd = extract_shell_command_str(&tool_name, &tool_input).ok_or_else(|| {
        anyhow::anyhow!(
            "cannot execute tool '{}' in a sandbox — only Bash commands are supported",
            tool_name,
        )
    })?;

    // Evaluate the policy to find the sandbox name.
    let settings = ClashSettings::load_or_create()?;
    let tree = settings
        .policy_tree()
        .ok_or_else(|| anyhow::anyhow!("no compiled policy available — run `clash init`"))?;
    let decision =
        tree.evaluate_with_mode(&tool_name, &tool_input, entry.mode.as_deref());
    let sandbox_name = decision
        .sandbox_name
        .as_ref()
        .map(|sr| sr.0.as_str());

    let clash_bin = std::env::current_exe().context("failed to locate clash binary")?;

    let mut args = vec!["shell"];
    if let Some(name) = sandbox_name {
        eprintln!("Replaying in sandbox '{}': clash shell -c {}", name, cmd);
        args.extend(["--sandbox", name]);
    } else {
        eprintln!("Replaying: clash shell -c {}", cmd);
    }
    args.extend(["-c", &cmd]);

    let status = std::process::Command::new(clash_bin)
        .args(&args)
        .status()
        .context("failed to execute clash shell")?;

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

/// Extract the raw shell command string from a Bash tool invocation.
///
/// Returns `Some(command_string)` for Bash tool inputs,
/// `None` for other tools.
fn extract_shell_command_str(tool_name: &str, tool_input: &serde_json::Value) -> Option<String> {
    if tool_name != "Bash" {
        return None;
    }
    tool_input.get("command")?.as_str().map(|s| s.to_string())
}

/// Inspect sandbox enforcement for a tool invocation (no mode context).
pub fn inspect(tool: &str, input: Option<&str>) -> Result<SandboxReport> {
    inspect_with_mode(tool, input, None)
}

/// Inspect sandbox enforcement for a tool invocation with mode context.
pub fn inspect_with_mode(
    tool: &str,
    input: Option<&str>,
    mode: Option<&str>,
) -> Result<SandboxReport> {
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    let (tool_name, tool_input) = crate::debug::replay::resolve_tool_input(tool, input)?;

    let settings = ClashSettings::load_or_create()?;
    let tree = settings
        .policy_tree()
        .ok_or_else(|| anyhow::anyhow!("no compiled policy available — run `clash init`"))?;

    let decision = tree.evaluate_with_mode(&tool_name, &tool_input, mode);

    let sandbox = decision.sandbox.clone();
    let cwd_path = Path::new(&cwd);

    // Compile platform-specific profile if sandbox is present.
    let compiled_profile = sandbox
        .as_ref()
        .and_then(|s| crate::sandbox::compile_sandbox_profile(s, cwd_path).ok());

    // Compute effective capabilities for notable paths.
    let path_caps = if let Some(ref s) = sandbox {
        compute_notable_path_caps(s, &cwd)
    } else {
        Vec::new()
    };

    Ok(SandboxReport {
        tool_name,
        tool_input,
        sandbox,
        compiled_profile,
        path_caps,
        effect: decision.effect,
    })
}

/// Compute effective capabilities for a set of notable paths.
fn compute_notable_path_caps(policy: &SandboxPolicy, cwd: &str) -> Vec<(String, Cap)> {
    let resolver = crate::policy::path::PathResolver::from_env();
    let home = if resolver.home().is_empty() {
        "/home".to_string()
    } else {
        resolver.home().to_string()
    };
    let tmpdir = resolver.tmpdir().to_string();

    let mut paths = vec![
        (cwd.to_string(), "CWD"),
        (home.clone(), "HOME"),
        (tmpdir.clone(), "TMPDIR"),
        ("/".to_string(), "/"),
    ];

    // Add paths from sandbox rules.
    for rule in &policy.rules {
        let resolved = SandboxPolicy::resolve_path(&rule.path, cwd);
        if !paths.iter().any(|(p, _)| *p == resolved) {
            paths.push((resolved, ""));
        }
    }

    paths
        .into_iter()
        .map(|(path, label)| {
            let caps = policy.effective_caps(&path, cwd);
            let display = if label.is_empty() {
                path
            } else {
                format!("{path} ({label})")
            };
            (display, caps)
        })
        .collect()
}

/// Format a network policy for display.
fn format_network(network: &NetworkPolicy) -> String {
    match network {
        NetworkPolicy::Deny => style::red("denied (all network blocked)"),
        NetworkPolicy::Allow => style::green("allowed (unrestricted)"),
        NetworkPolicy::Localhost => style::yellow("localhost only"),
        NetworkPolicy::AllowDomains(domains) => {
            format!("{}: {}", style::yellow("filtered"), domains.join(", "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::sandbox_types::{NetworkPolicy, PathMatch, RuleEffect, SandboxRule};

    #[test]
    fn test_compute_notable_path_caps() {
        let policy = SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![SandboxRule {
                effect: RuleEffect::Allow,
                caps: Cap::all(),
                path: "/tmp".into(),
                path_match: PathMatch::Subpath,
                follow_worktrees: false,
                doc: None,
            }],
            network: NetworkPolicy::Deny,
            doc: None,
        };

        let caps = compute_notable_path_caps(&policy, "/home/user/project");
        assert!(!caps.is_empty());
    }

    #[test]
    fn test_format_network_deny() {
        let s = format_network(&NetworkPolicy::Deny);
        assert!(s.contains("denied"));
    }

    #[test]
    fn test_format_network_allow() {
        let s = format_network(&NetworkPolicy::Allow);
        assert!(s.contains("unrestricted"));
    }

    #[test]
    fn test_format_network_localhost() {
        let s = format_network(&NetworkPolicy::Localhost);
        assert!(s.contains("localhost"));
    }

    #[test]
    fn test_format_network_domains() {
        let s = format_network(&NetworkPolicy::AllowDomains(vec![
            "github.com".into(),
            "api.github.com".into(),
        ]));
        assert!(s.contains("github.com"));
    }
}
