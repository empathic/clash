//! Sandbox enforcement inspection.
//!
//! Shows what a sandbox would enforce for a given command: the policy,
//! platform-specific compiled profile, effective capabilities per path,
//! and network restrictions.

use std::path::Path;

use anyhow::{Context, Result};

use crate::policy::sandbox_types::{Cap, NetworkPolicy, SandboxPolicy};
use crate::settings::ClashSettings;
use crate::style;

/// Detailed inspection of a sandbox enforcement.
pub struct SandboxReport {
    /// The tool name evaluated.
    pub tool_name: String,
    /// Human-readable subject.
    pub noun: String,
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
        let mut lines = Vec::new();

        lines.push(style::bold("Sandbox inspection:").to_string());
        lines.push(format!("  {}   {}", style::cyan("tool:"), self.tool_name));
        lines.push(format!("  {}   {}", style::cyan("noun:"), self.noun));
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
                            rule.caps.display(),
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
                            caps.display()
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
            "noun": self.noun,
            "effect": format!("{}", self.effect),
            "sandbox": self.sandbox.as_ref().map(|s| serde_json::to_value(s).ok()),
            "compiled_profile": self.compiled_profile,
            "effective_caps": self.path_caps.iter().map(|(path, caps)| {
                serde_json::json!({
                    "path": path,
                    "caps": caps.display(),
                })
            }).collect::<Vec<_>>(),
        });
        serde_json::to_string_pretty(&output).context("failed to serialize sandbox report")
    }
}

/// Inspect sandbox enforcement for a tool invocation.
pub fn inspect(tool: &str, input: Option<&str>) -> Result<SandboxReport> {
    let cwd = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    let (tool_name, tool_input) = crate::debug::replay::resolve_tool_input(tool, input)?;

    let settings = ClashSettings::load_or_create()?;
    let tree = settings
        .decision_tree()
        .ok_or_else(|| anyhow::anyhow!("no compiled policy available — run `clash init`"))?;

    let decision = tree.evaluate(&tool_name, &tool_input, &cwd);
    let noun = crate::permissions::extract_noun(&tool_name, &tool_input);

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
        noun,
        sandbox,
        compiled_profile,
        path_caps,
        effect: decision.effect,
    })
}

/// Compute effective capabilities for a set of notable paths.
fn compute_notable_path_caps(policy: &SandboxPolicy, cwd: &str) -> Vec<(String, Cap)> {
    let home = dirs::home_dir()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|| "/home".into());
    let tmpdir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());

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
            }],
            network: NetworkPolicy::Deny,
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
    fn test_format_network_domains() {
        let s = format_network(&NetworkPolicy::AllowDomains(vec![
            "github.com".into(),
            "api.github.com".into(),
        ]));
        assert!(s.contains("github.com"));
    }
}
