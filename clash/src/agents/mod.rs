//! Multi-agent support for Clash.
//!
//! Clash supports multiple coding agents (Claude Code, Gemini CLI, Codex CLI,
//! Amazon Q CLI, OpenCode, Copilot CLI). This module provides:
//!
//! - [`AgentKind`] — enum identifying each supported agent
//! - Canonical tool alias table — maps agent-native tool names to internal names
//! - [`protocol::HookProtocol`] — trait abstracting agent-specific hook JSON formats

pub mod amazonq;
pub mod claude;
pub mod codex;
pub mod copilot;
pub mod gemini;
pub mod opencode;
pub mod protocol;

use std::fmt;
use std::str::FromStr;

use clap::ValueEnum;

/// Identifies which coding agent is calling Clash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum)]
pub enum AgentKind {
    Claude,
    Gemini,
    Codex,
    #[value(name = "amazonq")]
    AmazonQ,
    #[value(name = "opencode")]
    OpenCode,
    Copilot,
}

impl fmt::Display for AgentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentKind::Claude => write!(f, "claude"),
            AgentKind::Gemini => write!(f, "gemini"),
            AgentKind::Codex => write!(f, "codex"),
            AgentKind::AmazonQ => write!(f, "amazonq"),
            AgentKind::OpenCode => write!(f, "opencode"),
            AgentKind::Copilot => write!(f, "copilot"),
        }
    }
}

impl crate::dialog::SelectItem for AgentKind {
    fn label(&self) -> &str {
        match self {
            AgentKind::Claude => "Claude Code",
            AgentKind::Gemini => "Gemini CLI",
            AgentKind::Codex => "Codex CLI",
            AgentKind::AmazonQ => "Amazon Q",
            AgentKind::OpenCode => "OpenCode",
            AgentKind::Copilot => "Copilot CLI",
        }
    }

    fn description(&self) -> &str {
        match self {
            AgentKind::Claude => "Anthropic's coding agent",
            AgentKind::Gemini => "Google's coding agent",
            AgentKind::Codex => "OpenAI's coding agent",
            AgentKind::AmazonQ => "Amazon's coding agent",
            AgentKind::OpenCode => "Open-source coding agent",
            AgentKind::Copilot => "GitHub's coding agent",
        }
    }

    fn variants() -> &'static [Self] {
        &[
            AgentKind::Claude,
            AgentKind::Gemini,
            AgentKind::Codex,
            AgentKind::AmazonQ,
            AgentKind::OpenCode,
            AgentKind::Copilot,
        ]
    }
}

impl FromStr for AgentKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "claude" => Ok(AgentKind::Claude),
            "gemini" => Ok(AgentKind::Gemini),
            "codex" => Ok(AgentKind::Codex),
            "amazonq" | "amazon-q" | "amazon_q" => Ok(AgentKind::AmazonQ),
            "opencode" | "open-code" => Ok(AgentKind::OpenCode),
            "copilot" => Ok(AgentKind::Copilot),
            _ => Err(format!("unknown agent: {s}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Canonical permission mode table
// ---------------------------------------------------------------------------

/// Maps agent-specific permission mode strings to canonical Clash modes.
///
/// Canonical modes: "default", "plan", "edit", "unrestricted".
/// Unknown modes pass through as-is so agent-specific extensions still work.
struct ModeAlias {
    /// Clash's canonical mode name.
    canonical: &'static str,
    /// Agent-specific names that map to this mode.
    agent_names: &'static [(AgentKind, &'static str)],
}

const MODE_ALIASES: &[ModeAlias] = &[
    ModeAlias {
        canonical: "default",
        agent_names: &[(AgentKind::Claude, "default")],
    },
    ModeAlias {
        canonical: "plan",
        agent_names: &[(AgentKind::Claude, "plan")],
    },
    ModeAlias {
        canonical: "edit",
        agent_names: &[(AgentKind::Claude, "edit")],
    },
    ModeAlias {
        canonical: "unrestricted",
        agent_names: &[(AgentKind::Claude, "dangerously_skip_permissions")],
    },
];

/// Given an agent's native permission mode string, return the canonical mode.
///
/// Case-insensitive. Returns the original string unchanged if no mapping exists.
pub fn resolve_permission_mode<'a>(agent: AgentKind, native_mode: &'a str) -> &'a str {
    let lower = native_mode.to_lowercase();
    for alias in MODE_ALIASES {
        for &(a, name) in alias.agent_names {
            if a == agent && name.to_lowercase() == lower {
                // Safety: canonical strings are 'static, but we return 'a to
                // keep the API simple — leak the static lifetime down.
                return alias.canonical;
            }
        }
    }
    native_mode
}

// ---------------------------------------------------------------------------
// Canonical tool alias table
// ---------------------------------------------------------------------------

/// Maps a Clash canonical name and agent-native names to a single internal name.
///
/// Internal names use Claude Code's tool names (e.g. "Bash", "Read") since
/// they are already embedded throughout the policy engine, match tree, and
/// permission logic. This avoids a flag-day rename.
struct ToolAlias {
    /// Clash's user-facing canonical name (e.g. "shell", "read").
    canonical: &'static str,
    /// Internal name used by the policy engine (Claude-style, e.g. "Bash").
    internal: &'static str,
    /// Agent-specific native names that map to this tool.
    agent_names: &'static [(AgentKind, &'static str)],
}

/// The ONE source of truth for tool name mappings across all agents.
///
/// Each entry is curated case-by-case. Tools that don't have a clean
/// cross-agent equivalent are NOT in this table — they stay agent-specific.
const TOOL_ALIASES: &[ToolAlias] = &[
    ToolAlias {
        canonical: "shell",
        internal: "Bash",
        agent_names: &[
            (AgentKind::Claude, "Bash"),
            (AgentKind::Gemini, "run_shell_command"),
            (AgentKind::Codex, "shell"),
            (AgentKind::AmazonQ, "execute_bash"),
            (AgentKind::OpenCode, "bash"),
            (AgentKind::Copilot, "bash"),
        ],
    },
    ToolAlias {
        canonical: "read",
        internal: "Read",
        agent_names: &[
            (AgentKind::Claude, "Read"),
            (AgentKind::Gemini, "read_file"),
            (AgentKind::AmazonQ, "fs_read"),
            (AgentKind::OpenCode, "read"),
            (AgentKind::Copilot, "view"),
        ],
    },
    ToolAlias {
        canonical: "write",
        internal: "Write",
        agent_names: &[
            (AgentKind::Claude, "Write"),
            (AgentKind::Gemini, "write_file"),
            (AgentKind::AmazonQ, "fs_write"),
            (AgentKind::OpenCode, "write"),
        ],
    },
    ToolAlias {
        canonical: "edit",
        internal: "Edit",
        agent_names: &[
            (AgentKind::Claude, "Edit"),
            (AgentKind::Gemini, "replace"),
            (AgentKind::OpenCode, "edit"),
            (AgentKind::Copilot, "edit"),
        ],
    },
    ToolAlias {
        canonical: "glob",
        internal: "Glob",
        agent_names: &[
            (AgentKind::Claude, "Glob"),
            (AgentKind::Gemini, "glob"),
            (AgentKind::OpenCode, "glob"),
        ],
    },
    ToolAlias {
        canonical: "grep",
        internal: "Grep",
        agent_names: &[
            (AgentKind::Claude, "Grep"),
            (AgentKind::Gemini, "grep_search"),
            (AgentKind::OpenCode, "grep"),
        ],
    },
    ToolAlias {
        canonical: "web_fetch",
        internal: "WebFetch",
        agent_names: &[
            (AgentKind::Claude, "WebFetch"),
            (AgentKind::Gemini, "web_fetch"),
            (AgentKind::OpenCode, "webfetch"),
        ],
    },
    ToolAlias {
        canonical: "web_search",
        internal: "WebSearch",
        agent_names: &[
            (AgentKind::Claude, "WebSearch"),
            (AgentKind::Gemini, "google_web_search"),
            (AgentKind::Codex, "web_search"),
            (AgentKind::OpenCode, "websearch"),
        ],
    },
];

/// Given an agent's native tool name, return the internal (Claude-style) name.
///
/// Case-insensitive. Returns the original name unchanged if no mapping exists
/// (unknown/agent-specific tools pass through as-is).
pub fn resolve_tool_name(agent: AgentKind, native_name: &str) -> &str {
    let lower = native_name.to_lowercase();
    for alias in TOOL_ALIASES {
        for &(a, name) in alias.agent_names {
            if a == agent && name.to_lowercase() == lower {
                return alias.internal;
            }
        }
    }
    // No mapping found — return the original name.
    // This is intentionally a leak-free identity: the caller's &str is returned.
    // For unknown tools, the policy engine matches on the native name.
    native_name
}

/// Given a Clash canonical name (e.g. "shell"), return the internal name (e.g. "Bash").
///
/// Case-insensitive. Used by the policy compiler to resolve user-facing aliases.
pub fn canonical_to_internal(clash_name: &str) -> Option<&'static str> {
    let lower = clash_name.to_lowercase();
    TOOL_ALIASES
        .iter()
        .find(|a| a.canonical.to_lowercase() == lower)
        .map(|a| a.internal)
}

/// Resolve any tool name to its internal form.
///
/// Accepts canonical names ("shell"), internal names ("Bash"), or any
/// agent-native name ("run_shell_command"). Case-insensitive.
/// Returns the internal name if found, or None if unrecognized.
pub fn resolve_any_to_internal(name: &str) -> Option<&'static str> {
    let lower = name.to_lowercase();
    for alias in TOOL_ALIASES {
        // Match canonical name
        if alias.canonical.to_lowercase() == lower {
            return Some(alias.internal);
        }
        // Match internal name
        if alias.internal.to_lowercase() == lower {
            return Some(alias.internal);
        }
        // Match any agent-native name
        for &(_, agent_name) in alias.agent_names {
            if agent_name.to_lowercase() == lower {
                return Some(alias.internal);
            }
        }
    }
    None
}

/// Given an internal name (e.g. "Bash"), return the Clash canonical name (e.g. "shell").
///
/// Case-insensitive.
pub fn internal_to_canonical(internal_name: &str) -> Option<&'static str> {
    let lower = internal_name.to_lowercase();
    TOOL_ALIASES
        .iter()
        .find(|a| a.internal.to_lowercase() == lower)
        .map(|a| a.canonical)
}

/// Return the best user-facing display name for a tool.
///
/// Prefers the canonical name ("shell") if one exists, otherwise returns
/// the internal name as-is. Used for stderr messages, deny reasons, and
/// other user-visible output.
pub fn display_name(internal_name: &str) -> &str {
    internal_to_canonical(internal_name).unwrap_or(internal_name)
}

/// Given an internal name and target agent, return the agent's native tool name.
///
/// Used for formatting output in the agent's expected vocabulary.
pub fn internal_to_agent(agent: AgentKind, internal_name: &str) -> Option<&'static str> {
    let lower = internal_name.to_lowercase();
    for alias in TOOL_ALIASES {
        if alias.internal.to_lowercase() == lower {
            for &(a, name) in alias.agent_names {
                if a == agent {
                    return Some(name);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_claude_bash() {
        assert_eq!(resolve_tool_name(AgentKind::Claude, "Bash"), "Bash");
    }

    #[test]
    fn resolve_gemini_shell() {
        assert_eq!(
            resolve_tool_name(AgentKind::Gemini, "run_shell_command"),
            "Bash"
        );
    }

    #[test]
    fn resolve_codex_shell() {
        assert_eq!(resolve_tool_name(AgentKind::Codex, "shell"), "Bash");
    }

    #[test]
    fn resolve_amazonq_bash() {
        assert_eq!(
            resolve_tool_name(AgentKind::AmazonQ, "execute_bash"),
            "Bash"
        );
    }

    #[test]
    fn resolve_case_insensitive() {
        assert_eq!(resolve_tool_name(AgentKind::Claude, "bash"), "Bash");
        assert_eq!(resolve_tool_name(AgentKind::Claude, "BASH"), "Bash");
        assert_eq!(
            resolve_tool_name(AgentKind::Gemini, "RUN_SHELL_COMMAND"),
            "Bash"
        );
    }

    #[test]
    fn resolve_unknown_passthrough() {
        assert_eq!(
            resolve_tool_name(AgentKind::Claude, "SomeCustomTool"),
            "SomeCustomTool"
        );
    }

    #[test]
    fn canonical_to_internal_works() {
        assert_eq!(canonical_to_internal("shell"), Some("Bash"));
        assert_eq!(canonical_to_internal("read"), Some("Read"));
        assert_eq!(canonical_to_internal("SHELL"), Some("Bash"));
        assert_eq!(canonical_to_internal("unknown"), None);
    }

    #[test]
    fn internal_to_canonical_works() {
        assert_eq!(internal_to_canonical("Bash"), Some("shell"));
        assert_eq!(internal_to_canonical("Read"), Some("read"));
        assert_eq!(internal_to_canonical("UnknownTool"), None);
    }

    #[test]
    fn internal_to_agent_works() {
        assert_eq!(
            internal_to_agent(AgentKind::Gemini, "Bash"),
            Some("run_shell_command")
        );
        assert_eq!(
            internal_to_agent(AgentKind::AmazonQ, "Read"),
            Some("fs_read")
        );
        assert_eq!(internal_to_agent(AgentKind::Codex, "Glob"), None);
    }

    #[test]
    fn resolve_any_canonical() {
        assert_eq!(resolve_any_to_internal("shell"), Some("Bash"));
        assert_eq!(resolve_any_to_internal("read"), Some("Read"));
    }

    #[test]
    fn resolve_any_internal() {
        assert_eq!(resolve_any_to_internal("Bash"), Some("Bash"));
        assert_eq!(resolve_any_to_internal("bash"), Some("Bash"));
        assert_eq!(resolve_any_to_internal("BASH"), Some("Bash"));
    }

    #[test]
    fn resolve_any_agent_native() {
        assert_eq!(resolve_any_to_internal("run_shell_command"), Some("Bash"));
        assert_eq!(resolve_any_to_internal("execute_bash"), Some("Bash"));
        assert_eq!(resolve_any_to_internal("fs_read"), Some("Read"));
    }

    #[test]
    fn resolve_any_unknown() {
        assert_eq!(resolve_any_to_internal("CustomTool"), None);
    }

    // --- resolve_permission_mode tests ---

    #[test]
    fn resolve_mode_claude_default() {
        assert_eq!(
            resolve_permission_mode(AgentKind::Claude, "default"),
            "default"
        );
    }

    #[test]
    fn resolve_mode_claude_plan() {
        assert_eq!(resolve_permission_mode(AgentKind::Claude, "plan"), "plan");
    }

    #[test]
    fn resolve_mode_claude_dangerously_skip() {
        assert_eq!(
            resolve_permission_mode(AgentKind::Claude, "dangerously_skip_permissions"),
            "unrestricted"
        );
    }

    #[test]
    fn resolve_mode_case_insensitive() {
        assert_eq!(
            resolve_permission_mode(AgentKind::Claude, "DANGEROUSLY_SKIP_PERMISSIONS"),
            "unrestricted"
        );
    }

    #[test]
    fn resolve_mode_unknown_passthrough() {
        assert_eq!(
            resolve_permission_mode(AgentKind::Claude, "custom_mode"),
            "custom_mode"
        );
    }

    #[test]
    fn resolve_mode_other_agents_default() {
        assert_eq!(
            resolve_permission_mode(AgentKind::Gemini, "default"),
            "default"
        );
        assert_eq!(
            resolve_permission_mode(AgentKind::Codex, "default"),
            "default"
        );
    }

    #[test]
    fn all_aliases_have_consistent_internal_names() {
        // Every internal name in the alias table should be a known Claude tool
        let claude_names: Vec<&str> = TOOL_ALIASES
            .iter()
            .flat_map(|a| {
                a.agent_names
                    .iter()
                    .filter(|(ak, _)| *ak == AgentKind::Claude)
            })
            .map(|(_, name)| *name)
            .collect();
        for alias in TOOL_ALIASES {
            assert!(
                claude_names.contains(&alias.internal),
                "internal name '{}' for canonical '{}' is not a Claude tool name",
                alias.internal,
                alias.canonical
            );
        }
    }
}
