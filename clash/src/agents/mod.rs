//! Multi-agent support for Clash.
//!
//! This module re-exports the core agent types and protocol implementations
//! from [`coding_agent_hooks`] and adds clash-specific extensions (dialog UI
//! traits).

// Re-export everything from the shared crate.
pub use coding_agent_hooks::agents::*;
pub use coding_agent_hooks::protocol;

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
