//! Clash-specific policy outcome type.
//!
//! [`PolicyDecision`] decouples policy evaluation from protocol response
//! construction. The policy engine returns a `PolicyDecision`, and the hook
//! command converts it to a [`clash_hooks::Response`] at the boundary.

/// The outcome of evaluating a tool invocation against the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Allow the tool invocation.
    Allow {
        reason: Option<String>,
        context: Option<String>,
        /// If set, the Bash command should be rewritten to run under this sandbox.
        updated_input: Option<serde_json::Value>,
    },
    /// Deny the tool invocation.
    Deny {
        reason: String,
        context: Option<String>,
    },
    /// Ask the user for confirmation.
    Ask {
        reason: Option<String>,
        context: Option<String>,
    },
    /// Pass through — no policy opinion, let Claude Code decide.
    Pass,
}

impl PolicyDecision {
    /// Returns true if this is a Deny decision.
    pub fn is_deny(&self) -> bool {
        matches!(self, PolicyDecision::Deny { .. })
    }

    /// Returns true if this is an Ask decision.
    pub fn is_ask(&self) -> bool {
        matches!(self, PolicyDecision::Ask { .. })
    }

    /// Returns the policy effect (for audit/stats), if any.
    pub fn effect(&self) -> Option<crate::policy::Effect> {
        match self {
            PolicyDecision::Allow { .. } => Some(crate::policy::Effect::Allow),
            PolicyDecision::Deny { .. } => Some(crate::policy::Effect::Deny),
            PolicyDecision::Ask { .. } => Some(crate::policy::Effect::Ask),
            PolicyDecision::Pass => None,
        }
    }
}
