//! The policy engine's output type — a decision about whether a tool call
//! should be allowed, denied, or require user confirmation.
//!
//! This is the boundary type between the policy engine ([`crate::permissions`])
//! and the protocol output layer. It replaces the old `HookOutput`-based return
//! from `check_permission`.

use crate::policy::Effect;

/// A policy decision about a tool invocation.
#[derive(Debug, Clone)]
pub enum PolicyDecision {
    /// Tool call is allowed. Optionally rewrites the tool input (e.g. for sandbox wrapping).
    Allow {
        reason: String,
        context: Option<String>,
        updated_input: Option<serde_json::Value>,
    },
    /// Tool call is denied. The agent receives the reason and context.
    Deny {
        reason: String,
        context: Option<String>,
    },
    /// Tool call requires user confirmation. Falls through to the agent's native permission UI.
    Ask {
        reason: String,
        context: Option<String>,
    },
    /// Pass through — no policy opinion. Let the agent's native permission system decide.
    Pass,
}

impl PolicyDecision {
    /// Returns `true` if this is a `Deny` decision.
    pub fn is_deny(&self) -> bool {
        matches!(self, PolicyDecision::Deny { .. })
    }

    /// Returns `true` if this is an `Ask` decision.
    pub fn is_ask(&self) -> bool {
        matches!(self, PolicyDecision::Ask { .. })
    }

    /// Returns `true` if this is an `Allow` decision.
    pub fn is_allow(&self) -> bool {
        matches!(self, PolicyDecision::Allow { .. })
    }

    /// Map to the policy [`Effect`], or `None` for `Pass`.
    pub fn effect(&self) -> Option<Effect> {
        match self {
            PolicyDecision::Allow { .. } => Some(Effect::Allow),
            PolicyDecision::Deny { .. } => Some(Effect::Deny),
            PolicyDecision::Ask { .. } => Some(Effect::Ask),
            PolicyDecision::Pass => None,
        }
    }

    /// Extract the reason string, if present.
    pub fn reason(&self) -> Option<&str> {
        match self {
            PolicyDecision::Allow { reason, .. }
            | PolicyDecision::Deny { reason, .. }
            | PolicyDecision::Ask { reason, .. } => Some(reason),
            PolicyDecision::Pass => None,
        }
    }

    /// Extract the additional context, if present.
    pub fn context(&self) -> Option<&str> {
        match self {
            PolicyDecision::Allow { context, .. }
            | PolicyDecision::Deny { context, .. }
            | PolicyDecision::Ask { context, .. } => context.as_deref(),
            PolicyDecision::Pass => None,
        }
    }

    /// Extract the updated_input, if this is an Allow with rewritten input.
    pub fn updated_input(&self) -> Option<&serde_json::Value> {
        match self {
            PolicyDecision::Allow { updated_input, .. } => updated_input.as_ref(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_effect() {
        let d = PolicyDecision::Allow {
            reason: "ok".into(),
            context: None,
            updated_input: None,
        };
        assert_eq!(d.effect(), Some(Effect::Allow));
        assert!(d.is_allow());
        assert!(!d.is_deny());
        assert!(!d.is_ask());
        assert_eq!(d.reason(), Some("ok"));
    }

    #[test]
    fn test_deny_effect() {
        let d = PolicyDecision::Deny {
            reason: "nope".into(),
            context: Some("ctx".into()),
        };
        assert_eq!(d.effect(), Some(Effect::Deny));
        assert!(d.is_deny());
        assert_eq!(d.context(), Some("ctx"));
    }

    #[test]
    fn test_ask_effect() {
        let d = PolicyDecision::Ask {
            reason: "confirm".into(),
            context: None,
        };
        assert_eq!(d.effect(), Some(Effect::Ask));
        assert!(d.is_ask());
    }

    #[test]
    fn test_pass_effect() {
        let d = PolicyDecision::Pass;
        assert_eq!(d.effect(), None);
        assert_eq!(d.reason(), None);
        assert_eq!(d.context(), None);
    }
}
