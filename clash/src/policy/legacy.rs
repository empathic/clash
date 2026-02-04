//! Legacy permission desugaring.
//!
//! Converts Claude Code's `PermissionSet` allow/deny/ask lists into
//! policy `Statement`s so the new engine can evaluate them.

use tracing::{Level, instrument};

use super::ast::{LegacyPermissions, MatchExpr, Pattern, Statement, VerbPattern};
use super::{Effect, Verb};

/// Convert a `LegacyPermissions` struct (allow / deny / ask string lists)
/// into equivalent statements with `entity = "agent"`.
#[instrument(level = Level::TRACE, skip(perms))]
pub fn desugar_legacy(perms: &LegacyPermissions) -> Vec<Statement> {
    let mut statements = Vec::new();

    for pattern in &perms.allow {
        if let Some(stmt) = legacy_pattern_to_statement(pattern, Effect::Allow) {
            statements.push(stmt);
        }
    }
    for pattern in &perms.deny {
        if let Some(stmt) = legacy_pattern_to_statement(pattern, Effect::Deny) {
            statements.push(stmt);
        }
    }
    for pattern in &perms.ask {
        if let Some(stmt) = legacy_pattern_to_statement(pattern, Effect::Ask) {
            statements.push(stmt);
        }
    }

    statements
}

/// Convert a single legacy permission pattern like `"Bash(git:*)"` into a Statement.
fn legacy_pattern_to_statement(pattern: &str, effect: Effect) -> Option<Statement> {
    let pattern = pattern.trim();

    // Parse "ToolName(arg)" or "ToolName"
    let (tool_name, arg) = if let Some(paren_start) = pattern.find('(') {
        if !pattern.ends_with(')') {
            return None;
        }
        let tool = &pattern[..paren_start];
        let arg = &pattern[paren_start + 1..pattern.len() - 1];
        (tool, Some(arg))
    } else {
        (pattern, None)
    };

    let verb = Verb::from_tool_name(tool_name)?;
    let verb_pattern = VerbPattern::Exact(verb);

    let noun = match arg {
        None => Pattern::Match(MatchExpr::Any),
        Some(arg) => {
            // Handle prefix pattern "git:*" → glob "git *"
            if let Some(prefix) = arg.strip_suffix(":*") {
                Pattern::Match(MatchExpr::Glob(format!("{} *", prefix)))
            } else if arg.contains('*') || arg.contains("**") || arg.contains('?') {
                Pattern::Match(MatchExpr::Glob(arg.to_string()))
            } else {
                Pattern::Match(MatchExpr::Exact(arg.to_string()))
            }
        }
    };

    Some(Statement {
        effect,
        entity: Pattern::Match(MatchExpr::Typed {
            entity_type: "agent".into(),
            name: None,
        }),
        verb: verb_pattern,
        noun,
        reason: None,
        delegate: None,
        profile: None,
    })
}
