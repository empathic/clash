//! Shared test parsing and evaluation for policy testing.
//!
//! Used by both the TUI test panel and the playground REPL to parse
//! shorthand tool invocations and evaluate them against a compiled policy.

use anyhow::{Context, Result};

use crate::policy::ir::PolicyDecision;
use crate::policy::match_tree::CompiledPolicy;
use crate::policy::Effect;

/// The result of testing a tool invocation against a policy.
#[derive(Debug, Clone)]
pub struct TestResult {
    /// The resolved tool name (e.g. "Bash", "Read").
    pub tool_name: String,
    /// The resolved tool input JSON.
    pub tool_input: serde_json::Value,
    /// The policy decision.
    pub decision: PolicyDecision,
}

impl TestResult {
    /// The effect of this test result.
    pub fn effect(&self) -> Effect {
        self.decision.effect
    }

    /// Short human-readable summary of the decision.
    pub fn summary(&self) -> String {
        let effect = match self.decision.effect {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
            Effect::Ask => "ask",
        };
        match &self.decision.reason {
            Some(reason) => format!("{effect} ({reason})"),
            None => effect.to_string(),
        }
    }
}

/// Parse a test input string and evaluate it against a compiled policy.
///
/// Accepts both JSON format (`Bash { "command": "git push" }`) and
/// shorthand (`bash "git push"`).
pub fn evaluate_test(input: &str, policy: &CompiledPolicy) -> Result<TestResult> {
    let (tool_name, tool_input) = parse_test_input(input)?;
    let decision = policy.evaluate(&tool_name, &tool_input);
    Ok(TestResult {
        tool_name,
        tool_input,
        decision,
    })
}

/// Parse `ToolName { json }` or `tool_shorthand "args"` formats.
///
/// Supports:
///   - `Bash { "command": "git status" }`
///   - `bash "git status"` (shorthand resolved via resolve_tool_input)
pub fn parse_test_input(input: &str) -> Result<(String, serde_json::Value)> {
    // Try "ToolName { json }" format first
    if let Some(brace_pos) = input.find('{') {
        let tool_name = input[..brace_pos].trim().to_string();
        let json_str = input[brace_pos..].trim();
        if !tool_name.is_empty() {
            let tool_input: serde_json::Value =
                serde_json::from_str(json_str).context("invalid JSON in tool input")?;
            return Ok((tool_name, tool_input));
        }
    }

    // Fall back to shorthand resolution
    let parts: Vec<&str> = input.splitn(2, ' ').collect();
    let tool = parts[0];
    let args = parts.get(1).copied();
    resolve_tool_input(tool, args)
}

/// Resolve a shorthand tool name and optional argument into a canonical
/// (tool_name, tool_input) pair.
///
/// Maps lowercase names to their canonical forms (`bash` → `Bash`) and
/// builds the appropriate JSON input shape for each tool type.
pub fn resolve_tool_input(
    tool: &str,
    input: Option<&str>,
) -> Result<(String, serde_json::Value)> {
    let noun = input.unwrap_or_default();

    if tool.to_lowercase() == "tool" {
        return Ok((noun.to_string(), serde_json::json!({})));
    }

    let tool_name = match tool.to_lowercase().as_str() {
        "bash" => "Bash",
        "read" => "Read",
        "write" => "Write",
        "edit" => "Edit",
        _ => tool,
    };

    let tool_input = serde_json::from_str::<serde_json::Value>(noun)
        .ok()
        .filter(|v| v.is_object())
        .unwrap_or_else(|| build_tool_input(tool_name, noun));

    Ok((tool_name.to_string(), tool_input))
}

fn build_tool_input(tool_name: &str, noun: &str) -> serde_json::Value {
    let field = match tool_name {
        "Bash" => "command",
        "Read" | "Write" | "Edit" | "NotebookEdit" => "file_path",
        "Glob" | "Grep" => "pattern",
        "WebFetch" => "url",
        "WebSearch" => "query",
        _ => "command",
    };
    serde_json::json!({ field: noun })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_json_format() {
        let (name, input) = parse_test_input(r#"Bash { "command": "git status" }"#).unwrap();
        assert_eq!(name, "Bash");
        assert_eq!(input["command"], "git status");
    }

    #[test]
    fn test_parse_shorthand() {
        let (name, input) = parse_test_input("bash \"git push\"").unwrap();
        assert_eq!(name, "Bash");
        assert_eq!(input["command"], "\"git push\"");
    }

    #[test]
    fn test_parse_read() {
        let (name, input) = parse_test_input(r#"Read { "file_path": "/etc/passwd" }"#).unwrap();
        assert_eq!(name, "Read");
        assert_eq!(input["file_path"], "/etc/passwd");
    }

    #[test]
    fn test_parse_invalid_json() {
        let result = parse_test_input("Bash { invalid }");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_bash() {
        let (name, input) = resolve_tool_input("bash", Some("ls -la")).unwrap();
        assert_eq!(name, "Bash");
        assert_eq!(input["command"], "ls -la");
    }

    #[test]
    fn test_resolve_read() {
        let (name, input) = resolve_tool_input("read", Some("/tmp/foo")).unwrap();
        assert_eq!(name, "Read");
        assert_eq!(input["file_path"], "/tmp/foo");
    }

    #[test]
    fn test_resolve_tool() {
        let (name, input) = resolve_tool_input("tool", Some("Agent")).unwrap();
        assert_eq!(name, "Agent");
        assert!(input.is_object());
    }
}
