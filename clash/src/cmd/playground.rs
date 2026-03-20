//! Interactive policy REPL for testing rules against hypothetical tool invocations.

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use reedline_repl_rs::clap::{Arg, ArgMatches, Command};
use reedline_repl_rs::{Repl, Result as ReplResult};
use tracing::{Level, instrument};

use crate::debug::replay;
use crate::display;
use crate::policy::compile;
use crate::policy::match_tree::CompiledPolicy;
use crate::style;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Default)]
struct PlaygroundState {
    /// Raw Starlark policy snippets accumulated by the user.
    snippets: Vec<String>,
    /// Current compiled policy (recompiled after each `policy` command).
    compiled: Option<CompiledPolicy>,
}

impl PlaygroundState {
    /// Recompile the current snippets into a CompiledPolicy.
    fn recompile(&mut self) -> Result<()> {
        if self.snippets.is_empty() {
            self.compiled = None;
            return Ok(());
        }

        let starlark_source = self.build_starlark_source();
        let json =
            clash_starlark::evaluate(&starlark_source, "playground.star", &PathBuf::from("."))
                .context("failed to evaluate policy")?;
        let tree = compile::compile_to_tree(&json.json)
            .context("failed to compile policy to decision tree")?;
        self.compiled = Some(tree);
        Ok(())
    }

    /// Build a complete Starlark policy source from the accumulated snippets.
    fn build_starlark_source(&self) -> String {
        let mut lines = vec![
            r#"load("@clash//std.star", "exe", "tool", "policy", "sandbox", "cwd", "home", "tempdir", "path", "regex", "domains")"#.to_string(),
            String::new(),
            "def main():".to_string(),
            "    return policy(default = deny, rules = [".to_string(),
        ];
        for snippet in &self.snippets {
            lines.push(format!("        {},", snippet.trim()));
        }
        lines.push("    ])".to_string());

        lines.join("\n")
    }

    fn reset(&mut self) {
        self.snippets.clear();
        self.compiled = None;
    }
}

// ---------------------------------------------------------------------------
// Command callbacks
// ---------------------------------------------------------------------------

fn handle_show(_args: ArgMatches, state: &mut PlaygroundState) -> ReplResult<Option<String>> {
    if state.snippets.is_empty() {
        return Ok(Some(
            "No policy rules defined. Use 'policy' to add rules.".to_string(),
        ));
    }

    let mut lines = vec![format!("{}", style::header("Current policy rules:"))];
    for (i, snippet) in state.snippets.iter().enumerate() {
        lines.push(format!("  [{}] {}", i + 1, snippet));
    }
    lines.push(String::new());
    lines.push(format!(
        "{} {}",
        style::bold("Status:"),
        if state.compiled.is_some() {
            "compiled"
        } else {
            "not compiled"
        }
    ));
    Ok(Some(lines.join("\n")))
}

fn handle_reset(_args: ArgMatches, state: &mut PlaygroundState) -> ReplResult<Option<String>> {
    state.reset();
    Ok(Some("Policy cleared.".to_string()))
}

// ---------------------------------------------------------------------------
// Test input parsing
// ---------------------------------------------------------------------------

/// Parse `ToolName { json }` or `tool_shorthand "args"` formats.
///
/// Supports:
///   - `Bash { "command": "git status" }`
///   - `bash "git status"` (shorthand resolved via replay::resolve_tool_input)
fn parse_test_input(input: &str) -> Result<(String, serde_json::Value)> {
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

    // Fall back to the same resolution used by `clash explain`
    let parts: Vec<&str> = input.splitn(2, ' ').collect();
    let tool = parts[0];
    let args = parts.get(1).copied();
    replay::resolve_tool_input(tool, args)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run the interactive playground REPL.
#[instrument(level = Level::TRACE)]
pub fn run() -> Result<()> {
    let repl = Repl::new(PlaygroundState::default())
        .with_name("clash")
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_description("clash playground — interactive policy sandbox")
        .with_banner("Type 'help' for available commands.\n")
        .with_command(
            Command::new("policy")
                .about("Add a Starlark policy rule (e.g. exe(\"git\").allow())")
                .arg(
                    Arg::new("rule")
                        .required(true)
                        .num_args(1..)
                        .trailing_var_arg(true)
                        .help("Starlark rule expression"),
                ),
            |args, state| {
                let parts: Vec<&str> = args
                    .get_many::<String>("rule")
                    .unwrap()
                    .map(|s| s.as_str())
                    .collect();
                let combined = parts.join(" ");
                handle_policy_combined(&combined, state)
            },
        )
        .with_command(
            Command::new("test")
                .about("Test a tool invocation against current policy")
                .arg(
                    Arg::new("invocation")
                        .required(true)
                        .num_args(1..)
                        .trailing_var_arg(true)
                        .help("e.g. Bash { \"command\": \"git status\" } or bash \"git push\""),
                ),
            |args, state| {
                let parts: Vec<&str> = args
                    .get_many::<String>("invocation")
                    .unwrap()
                    .map(|s| s.as_str())
                    .collect();
                let combined = parts.join(" ");
                handle_test_combined(&combined, state)
            },
        )
        .with_command(
            Command::new("show").about("Display current policy rules"),
            handle_show,
        )
        .with_command(
            Command::new("reset").about("Clear all policy rules"),
            handle_reset,
        );

    let mut repl = repl;
    repl.run().context("playground REPL failed")?;
    Ok(())
}

// Helpers that take a pre-combined string instead of ArgMatches
fn handle_policy_combined(
    snippet: &str,
    state: &mut PlaygroundState,
) -> ReplResult<Option<String>> {
    if snippet.is_empty() {
        return Ok(Some("Usage: policy <starlark rule expression>".to_string()));
    }

    state.snippets.push(snippet.to_string());

    match state.recompile() {
        Ok(()) => Ok(Some(format!(
            "Rule added (total: {}). Use 'test' to evaluate.",
            state.snippets.len()
        ))),
        Err(e) => {
            state.snippets.pop();
            let _ = state.recompile();
            Ok(Some(format!("Error adding rule: {e:#}")))
        }
    }
}

fn handle_test_combined(input: &str, state: &mut PlaygroundState) -> ReplResult<Option<String>> {
    let tree = match &state.compiled {
        Some(t) => t,
        None => {
            return Ok(Some(
                "No policy loaded. Add rules with 'policy' first.".to_string(),
            ));
        }
    };

    let (tool_name, tool_input) = match parse_test_input(input) {
        Ok(pair) => pair,
        Err(e) => return Ok(Some(format!("Failed to parse test input: {e}"))),
    };

    let decision = tree.evaluate(&tool_name, &tool_input);

    let mut lines = display::format_tool_header("Input:", &tool_name, &tool_input);
    lines.push(String::new());
    lines.extend(display::format_decision(&decision));
    Ok(Some(lines.join("\n")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_test_input_json_format() {
        let (name, input) = parse_test_input(r#"Bash { "command": "git status" }"#).unwrap();
        assert_eq!(name, "Bash");
        assert_eq!(input["command"], "git status");
    }

    #[test]
    fn test_parse_test_input_shorthand() {
        let (name, input) = parse_test_input("bash \"git push\"").unwrap();
        assert_eq!(name, "Bash");
        assert_eq!(input["command"], "\"git push\"");
    }

    #[test]
    fn test_parse_test_input_read() {
        let (name, input) = parse_test_input(r#"Read { "file_path": "/etc/passwd" }"#).unwrap();
        assert_eq!(name, "Read");
        assert_eq!(input["file_path"], "/etc/passwd");
    }

    #[test]
    fn test_parse_test_input_invalid_json() {
        let result = parse_test_input("Bash { invalid }");
        assert!(result.is_err());
    }

    #[test]
    fn test_playground_state_default() {
        let state = PlaygroundState::default();
        assert!(state.snippets.is_empty());
        assert!(state.compiled.is_none());
    }

    #[test]
    fn test_playground_state_recompile_empty() {
        let mut state = PlaygroundState::default();
        state.recompile().unwrap();
        assert!(state.compiled.is_none());
    }

    #[test]
    fn test_playground_state_recompile_valid() {
        let mut state = PlaygroundState::default();
        state.snippets.push(r#"exe("git").allow()"#.to_string());
        state.recompile().unwrap();
        assert!(state.compiled.is_some());
    }

    #[test]
    fn test_playground_state_reset() {
        let mut state = PlaygroundState::default();
        state.snippets.push(r#"exe("git").allow()"#.to_string());
        state.recompile().unwrap();
        state.reset();
        assert!(state.snippets.is_empty());
        assert!(state.compiled.is_none());
    }

    #[test]
    fn test_build_starlark_source() {
        let mut state = PlaygroundState::default();
        state.snippets.push(r#"exe("git").allow()"#.to_string());
        state.snippets.push(r#"tool("Read").allow()"#.to_string());

        let source = state.build_starlark_source();
        assert!(source.contains("def main():"));
        assert!(source.contains(r#"exe("git").allow()"#));
        assert!(source.contains(r#"tool("Read").allow()"#));
        assert!(source.contains("return policy("));
    }

    #[test]
    fn test_handle_policy_combined_valid() {
        let mut state = PlaygroundState::default();
        let result = handle_policy_combined(r#"exe("git").allow()"#, &mut state).unwrap();
        assert!(result.unwrap().contains("Rule added"));
        assert_eq!(state.snippets.len(), 1);
    }

    #[test]
    fn test_handle_policy_combined_invalid() {
        let mut state = PlaygroundState::default();
        let result = handle_policy_combined("this_is_not_valid(((", &mut state).unwrap();
        assert!(result.unwrap().contains("Error"));
        assert!(state.snippets.is_empty());
    }

    #[test]
    fn test_handle_test_combined_no_policy() {
        let mut state = PlaygroundState::default();
        let result = handle_test_combined(r#"Bash { "command": "ls" }"#, &mut state).unwrap();
        assert!(result.unwrap().contains("No policy loaded"));
    }

    #[test]
    fn test_handle_test_combined_with_policy() {
        let mut state = PlaygroundState::default();
        handle_policy_combined(r#"exe("git").allow()"#, &mut state).unwrap();

        let result =
            handle_test_combined(r#"Bash { "command": "git status" }"#, &mut state).unwrap();
        let output = result.unwrap();
        assert!(output.contains("allow"), "expected 'allow' in: {output}");
    }

    #[test]
    fn test_handle_test_combined_deny() {
        let mut state = PlaygroundState::default();
        handle_policy_combined(r#"exe("git").allow()"#, &mut state).unwrap();

        let result = handle_test_combined(r#"Bash { "command": "rm -rf /" }"#, &mut state).unwrap();
        let output = result.unwrap();
        assert!(output.contains("deny"), "expected 'deny' in: {output}");
    }
}
