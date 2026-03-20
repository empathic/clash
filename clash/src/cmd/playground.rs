//! Interactive policy REPL for testing rules against hypothetical tool invocations.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use tracing::{Level, instrument};

use crate::debug::replay;
use crate::display;
use crate::policy::compile;
use crate::policy::match_tree::CompiledPolicy;
use crate::style;

/// Run the interactive playground REPL.
#[instrument(level = Level::TRACE)]
pub fn run() -> Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    writeln!(out, "clash playground — interactive policy sandbox")?;
    writeln!(out, "Type 'help' for available commands.\n")?;

    let mut state = PlaygroundState::default();

    for line in stdin.lock().lines() {
        let line = line.context("failed to read line from stdin")?;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            write!(out, "clash> ")?;
            out.flush()?;
            continue;
        }

        match dispatch(trimmed, &mut state) {
            ControlFlow::Continue(output) => {
                if !output.is_empty() {
                    writeln!(out, "{output}")?;
                }
                write!(out, "clash> ")?;
                out.flush()?;
            }
            ControlFlow::Quit => {
                return Ok(());
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Default)]
struct PlaygroundState {
    /// Raw Starlark policy snippets accumulated by the user.
    snippets: Vec<String>,
    /// Current compiled policy (recompiled after each `policy:` command).
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
// Dispatch
// ---------------------------------------------------------------------------

enum ControlFlow {
    Continue(String),
    Quit,
}

fn dispatch(input: &str, state: &mut PlaygroundState) -> ControlFlow {
    if let Some(snippet) = input.strip_prefix("policy:") {
        ControlFlow::Continue(handle_policy(snippet.trim(), state))
    } else if let Some(test_input) = input.strip_prefix("test:") {
        ControlFlow::Continue(handle_test(test_input.trim(), state))
    } else {
        match input {
            "help" => ControlFlow::Continue(handle_help()),
            "show" => ControlFlow::Continue(handle_show(state)),
            "reset" => {
                state.reset();
                ControlFlow::Continue("Policy cleared.".to_string())
            }
            "quit" | "exit" => ControlFlow::Quit,
            _ => ControlFlow::Continue(format!(
                "Unknown command: {input}\nType 'help' for available commands."
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

fn handle_help() -> String {
    [
        "Available commands:",
        "  policy: <rule>    Add a Starlark policy rule (e.g. exe(\"git\").allow())",
        "  test: <tool>      Test a tool invocation (e.g. Bash { \"command\": \"git status\" })",
        "  show              Display current policy rules",
        "  reset             Clear all policy rules",
        "  help              Show this help message",
        "  quit / exit       Leave the playground",
        "",
        "Examples:",
        "  policy: exe(\"git\").allow()",
        "  policy: tool(\"Read\").allow()",
        "  test: Bash { \"command\": \"git status\" }",
        "  test: Read { \"file_path\": \"/tmp/test.txt\" }",
    ]
    .join("\n")
}

fn handle_policy(snippet: &str, state: &mut PlaygroundState) -> String {
    if snippet.is_empty() {
        return "Usage: policy: <starlark rule expression>".to_string();
    }

    state.snippets.push(snippet.to_string());

    match state.recompile() {
        Ok(()) => {
            format!(
                "Rule added (total: {}). Use 'test:' to evaluate.",
                state.snippets.len()
            )
        }
        Err(e) => {
            // Remove the bad snippet
            state.snippets.pop();
            // Try to recompile without it
            let _ = state.recompile();
            format!("Error adding rule: {e:#}")
        }
    }
}

fn handle_test(input: &str, state: &PlaygroundState) -> String {
    let tree = match &state.compiled {
        Some(t) => t,
        None => return "No policy loaded. Add rules with 'policy:' first.".to_string(),
    };

    let (tool_name, tool_input) = match parse_test_input(input) {
        Ok(pair) => pair,
        Err(e) => return format!("Failed to parse test input: {e}"),
    };

    let decision = tree.evaluate(&tool_name, &tool_input);

    let mut lines = display::format_tool_header("Input:", &tool_name, &tool_input);
    lines.push(String::new());
    lines.extend(display::format_decision(&decision));
    lines.join("\n")
}

fn handle_show(state: &PlaygroundState) -> String {
    if state.snippets.is_empty() {
        return "No policy rules defined. Use 'policy:' to add rules.".to_string();
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
    lines.join("\n")
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
    fn test_dispatch_help() {
        let mut state = PlaygroundState::default();
        match dispatch("help", &mut state) {
            ControlFlow::Continue(output) => assert!(output.contains("Available commands")),
            ControlFlow::Quit => panic!("unexpected quit"),
        }
    }

    #[test]
    fn test_dispatch_quit() {
        let mut state = PlaygroundState::default();
        assert!(matches!(dispatch("quit", &mut state), ControlFlow::Quit));
        assert!(matches!(dispatch("exit", &mut state), ControlFlow::Quit));
    }

    #[test]
    fn test_dispatch_unknown() {
        let mut state = PlaygroundState::default();
        match dispatch("foobar", &mut state) {
            ControlFlow::Continue(output) => assert!(output.contains("Unknown command")),
            ControlFlow::Quit => panic!("unexpected quit"),
        }
    }

    #[test]
    fn test_dispatch_reset() {
        let mut state = PlaygroundState::default();
        match dispatch("reset", &mut state) {
            ControlFlow::Continue(output) => assert!(output.contains("cleared")),
            ControlFlow::Quit => panic!("unexpected quit"),
        }
    }

    #[test]
    fn test_dispatch_show_empty() {
        let mut state = PlaygroundState::default();
        match dispatch("show", &mut state) {
            ControlFlow::Continue(output) => assert!(output.contains("No policy rules")),
            ControlFlow::Quit => panic!("unexpected quit"),
        }
    }

    #[test]
    fn test_dispatch_test_no_policy() {
        let mut state = PlaygroundState::default();
        match dispatch(r#"test: Bash { "command": "ls" }"#, &mut state) {
            ControlFlow::Continue(output) => assert!(output.contains("No policy loaded")),
            ControlFlow::Quit => panic!("unexpected quit"),
        }
    }

    #[test]
    fn test_policy_add_and_test() {
        let mut state = PlaygroundState::default();

        // Add a policy rule
        match dispatch(r#"policy: exe("git").allow()"#, &mut state) {
            ControlFlow::Continue(output) => assert!(output.contains("Rule added")),
            ControlFlow::Quit => panic!("unexpected quit"),
        }

        // Test a matching invocation
        match dispatch(r#"test: Bash { "command": "git status" }"#, &mut state) {
            ControlFlow::Continue(output) => {
                assert!(
                    output.contains("allow"),
                    "expected 'allow' in output, got: {output}"
                );
            }
            ControlFlow::Quit => panic!("unexpected quit"),
        }

        // Test a non-matching invocation (default deny)
        match dispatch(r#"test: Bash { "command": "rm -rf /" }"#, &mut state) {
            ControlFlow::Continue(output) => {
                assert!(
                    output.contains("deny"),
                    "expected 'deny' in output, got: {output}"
                );
            }
            ControlFlow::Quit => panic!("unexpected quit"),
        }
    }

    #[test]
    fn test_policy_invalid_snippet() {
        let mut state = PlaygroundState::default();
        match dispatch("policy: this_is_not_valid(((", &mut state) {
            ControlFlow::Continue(output) => {
                assert!(
                    output.contains("Error"),
                    "expected error message, got: {output}"
                );
            }
            ControlFlow::Quit => panic!("unexpected quit"),
        }
        // State should still be empty after failed add
        assert!(state.snippets.is_empty());
        assert!(state.compiled.is_none());
    }

    #[test]
    fn test_show_with_rules() {
        let mut state = PlaygroundState::default();
        dispatch(r#"policy: exe("git").allow()"#, &mut state);

        match dispatch("show", &mut state) {
            ControlFlow::Continue(output) => {
                assert!(output.contains("[1]"));
                assert!(output.contains("exe(\"git\").allow()"));
                assert!(output.contains("compiled"));
            }
            ControlFlow::Quit => panic!("unexpected quit"),
        }
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
}
