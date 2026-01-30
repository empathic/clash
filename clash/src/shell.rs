//! Shell command parsing for per-segment permission checking.
//!
//! Parses bash command strings into individual command segments so that
//! each segment (pipeline stage, `&&`/`||`/`;` operand) can be
//! permission-checked independently.
//!
//! Uses `brush-parser` (MIT-licensed, POSIX+bash-compatible) for proper
//! shell AST parsing, which correctly handles quoting, escaping, and
//! nested constructs.

use brush_parser::ast;
use std::io::Cursor;
use tracing::debug;

/// Extract individual command segments from a shell command string.
///
/// Splits on pipes (`|`), `&&`, `||`, and `;` operators while respecting
/// shell quoting. Each returned string is a single "atomic" command
/// suitable for independent permission evaluation.
///
/// Returns the original command wrapped in a `Vec` if parsing fails
/// (graceful fallback to current behavior).
///
/// # Examples
///
/// ```text
/// "ls -la"                          → ["ls -la"]
/// "cat f.txt | grep hello"          → ["cat f.txt", "grep hello"]
/// "make && make install"            → ["make", "make install"]
/// "echo 'hello | world'"           → ["echo 'hello | world'"]
/// ```
pub fn extract_command_segments(command: &str) -> Vec<String> {
    match parse_and_extract(command) {
        Ok(segments) if !segments.is_empty() => segments,
        Ok(_) => {
            debug!(
                command,
                "Shell parser returned no segments; using whole command"
            );
            vec![command.to_string()]
        }
        Err(e) => {
            debug!(command, error = %e, "Shell parse failed; using whole command as fallback");
            vec![command.to_string()]
        }
    }
}

/// Parse a command string and extract all atomic command segments.
fn parse_and_extract(command: &str) -> Result<Vec<String>, brush_parser::ParseError> {
    let reader = Cursor::new(command);
    let mut parser = brush_parser::Parser::new(
        reader,
        &brush_parser::ParserOptions::default(),
        &brush_parser::SourceInfo::default(),
    );
    let program = parser.parse_program()?;

    let mut segments = Vec::new();
    extract_from_program(&program, &mut segments);
    Ok(segments)
}

fn extract_from_program(program: &ast::Program, segments: &mut Vec<String>) {
    for complete_command in &program.complete_commands {
        extract_from_compound_list(complete_command, segments);
    }
}

fn extract_from_compound_list(list: &ast::CompoundList, segments: &mut Vec<String>) {
    for item in &list.0 {
        extract_from_and_or_list(&item.0, segments);
    }
}

fn extract_from_and_or_list(list: &ast::AndOrList, segments: &mut Vec<String>) {
    extract_from_pipeline(&list.first, segments);
    for and_or in &list.additional {
        match and_or {
            ast::AndOr::And(pipeline) | ast::AndOr::Or(pipeline) => {
                extract_from_pipeline(pipeline, segments);
            }
        }
    }
}

fn extract_from_pipeline(pipeline: &ast::Pipeline, segments: &mut Vec<String>) {
    for command in &pipeline.seq {
        extract_from_command(command, segments);
    }
}

fn extract_from_command(command: &ast::Command, segments: &mut Vec<String>) {
    match command {
        ast::Command::Simple(simple) => {
            let s = format!("{}", simple).trim().to_string();
            if !s.is_empty() {
                segments.push(s);
            }
        }
        ast::Command::Compound(compound, _redirects) => {
            // For compound commands (if/for/while/case/brace groups/subshells),
            // recurse into the body to extract nested atomic commands.
            extract_from_compound_command(compound, segments);
        }
        ast::Command::Function(_) | ast::Command::ExtendedTest(..) => {
            // Function definitions and [[ ]] tests: treat as single unit.
            let s = format!("{}", command).trim().to_string();
            if !s.is_empty() {
                segments.push(s);
            }
        }
    }
}

fn extract_from_compound_command(compound: &ast::CompoundCommand, segments: &mut Vec<String>) {
    match compound {
        ast::CompoundCommand::BraceGroup(bg) => {
            extract_from_compound_list(&bg.list, segments);
        }
        ast::CompoundCommand::Subshell(sub) => {
            extract_from_compound_list(&sub.list, segments);
        }
        // For other compound commands (if/for/while/case/arithmetic),
        // treat the entire construct as a single segment. Recursing into
        // control flow bodies is a future enhancement.
        _ => {
            let s = format!("{}", compound).trim().to_string();
            if !s.is_empty() {
                segments.push(s);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_command() {
        assert_eq!(extract_command_segments("ls -la"), vec!["ls -la"]);
    }

    #[test]
    fn test_single_command_with_args() {
        assert_eq!(
            extract_command_segments("git commit -m 'test'"),
            vec!["git commit -m 'test'"]
        );
    }

    #[test]
    fn test_pipeline_two_commands() {
        assert_eq!(
            extract_command_segments("cat file.txt | grep hello"),
            vec!["cat file.txt", "grep hello"]
        );
    }

    #[test]
    fn test_pipeline_three_commands() {
        assert_eq!(
            extract_command_segments("cat file.txt | grep hello | wc -l"),
            vec!["cat file.txt", "grep hello", "wc -l"]
        );
    }

    #[test]
    fn test_and_operator() {
        assert_eq!(
            extract_command_segments("make && make install"),
            vec!["make", "make install"]
        );
    }

    #[test]
    fn test_or_operator() {
        assert_eq!(
            extract_command_segments("test -f x || echo missing"),
            vec!["test -f x", "echo missing"]
        );
    }

    #[test]
    fn test_semicolon_separator() {
        assert_eq!(
            extract_command_segments("echo hello; echo world"),
            vec!["echo hello", "echo world"]
        );
    }

    #[test]
    fn test_mixed_pipe_and_and() {
        assert_eq!(
            extract_command_segments("cat f | grep x && echo done"),
            vec!["cat f", "grep x", "echo done"]
        );
    }

    #[test]
    fn test_quoted_pipe_not_split() {
        // A pipe inside quotes should NOT cause a split
        let segments = extract_command_segments("echo 'hello | world'");
        assert_eq!(segments.len(), 1);
        assert!(segments[0].contains("hello | world"));
    }

    #[test]
    fn test_quoted_double_pipe_not_split() {
        let segments = extract_command_segments("echo \"hello | world\"");
        assert_eq!(segments.len(), 1);
        assert!(segments[0].contains("hello | world"));
    }

    #[test]
    fn test_subshell_commands_extracted() {
        // Commands inside a subshell should be extracted
        let segments = extract_command_segments("(echo hello; echo world)");
        assert_eq!(segments, vec!["echo hello", "echo world"]);
    }

    #[test]
    fn test_brace_group_commands_extracted() {
        let segments = extract_command_segments("{ echo hello; echo world; }");
        assert_eq!(segments, vec!["echo hello", "echo world"]);
    }

    #[test]
    fn test_empty_command_fallback() {
        let segments = extract_command_segments("");
        // Empty input should gracefully handle (either empty vec or fallback)
        assert!(!segments.is_empty() || segments == vec![""]);
    }

    #[test]
    fn test_complex_pipeline() {
        assert_eq!(
            extract_command_segments("find . -name '*.rs' | xargs grep TODO | sort -u"),
            vec!["find . -name '*.rs'", "xargs grep TODO", "sort -u"]
        );
    }
}
