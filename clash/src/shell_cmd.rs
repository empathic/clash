//! `clash shell` — bash-compatible shell with per-command sandbox enforcement.
//!
//! Parses shell commands/scripts using brush-parser, rewrites each simple
//! command to execute through `clash sandbox exec --profile <binary>`, then
//! hands the rewritten script to the system bash for execution.
//!
//! This gives per-command sandbox resolution: each command in a pipeline or
//! script gets its own sandbox profile looked up by binary name, falling back
//! to the default sandbox when no command-specific profile exists.

use anyhow::{Context, Result};
use brush_parser::ast;
use tracing::info;

/// Shell builtins that should NOT be wrapped with sandbox exec.
/// These must run in the shell process itself (e.g., cd changes cwd).
const SHELL_BUILTINS: &[&str] = &[
    "cd", "pushd", "popd", "dirs", "export", "unset", "source", ".", "eval", "exec", "exit",
    "return", "set", "shopt", "shift", "trap", "type", "typeset", "declare", "local", "readonly",
    "alias", "unalias", "builtin", "command", "enable", "hash", "help", "let", "logout", "mapfile",
    "readarray", "printf", "echo", "read", "test", "[", "true", "false", ":", "jobs", "fg", "bg",
    "wait", "kill", "disown", "suspend", "times", "ulimit", "umask", "getopts", "complete",
    "compgen", "compopt", "bind", "break", "continue", "caller",
];

fn is_shell_builtin(name: &str) -> bool {
    SHELL_BUILTINS.contains(&name)
}

/// Run a bash-compatible shell with per-command sandbox enforcement.
///
/// Parses the input, rewrites each external command to run through
/// `clash sandbox exec`, then executes via system bash.
pub fn run_shell(
    command: Option<String>,
    script_args: Vec<String>,
    cwd: String,
) -> Result<()> {
    let cwd = crate::sandbox_cmd::resolve_cwd(&cwd)?;
    let clash_bin = std::env::current_exe()
        .context("failed to determine clash executable path")?
        .to_string_lossy()
        .to_string();

    let input = if let Some(ref cmd) = command {
        cmd.clone()
    } else if !script_args.is_empty() {
        std::fs::read_to_string(&script_args[0])
            .with_context(|| format!("failed to read script: {}", script_args[0]))?
    } else {
        anyhow::bail!("clash shell requires -c <command> or a script path");
    };

    let rewritten = rewrite_input(&input, &clash_bin, &cwd)
        .context("failed to parse shell input")?;

    info!(original = %input, rewritten = %rewritten, "executing rewritten shell command");

    let mut cmd = std::process::Command::new("bash");
    cmd.arg("-c").arg(&rewritten);
    cmd.current_dir(&cwd);
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    // Pass script args as positional parameters ($0, $1, ...) when running a script.
    if command.is_none() && script_args.len() > 1 {
        cmd.args(&script_args[1..]);
    }

    let status = cmd.spawn()
        .context("failed to spawn bash")?
        .wait()
        .context("failed to wait for bash")?;

    let code = status.code().unwrap_or(1);
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

/// Parse shell input with brush-parser and rewrite each simple command
/// to run through `clash sandbox exec`.
fn rewrite_input(input: &str, clash_bin: &str, cwd: &str) -> Result<String> {
    let mut reader = std::io::BufReader::new(input.as_bytes());
    let options = brush_parser::ParserOptions::default();
    let source_info = brush_parser::SourceInfo {
        source: "clash-shell".to_string(),
    };
    let mut parser = brush_parser::Parser::new(&mut reader, &options, &source_info);

    let mut program = parser
        .parse_program()
        .map_err(|e| anyhow::anyhow!("parse error: {e}"))?;

    rewrite_program(&mut program, clash_bin, cwd);
    Ok(program.to_string())
}

// ── AST rewriting ────────────────────────────────────────────────────────

fn rewrite_program(program: &mut ast::Program, clash_bin: &str, cwd: &str) {
    for cc in &mut program.complete_commands {
        rewrite_compound_list(cc, clash_bin, cwd);
    }
}

fn rewrite_compound_list(list: &mut ast::CompoundList, clash_bin: &str, cwd: &str) {
    for item in &mut list.0 {
        rewrite_and_or_list(&mut item.0, clash_bin, cwd);
    }
}

fn rewrite_and_or_list(aol: &mut ast::AndOrList, clash_bin: &str, cwd: &str) {
    rewrite_pipeline(&mut aol.first, clash_bin, cwd);
    for additional in &mut aol.additional {
        match additional {
            ast::AndOr::And(p) | ast::AndOr::Or(p) => rewrite_pipeline(p, clash_bin, cwd),
        }
    }
}

fn rewrite_pipeline(pipeline: &mut ast::Pipeline, clash_bin: &str, cwd: &str) {
    for command in &mut pipeline.seq {
        rewrite_command(command, clash_bin, cwd);
    }
}

fn rewrite_command(command: &mut ast::Command, clash_bin: &str, cwd: &str) {
    match command {
        ast::Command::Simple(simple) => rewrite_simple_command(simple, clash_bin, cwd),
        ast::Command::Compound(compound, _) => rewrite_compound_command(compound, clash_bin, cwd),
        ast::Command::Function(func) => {
            let ast::FunctionBody(body, _) = &mut func.body;
            rewrite_compound_command(body, clash_bin, cwd);
        }
        ast::Command::ExtendedTest(_) => {} // [[ ... ]] — nothing to rewrite
    }
}

fn rewrite_simple_command(cmd: &mut ast::SimpleCommand, clash_bin: &str, cwd: &str) {
    let Some(word) = &cmd.word_or_name else {
        return; // No command name (e.g., bare assignment like FOO=bar)
    };

    let binary_name = &word.value;

    // Don't wrap shell builtins — they must run in the shell process.
    if is_shell_builtin(binary_name) {
        return;
    }

    // Don't wrap variable expansions or command substitutions in the command
    // name — we can't determine the binary at parse time.
    if binary_name.contains('$') || binary_name.contains('`') {
        return;
    }

    let original_word = word.clone();
    let binary_name = binary_name.clone();

    // Rewrite: cmd args... → clash sandbox exec --profile <cmd> --fallback-default --cwd <cwd> -- cmd args...
    cmd.word_or_name = Some(ast::Word::new(clash_bin));

    let mut new_suffix_items = vec![
        word_item("sandbox"),
        word_item("exec"),
        word_item("--profile"),
        word_item(&binary_name),
        word_item("--fallback-default"),
        word_item("--cwd"),
        word_item(cwd),
        word_item("--"),
        ast::CommandPrefixOrSuffixItem::Word(original_word),
    ];

    // Append original suffix items (args, redirections).
    if let Some(ref suffix) = cmd.suffix {
        new_suffix_items.extend(suffix.0.iter().cloned());
    }

    cmd.suffix = Some(ast::CommandSuffix(new_suffix_items));
}

fn rewrite_compound_command(compound: &mut ast::CompoundCommand, clash_bin: &str, cwd: &str) {
    match compound {
        ast::CompoundCommand::BraceGroup(bg) => {
            rewrite_compound_list(&mut bg.list, clash_bin, cwd);
        }
        ast::CompoundCommand::Subshell(sub) => {
            rewrite_compound_list(&mut sub.list, clash_bin, cwd);
        }
        ast::CompoundCommand::ForClause(fc) => {
            rewrite_compound_list(&mut fc.body.list, clash_bin, cwd);
        }
        ast::CompoundCommand::ArithmeticForClause(afc) => {
            rewrite_compound_list(&mut afc.body.list, clash_bin, cwd);
        }
        ast::CompoundCommand::CaseClause(cc) => {
            for case_item in &mut cc.cases {
                if let Some(ref mut body) = case_item.cmd {
                    rewrite_compound_list(body, clash_bin, cwd);
                }
            }
        }
        ast::CompoundCommand::IfClause(ic) => {
            rewrite_compound_list(&mut ic.condition, clash_bin, cwd);
            rewrite_compound_list(&mut ic.then, clash_bin, cwd);
            if let Some(ref mut elses) = ic.elses {
                for else_clause in elses {
                    if let Some(ref mut cond) = else_clause.condition {
                        rewrite_compound_list(cond, clash_bin, cwd);
                    }
                    rewrite_compound_list(&mut else_clause.body, clash_bin, cwd);
                }
            }
        }
        ast::CompoundCommand::WhileClause(wc) | ast::CompoundCommand::UntilClause(wc) => {
            rewrite_compound_list(&mut wc.0, clash_bin, cwd);
            rewrite_compound_list(&mut wc.1.list, clash_bin, cwd);
        }
        ast::CompoundCommand::Arithmetic(_) => {} // (( expr )) — nothing to rewrite
    }
}

/// Create a word suffix item.
fn word_item(s: &str) -> ast::CommandPrefixOrSuffixItem {
    ast::CommandPrefixOrSuffixItem::Word(ast::Word::new(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_simple_command() {
        let result = rewrite_input("git push", "/usr/bin/clash", "/tmp").unwrap();
        assert!(result.contains("/usr/bin/clash"));
        assert!(result.contains("sandbox exec"));
        assert!(result.contains("--profile git"));
        assert!(result.contains("-- git push"));
    }

    #[test]
    fn rewrite_pipeline() {
        let result = rewrite_input("cat file | grep pattern", "/usr/bin/clash", "/tmp").unwrap();
        // Both commands should be wrapped
        assert!(result.contains("--profile cat"));
        assert!(result.contains("--profile grep"));
    }

    #[test]
    fn rewrite_and_list() {
        let result = rewrite_input("git pull && cargo build", "/usr/bin/clash", "/tmp").unwrap();
        assert!(result.contains("--profile git"));
        assert!(result.contains("--profile cargo"));
    }

    #[test]
    fn skips_builtins() {
        let result = rewrite_input("cd /tmp && echo hello && git push", "/usr/bin/clash", "/tmp").unwrap();
        // cd and echo are builtins — should NOT be wrapped
        assert!(!result.contains("--profile cd"));
        assert!(!result.contains("--profile echo"));
        // git should be wrapped
        assert!(result.contains("--profile git"));
    }

    #[test]
    fn skips_variable_command_names() {
        let result = rewrite_input("$CMD arg1", "/usr/bin/clash", "/tmp").unwrap();
        // Can't determine binary at parse time — leave as-is
        assert!(!result.contains("sandbox exec"));
    }

    #[test]
    fn rewrites_inside_if() {
        let result = rewrite_input("if true; then git push; fi", "/usr/bin/clash", "/tmp").unwrap();
        assert!(result.contains("--profile git"));
    }

    #[test]
    fn rewrites_inside_for_loop() {
        let result = rewrite_input("for f in *.txt; do cat $f; done", "/usr/bin/clash", "/tmp").unwrap();
        assert!(result.contains("--profile cat"));
    }

    #[test]
    fn preserves_redirections() {
        let result = rewrite_input("git log > output.txt", "/usr/bin/clash", "/tmp").unwrap();
        assert!(result.contains("--profile git"));
        assert!(result.contains("> output.txt") || result.contains(">output.txt"));
    }
}
