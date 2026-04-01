//! Interactive policy REPL for testing rules against hypothetical tool invocations.

use std::path::PathBuf;

use anyhow::{Context, Result};
use nu_ansi_term::{Color, Style};
use reedline::{
    ColumnarMenu, Completer, DefaultPrompt, DefaultPromptSegment, Highlighter, KeyCode,
    KeyModifiers, MenuBuilder, Reedline, ReedlineEvent, ReedlineMenu, Signal, Span, StyledText,
    Suggestion, ValidationResult, Validator,
};
use tracing::{Level, instrument};

use crate::display;
use crate::policy::compile;
use crate::policy::match_tree::CompiledPolicy;
use crate::style;

/// Starlark DSL functions available in the playground, with signatures and descriptions.
const STARLARK_FUNCTIONS: &[(&str, &str, &str)] = &[
    (
        "match",
        r#"match({ "ToolName": { ... }, ... })"#,
        "Build rules from a nested dict tree (roots are tool names)",
    ),
    ("allow", "allow(sandbox=None)", "Create an allow effect"),
    ("deny", "deny(sandbox=None)", "Create a deny effect"),
    ("ask", "ask(sandbox=None)", "Create an ask effect"),
    (
        "cwd",
        "cwd(follow_worktrees=False)",
        "Match the current working directory",
    ),
    ("home", "home()", "Match the home directory"),
    ("tempdir", "tempdir()", "Match the temp directory"),
    (
        "path",
        r#"path(path_str=None, env=None)"#,
        "Match an arbitrary path or env var",
    ),
    (
        "domains",
        r#"domains({ "host": effect, ... })"#,
        "Build net rules from a domain->effect dict",
    ),
    (
        "domain",
        r#"domain(name, effect)"#,
        "Build a single net rule",
    ),
    (
        "sandbox",
        r#"sandbox(name, default="deny", fs=None, net=None)"#,
        "Build a sandbox definition",
    ),
    ("regex", r#"regex(pattern)"#, "Create a regex pattern"),
    (
        "policy",
        r#"policy(default="deny", rules=None)"#,
        "Build a policy (used internally by playground)",
    ),
];

/// All completable tokens: DSL functions, effects, path methods, and common tool names.
const COMPLETIONS: &[&str] = &[
    // DSL functions
    "match(",
    "allow(",
    "deny(",
    "ask(",
    "cwd(",
    "home(",
    "tempdir(",
    "path(",
    "domains(",
    "domain(",
    "sandbox(",
    "regex(",
    "policy(",
    // Chainable methods
    ".allow()",
    ".deny()",
    ".ask()",
    ".sandbox(",
    ".on(",
    ".child(",
    ".file(",
    ".recurse()",
    ".match(",
    // Common tool names
    "\"Bash\"",
    "\"Read\"",
    "\"Write\"",
    "\"Edit\"",
    "\"Glob\"",
    "\"Grep\"",
    "\"Agent\"",
    "\"Skill\"",
    "\"WebFetch\"",
    "\"WebSearch\"",
    // Args keyword
    "args=[",
    "follow_worktrees=True",
];

// ---------------------------------------------------------------------------
// Completer
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct PlaygroundCompleter;

/// Check if position is inside a quoted string.
fn inside_quotes(text: &str) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    for c in text.chars() {
        match c {
            '"' if !in_single => in_double = !in_double,
            '\'' if !in_double => in_single = !in_single,
            _ => {}
        }
    }
    in_single || in_double
}

impl Completer for PlaygroundCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        let prefix = &line[..pos];

        // Don't complete inside quoted strings
        if inside_quotes(prefix) {
            return vec![];
        }

        // Find the start of the current token
        let token_start = prefix
            .rfind([' ', ',', '[', '(', '{'])
            .map(|i| i + 1)
            .unwrap_or(0);
        let partial = &prefix[token_start..];

        if partial.is_empty() {
            return vec![];
        }

        // Also check for method completions (starts with .)
        let dot_start = prefix.rfind('.').unwrap_or(token_start);
        let dot_partial = &prefix[dot_start..];

        let mut suggestions = Vec::new();
        for &completion in COMPLETIONS {
            if completion.starts_with(partial) {
                suggestions.push(Suggestion {
                    value: completion.to_string(),
                    description: None,
                    style: None,
                    extra: None,
                    span: Span {
                        start: token_start,
                        end: pos,
                    },
                    match_indices: None,
                    display_override: None,
                    append_whitespace: false,
                });
            } else if completion.starts_with(dot_partial) && dot_start != token_start {
                suggestions.push(Suggestion {
                    value: completion.to_string(),
                    description: None,
                    style: None,
                    extra: None,
                    span: Span {
                        start: dot_start,
                        end: pos,
                    },
                    match_indices: None,
                    display_override: None,
                    append_whitespace: false,
                });
            }
        }

        // Also complete REPL commands
        let commands = [
            "load",
            "save",
            "add rule",
            "add sandbox",
            "test",
            "show",
            "reset",
            "functions",
            "help",
            "quit",
            "exit",
        ];
        if token_start == 0 {
            for &cmd in &commands {
                if cmd.starts_with(partial) {
                    suggestions.push(Suggestion {
                        value: cmd.to_string(),
                        description: None,
                        style: None,
                        extra: None,
                        span: Span { start: 0, end: pos },
                        match_indices: None,
                        display_override: None,
                        append_whitespace: true,
                    });
                }
            }
        }

        suggestions
    }
}

// ---------------------------------------------------------------------------
// Syntax highlighting
// ---------------------------------------------------------------------------

/// DSL function names that get highlighted as builtins.
const DSL_FUNCTIONS: &[&str] = &[
    "match", "allow", "deny", "ask", "cwd", "home", "tempdir", "path", "domains", "domain",
    "sandbox", "regex", "policy",
];

/// REPL commands that get highlighted as keywords.
const REPL_COMMANDS: &[&str] = &[
    "add",
    "rule",
    "test",
    "show",
    "reset",
    "functions",
    "help",
    "load",
    "save",
];

struct StarlarkHighlighter;

impl Highlighter for StarlarkHighlighter {
    fn highlight(&self, line: &str, _cursor: usize) -> StyledText {
        let mut styled = StyledText::new();
        let mut chars = line.char_indices().peekable();

        while let Some(&(i, c)) = chars.peek() {
            if c == '"' || c == '\'' {
                // String literal
                let quote = c;
                let start = i;
                chars.next();
                while let Some(&(_, ch)) = chars.peek() {
                    chars.next();
                    if ch == quote {
                        break;
                    }
                }
                let end = chars.peek().map_or(line.len(), |&(j, _)| j);
                styled.push((Style::new().fg(Color::Yellow), line[start..end].to_string()));
            } else if c == '#' {
                // Comment — rest of line
                styled.push((Style::new().fg(Color::DarkGray), line[i..].to_string()));
                return styled;
            } else if c.is_alphabetic() || c == '_' {
                // Identifier
                let start = i;
                while let Some(&(_, ch)) = chars.peek() {
                    if ch.is_alphanumeric() || ch == '_' {
                        chars.next();
                    } else {
                        break;
                    }
                }
                let end = chars.peek().map_or(line.len(), |&(j, _)| j);
                let word = &line[start..end];

                let style = if DSL_FUNCTIONS.contains(&word) {
                    Style::new().fg(Color::Cyan).bold()
                } else if REPL_COMMANDS.contains(&word) {
                    Style::new().fg(Color::Green).bold()
                } else if word == "True" || word == "False" || word == "None" {
                    Style::new().fg(Color::Magenta)
                } else {
                    Style::new().fg(Color::White)
                };
                styled.push((style, word.to_string()));
            } else if c == '(' || c == ')' || c == '[' || c == ']' || c == '{' || c == '}' {
                chars.next();
                styled.push((Style::new().fg(Color::LightGray), c.to_string()));
            } else if c == '.' {
                // Method call — highlight the dot and method name together
                let start = i;
                chars.next();
                while let Some(&(_, ch)) = chars.peek() {
                    if ch.is_alphanumeric() || ch == '_' {
                        chars.next();
                    } else {
                        break;
                    }
                }
                let end = chars.peek().map_or(line.len(), |&(j, _)| j);
                let token = &line[start..end];
                styled.push((Style::new().fg(Color::Cyan), token.to_string()));
            } else {
                chars.next();
                styled.push((Style::new().fg(Color::White), c.to_string()));
            }
        }

        styled
    }
}

// ---------------------------------------------------------------------------
// Multi-line validator
// ---------------------------------------------------------------------------

struct BracketValidator;

impl Validator for BracketValidator {
    fn validate(&self, line: &str) -> ValidationResult {
        let mut depth: i32 = 0;
        let mut in_single = false;
        let mut in_double = false;

        for c in line.chars() {
            match c {
                '"' if !in_single => in_double = !in_double,
                '\'' if !in_double => in_single = !in_single,
                '(' | '{' | '[' if !in_single && !in_double => depth += 1,
                ')' | '}' | ']' if !in_single && !in_double => depth -= 1,
                _ => {}
            }
        }

        if depth > 0 || in_single || in_double {
            ValidationResult::Incomplete
        } else {
            ValidationResult::Complete
        }
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

enum PendingSave {
    /// Overwrite a file with new content.
    Overwrite { path: PathBuf, content: String },
    /// Write a .star file and add it as an include in a .json manifest.
    Include {
        star_path: PathBuf,
        star_content: String,
        json_path: PathBuf,
        include_name: String,
    },
}

#[derive(Default)]
struct PlaygroundState {
    /// Rule snippets (match, tool, etc.).
    rules: Vec<String>,
    /// Named sandbox definitions (variable name → expression).
    sandboxes: Vec<(String, String)>,
    /// Path to a loaded policy file, if any.
    loaded_file: Option<String>,
    /// Compiled policy from a loaded file (base to merge with added rules).
    loaded_compiled: Option<CompiledPolicy>,
    /// Current compiled policy (loaded + added rules merged).
    compiled: Option<CompiledPolicy>,
    /// Pending save awaiting confirmation.
    pending_save: Option<PendingSave>,
    /// Active mode for test evaluation (e.g. "plan", "edit").
    mode: Option<String>,
}

const STARLARK_LOAD_NAMES: &[&str] = &[
    "match", "policy", "settings", "sandbox", "cwd", "home", "tempdir", "path", "regex",
    "domains", "domain", "allow", "deny", "ask",
];

impl PlaygroundState {
    /// Recompile the current state into a CompiledPolicy.
    ///
    /// If a policy was loaded from file, the added rules are compiled separately
    /// and merged on top of the loaded policy's tree.
    fn recompile(&mut self) -> Result<()> {
        if self.rules.is_empty() {
            // No added rules — use loaded policy as-is (if any)
            self.compiled = self.loaded_compiled.clone();
            return Ok(());
        }

        let starlark_source = self.build_starlark_source();
        let json =
            clash_starlark::evaluate(&starlark_source, "playground.star", &PathBuf::from("."))
                .context("failed to evaluate policy")?;
        let mut tree = compile::compile_to_tree(&json.json)
            .context("failed to compile policy to decision tree")?;

        // Merge loaded policy tree (loaded rules come first, added rules override)
        if let Some(loaded) = &self.loaded_compiled {
            let mut merged = loaded.clone();
            merged.tree.extend(tree.tree);
            merged.sandboxes.extend(tree.sandboxes);
            tree = merged;
        }

        self.compiled = Some(tree);
        Ok(())
    }

    /// Build a complete Starlark policy source.
    fn build_starlark_source(&self) -> String {
        use clash_starlark::codegen::ast::{Expr, Stmt};
        use clash_starlark::codegen::builder::*;

        let mut stmts = vec![load_std(STARLARK_LOAD_NAMES), Stmt::Blank];

        // Emit sandbox definitions as top-level variables
        for (name, expr) in &self.sandboxes {
            stmts.push(Stmt::assign(name, Expr::raw(expr)));
        }
        if !self.sandboxes.is_empty() {
            stmts.push(Stmt::Blank);
        }

        let rules: Vec<Expr> = self.rules.iter().map(|r| Expr::raw(r.trim())).collect();
        stmts.push(Stmt::Expr(settings(deny(), None)));
        stmts.push(Stmt::Blank);
        stmts.push(Stmt::Expr(policy("playground", deny(), rules, None)));

        clash_starlark::codegen::serialize(&stmts)
    }

    fn reset(&mut self) {
        self.rules.clear();
        self.sandboxes.clear();
        self.loaded_file = None;
        self.loaded_compiled = None;
        self.compiled = None;
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

fn execute_pending_save(pending: PendingSave) -> String {
    match pending {
        PendingSave::Overwrite { path, content } => match std::fs::write(&path, &content) {
            Ok(()) => format!("Saved to {}", path.display()),
            Err(e) => format!("Failed to write {}: {e}", path.display()),
        },
        PendingSave::Include {
            star_path,
            star_content,
            json_path,
            include_name,
        } => {
            use crate::policy::match_tree::IncludeEntry;
            use crate::policy_loader::{read_manifest, write_manifest};

            // Write the .star file
            if let Err(e) = std::fs::write(&star_path, &star_content) {
                return format!("Failed to write {}: {e}", star_path.display());
            }

            // Add include to the .json manifest if not already present
            let mut manifest = match read_manifest(&json_path) {
                Ok(m) => m,
                Err(e) => return format!("Failed to read {}: {e:#}", json_path.display()),
            };

            if !manifest.includes.iter().any(|i| i.path == include_name) {
                manifest.includes.push(IncludeEntry {
                    path: include_name.clone(),
                });
                if let Err(e) = write_manifest(&json_path, &manifest) {
                    return format!("Failed to update {}: {e:#}", json_path.display());
                }
            }

            format!(
                "Saved {} and added include '{}' to {}",
                star_path.display(),
                include_name,
                json_path.display()
            )
        }
    }
}

enum ControlFlow {
    Continue(String),
    Quit,
}

fn dispatch(input: &str, state: &mut PlaygroundState) -> ControlFlow {
    // Handle pending save confirmation
    if state.pending_save.is_some() {
        match input {
            "yes" | "y" => {
                let pending = state.pending_save.take().unwrap();
                return ControlFlow::Continue(execute_pending_save(pending));
            }
            "no" | "n" => {
                state.pending_save = None;
                return ControlFlow::Continue("Save cancelled.".to_string());
            }
            _ => {
                return ControlFlow::Continue("Pending save — type 'yes' or 'no'.".to_string());
            }
        }
    }

    if input == "load" {
        // Load user-level policy
        match crate::settings::ClashSettings::policy_file() {
            Ok(path) => ControlFlow::Continue(handle_load_path(&path, state)),
            Err(e) => ControlFlow::Continue(format!("Cannot find user policy: {e:#}")),
        }
    } else if let Some(rest) = input.strip_prefix("load ") {
        ControlFlow::Continue(handle_load(rest.trim(), state))
    } else if let Some(rest) = input.strip_prefix("add rule ") {
        ControlFlow::Continue(handle_add_rule(rest.trim(), state))
    } else if let Some(rest) = input.strip_prefix("add sandbox ") {
        ControlFlow::Continue(handle_add_sandbox(rest.trim(), state))
    } else if input == "add" || input == "add rule" || input == "add sandbox" {
        ControlFlow::Continue("Usage: add rule <expr>  or  add sandbox <name> <expr>".to_string())
    } else if input == "save" {
        // Save to user-level policy
        match crate::settings::ClashSettings::policy_file() {
            Ok(path) => ControlFlow::Continue(handle_save_path(&path, state)),
            Err(e) => ControlFlow::Continue(format!("Cannot find user policy path: {e:#}")),
        }
    } else if let Some(rest) = input.strip_prefix("save ") {
        ControlFlow::Continue(handle_save(rest.trim(), state))
    } else if let Some(test_input) = input.strip_prefix("test ") {
        ControlFlow::Continue(handle_test(test_input.trim(), state))
    } else if input == "test" {
        ControlFlow::Continue("Usage: test <tool invocation>".to_string())
    } else if let Some(mode_name) = input.strip_prefix("mode ") {
        let mode_name = mode_name.trim();
        if mode_name == "none" || mode_name == "clear" || mode_name.is_empty() {
            state.mode = None;
            ControlFlow::Continue("Mode cleared (no mode set).".to_string())
        } else {
            state.mode = Some(mode_name.to_string());
            ControlFlow::Continue(format!(
                "Mode set to '{mode_name}'. Tests will evaluate with this mode."
            ))
        }
    } else if input == "mode" {
        let current = state.mode.as_deref().unwrap_or("(none)");
        ControlFlow::Continue(format!(
            "Current mode: {current}\nUsage: mode <name>  or  mode clear"
        ))
    } else {
        match input {
            "help" => ControlFlow::Continue(handle_help()),
            "functions" => ControlFlow::Continue(handle_functions()),
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
        "  load [path]              Load a policy file (default: user policy)",
        "  save [path]              Save current policy to a .star file (default: user policy)",
        "  add rule <expr>          Add a policy rule",
        "  add sandbox <name> <expr> Define a named sandbox",
        "  mode [name|clear]        Set/show the permission mode for test evaluation",
        "  test <tool>              Test a tool invocation against current policy",
        "  show                     Display current rules, sandboxes, and decision tree",
        "  reset                    Clear all rules and sandboxes",
        "  functions                Show available Starlark DSL functions",
        "  help                     Show this help message",
        "  quit / exit              Leave the playground",
        "",
        "Examples:",
        "  load ~/.clash/policy.star",
        "  add sandbox sb sandbox(\"sb\", fs=[cwd().allow(read=True, write=True)])",
        "  add rule match({\"Bash\": {\"git\": allow(sandbox=sb)}})",
        "  add rule match({\"Bash\": {\"git\": {\"push\": deny(), \"pull\": allow()}}})",
        "  test Bash { \"command\": \"git status\" }",
        "",
        "Tab completion is available for Starlark functions and commands.",
    ]
    .join("\n")
}

fn handle_functions() -> String {
    let mut lines = vec![format!(
        "{}\n",
        style::header("Available Starlark DSL functions:")
    )];
    for &(name, signature, description) in STARLARK_FUNCTIONS {
        lines.push(format!(
            "  {}  {}",
            style::bold(&format!("{signature:<50}")),
            description
        ));
        // Add usage hints for key functions
        match name {
            "match" => {
                lines.push(
                    "        match({\"Bash\": {\"git\": {\"push\": deny()}, \"cargo\": allow()}})"
                        .to_string(),
                );
                lines.push(
                    "        match({(\"Read\", \"Glob\"): allow(), \"WebSearch\": deny()})"
                        .to_string(),
                );
            }
            "cwd" => {
                lines.push(
                    "        cwd(follow_worktrees=True).allow(read=True, write=True)".to_string(),
                );
            }
            "sandbox" => {
                lines.push(
                    "        sandbox(\"my_sb\", fs=[cwd().allow(read=True)], net=allow())"
                        .to_string(),
                );
            }
            _ => {}
        }
    }

    lines.push(String::new());
    lines.push(style::header("Chainable methods:").to_string());
    lines.push("  .allow()  .deny()  .ask()  .sandbox(sb)  .on([children])".to_string());
    lines.push("  .child(name)  .file(name)  .recurse()  .match(regex)".to_string());

    lines.join("\n")
}

fn evaluate_policy_file(path: &std::path::Path) -> Result<String> {
    if path.extension().is_some_and(|ext| ext == "json") {
        crate::policy_loader::load_json_policy(path)
    } else {
        crate::policy_loader::evaluate_star_policy(path)
    }
}

fn handle_load(path_str: &str, state: &mut PlaygroundState) -> String {
    // Expand ~ to home directory
    let expanded = if let Some(rest) = path_str.strip_prefix("~/") {
        match dirs::home_dir() {
            Some(home) => home.join(rest),
            None => return "Cannot resolve home directory".to_string(),
        }
    } else {
        PathBuf::from(path_str)
    };
    handle_load_path(&expanded, state)
}

fn handle_load_path(path: &std::path::Path, state: &mut PlaygroundState) -> String {
    if !path.exists() {
        return format!("File not found: {}", path.display());
    }

    match evaluate_policy_file(path) {
        Ok(json_source) => match compile::compile_to_tree(&json_source) {
            Ok(tree) => {
                let rule_count = tree.tree.len();
                state.reset();
                state.loaded_file = Some(path.display().to_string());
                state.loaded_compiled = Some(tree.clone());
                state.compiled = Some(tree);
                format!(
                    "Loaded {} with {} top-level rules.",
                    path.display(),
                    rule_count
                )
            }
            Err(e) => format!("Policy compiled but failed to build tree: {e:#}"),
        },
        Err(e) => format!("Failed to evaluate {}: {e:#}", path.display()),
    }
}

fn handle_save(path_str: &str, state: &mut PlaygroundState) -> String {
    let expanded = if let Some(rest) = path_str.strip_prefix("~/") {
        match dirs::home_dir() {
            Some(home) => home.join(rest),
            None => return "Cannot resolve home directory".to_string(),
        }
    } else {
        PathBuf::from(path_str)
    };
    handle_save_path(&expanded, state)
}

fn handle_save_path(path: &std::path::Path, state: &mut PlaygroundState) -> String {
    if state.rules.is_empty() {
        return "Nothing to save. Add rules first.".to_string();
    }

    // If saving to a .json policy, add the playground rules as a .star include
    if path.extension().is_some_and(|ext| ext == "json") && path.exists() {
        return handle_save_as_include(path, state);
    }

    // Saving as .star
    let save_path = if path.extension().is_some_and(|ext| ext == "json") {
        // Target is .json but doesn't exist yet — save as .star sibling
        path.with_extension("star")
    } else {
        path.to_path_buf()
    };

    let new_source = state.build_starlark_source();

    // If file exists, show diff and ask for confirmation
    if save_path.exists() {
        let old_source = match std::fs::read_to_string(&save_path) {
            Ok(s) => s,
            Err(e) => return format!("Failed to read {}: {e}", save_path.display()),
        };

        if old_source.trim() == new_source.trim() {
            return format!(
                "No changes — {} is already up to date.",
                save_path.display()
            );
        }

        let mut lines = vec![format!(
            "{} {} already exists. Changes:\n",
            style::bold("Warning:"),
            save_path.display()
        )];
        render_diff(&old_source, &new_source, &mut lines);
        lines.push(String::new());
        lines.push("Type 'yes' to overwrite or 'no' to cancel.".to_string());

        state.pending_save = Some(PendingSave::Overwrite {
            path: save_path,
            content: new_source,
        });
        return lines.join("\n");
    }

    // New file — write directly
    if let Some(parent) = save_path.parent()
        && !parent.exists()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        return format!("Failed to create directory {}: {e}", parent.display());
    }

    match std::fs::write(&save_path, &new_source) {
        Ok(()) => format!("Saved to {}", save_path.display()),
        Err(e) => format!("Failed to write {}: {e}", save_path.display()),
    }
}

/// Save playground rules as a .star include added to an existing .json policy.
fn handle_save_as_include(json_path: &std::path::Path, state: &mut PlaygroundState) -> String {
    use crate::policy_loader::read_manifest;

    let manifest = match read_manifest(json_path) {
        Ok(m) => m,
        Err(e) => return format!("Failed to read {}: {e:#}", json_path.display()),
    };

    // Write the .star file next to the .json
    let star_path = json_path.with_extension("playground.star");
    let star_name = star_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let new_source = state.build_starlark_source();

    // Check if this include already exists
    let already_included = manifest.includes.iter().any(|i| i.path == star_name);

    let mut lines = Vec::new();

    if star_path.exists() {
        let old_source = match std::fs::read_to_string(&star_path) {
            Ok(s) => s,
            Err(e) => return format!("Failed to read {}: {e}", star_path.display()),
        };

        if old_source.trim() == new_source.trim() && already_included {
            return format!(
                "No changes — {} is already up to date.",
                star_path.display()
            );
        }

        lines.push(format!(
            "Will update {} with playground rules:",
            star_path.display()
        ));
        render_diff(&old_source, &new_source, &mut lines);
    } else {
        lines.push(format!("Will create {}", star_path.display()));
    }

    if !already_included {
        lines.push(format!(
            "Will add include '{}' to {}",
            star_name,
            json_path.display()
        ));
    }

    lines.push(String::new());
    lines.push("Type 'yes' to confirm or 'no' to cancel.".to_string());

    state.pending_save = Some(PendingSave::Include {
        star_path,
        star_content: new_source,
        json_path: json_path.to_path_buf(),
        include_name: star_name,
    });

    lines.join("\n")
}

fn render_diff(old: &str, new: &str, lines: &mut Vec<String>) {
    let diff = similar::TextDiff::from_lines(old, new);
    for change in diff.iter_all_changes() {
        match change.tag() {
            similar::ChangeTag::Delete => {
                lines.push(style::red(&format!("- {}", change.value().trim_end())).to_string());
            }
            similar::ChangeTag::Insert => {
                lines.push(style::green(&format!("+ {}", change.value().trim_end())).to_string());
            }
            similar::ChangeTag::Equal => {}
        }
    }
}

fn handle_add_rule(snippet: &str, state: &mut PlaygroundState) -> String {
    if snippet.is_empty() {
        return "Usage: add rule <starlark rule expression>".to_string();
    }

    state.rules.push(snippet.to_string());

    match state.recompile() {
        Ok(()) => {
            format!(
                "Rule added (total: {}). Use 'test' to evaluate.",
                state.rules.len()
            )
        }
        Err(e) => {
            state.rules.pop();
            let _ = state.recompile();
            format!("Error adding rule: {e:#}")
        }
    }
}

fn handle_add_sandbox(input: &str, state: &mut PlaygroundState) -> String {
    // Parse: <name> <expression>
    let Some((name, expr)) = input.split_once(' ') else {
        return "Usage: add sandbox <name> <expression>\n\
                Example: add sandbox sb sandbox(\"sb\", fs=[cwd().allow(read=True)])"
            .to_string();
    };
    let name = name.trim();
    let expr = expr.trim();

    if name.is_empty() || expr.is_empty() {
        return "Usage: add sandbox <name> <expression>".to_string();
    }

    // Check for duplicate names
    if state.sandboxes.iter().any(|(n, _)| n == name) {
        return format!("Sandbox '{name}' already defined. Use 'reset' to start over.");
    }

    state.sandboxes.push((name.to_string(), expr.to_string()));

    // Validate by trying to compile (if we have rules)
    if !state.rules.is_empty()
        && let Err(e) = state.recompile()
    {
        state.sandboxes.pop();
        let _ = state.recompile();
        return format!("Error adding sandbox: {e:#}");
    }

    format!("Sandbox '{name}' defined.")
}

fn handle_test(input: &str, state: &PlaygroundState) -> String {
    let tree = match &state.compiled {
        Some(t) => t,
        None => return "No policy loaded. Use 'add rule' first.".to_string(),
    };

    match crate::policy::test_eval::evaluate_test_with_mode(input, tree, state.mode.as_deref()) {
        Ok(result) => {
            let mut lines =
                display::format_tool_header("Input:", &result.tool_name, &result.tool_input);
            lines.push(String::new());
            lines.extend(display::format_decision(&result.decision));
            lines.join("\n")
        }
        Err(e) => format!("Failed to parse test input: {e}"),
    }
}

fn handle_show(state: &PlaygroundState) -> String {
    if state.rules.is_empty() && state.sandboxes.is_empty() && state.loaded_file.is_none() {
        return "No policy defined. Use 'add rule', 'add sandbox', or 'load <path>'.".to_string();
    }

    let mut lines = Vec::new();

    if let Some(path) = &state.loaded_file {
        lines.push(format!("{} {path}", style::header("Loaded:")));
        lines.push(String::new());
    }

    if !state.sandboxes.is_empty() {
        lines.push(style::header("Sandboxes:").to_string());
        for (name, expr) in &state.sandboxes {
            lines.push(format!("  {name} = {expr}"));
        }
        lines.push(String::new());
    }

    if !state.rules.is_empty() {
        lines.push(style::header("Rules:").to_string());
        for (i, rule) in state.rules.iter().enumerate() {
            lines.push(format!("  [{}] {}", i + 1, rule));
        }
    }

    if let Some(compiled) = &state.compiled {
        if !compiled.sandboxes.is_empty() {
            lines.push(String::new());
            for (name, sandbox) in &compiled.sandboxes {
                lines.push(format!("{} {name}", style::header("Sandbox:")));
                lines.extend(display::format_sandbox_summary(sandbox));
            }
        }

        lines.push(String::new());
        lines.push(style::header("Decision tree:").to_string());
        lines.extend(compiled.format_tree());
    }

    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run the interactive playground REPL.
#[instrument(level = Level::TRACE)]
pub fn run() -> Result<()> {
    println!("clash playground — interactive policy sandbox");
    println!("Type 'help' for commands, 'functions' for Starlark DSL reference.\n");

    let completer = Box::new(PlaygroundCompleter);
    let completion_menu = Box::new(
        ColumnarMenu::default()
            .with_name("completion_menu")
            .with_columns(1),
    );

    let mut keybindings = reedline::default_emacs_keybindings();
    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );
    keybindings.add_binding(
        KeyModifiers::SHIFT,
        KeyCode::BackTab,
        ReedlineEvent::MenuPrevious,
    );

    let edit_mode = Box::new(reedline::Emacs::new(keybindings));

    let mut editor = Reedline::create()
        .with_completer(completer)
        .with_menu(ReedlineMenu::EngineCompleter(completion_menu))
        .with_edit_mode(edit_mode)
        .with_highlighter(Box::new(StarlarkHighlighter))
        .with_validator(Box::new(BracketValidator));

    let prompt = DefaultPrompt::new(
        DefaultPromptSegment::Basic("clash ".to_string()),
        DefaultPromptSegment::Empty,
    );

    let mut state = PlaygroundState::default();

    loop {
        match editor.read_line(&prompt) {
            Ok(Signal::Success(line)) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                match dispatch(trimmed, &mut state) {
                    ControlFlow::Continue(output) => {
                        if !output.is_empty() {
                            println!("{output}");
                        }
                    }
                    ControlFlow::Quit => return Ok(()),
                }
            }
            Ok(Signal::CtrlD | Signal::CtrlC) => return Ok(()),
            Err(e) => {
                eprintln!("Error reading input: {e}");
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // parse_test_input tests have moved to policy::test_eval::tests

    #[test]
    fn test_dispatch_help() {
        let mut state = PlaygroundState::default();
        match dispatch("help", &mut state) {
            ControlFlow::Continue(output) => assert!(output.contains("Available commands")),
            ControlFlow::Quit => panic!("unexpected quit"),
        }
    }

    #[test]
    fn test_dispatch_functions() {
        let mut state = PlaygroundState::default();
        match dispatch("functions", &mut state) {
            ControlFlow::Continue(output) => {
                assert!(output.contains("match"));
                assert!(output.contains("tool"));
                assert!(output.contains("allow"));
            }
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
            ControlFlow::Continue(output) => assert!(output.contains("No policy defined")),
            ControlFlow::Quit => panic!("unexpected quit"),
        }
    }

    #[test]
    fn test_dispatch_test_no_policy() {
        let mut state = PlaygroundState::default();
        match dispatch(r#"test Bash { "command": "ls" }"#, &mut state) {
            ControlFlow::Continue(output) => assert!(output.contains("No policy loaded")),
            ControlFlow::Quit => panic!("unexpected quit"),
        }
    }

    #[test]
    fn test_policy_add_and_test() {
        let mut state = PlaygroundState::default();

        // Add a policy rule
        match dispatch(r#"add rule match({"Bash": {"git": allow()}})"#, &mut state) {
            ControlFlow::Continue(output) => assert!(output.contains("Rule added")),
            ControlFlow::Quit => panic!("unexpected quit"),
        }

        // Test a matching invocation
        match dispatch(r#"test Bash { "command": "git status" }"#, &mut state) {
            ControlFlow::Continue(output) => {
                assert!(
                    output.contains("allow"),
                    "expected 'allow' in output, got: {output}"
                );
            }
            ControlFlow::Quit => panic!("unexpected quit"),
        }

        // Test a non-matching invocation (default deny)
        match dispatch(r#"test Bash { "command": "rm -rf /" }"#, &mut state) {
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
        match dispatch("add rule this_is_not_valid(((", &mut state) {
            ControlFlow::Continue(output) => {
                assert!(
                    output.contains("Error"),
                    "expected error message, got: {output}"
                );
            }
            ControlFlow::Quit => panic!("unexpected quit"),
        }
        // State should still be empty after failed add
        assert!(state.rules.is_empty());
        assert!(state.compiled.is_none());
    }

    #[test]
    fn test_show_with_rules() {
        let mut state = PlaygroundState::default();
        dispatch(r#"add rule match({"Bash": {"git": allow()}})"#, &mut state);

        match dispatch("show", &mut state) {
            ControlFlow::Continue(output) => {
                assert!(output.contains("[1]"));
                assert!(output.contains("match("));
                // Should include the decision tree
                assert!(
                    output.contains("Decision tree:"),
                    "expected decision tree in show output, got: {output}"
                );
            }
            ControlFlow::Quit => panic!("unexpected quit"),
        }
    }

    #[test]
    fn test_build_starlark_source() {
        let mut state = PlaygroundState::default();
        state
            .rules
            .push(r#"match({"Bash": {"git": allow()}})"#.to_string());
        state
            .rules
            .push(r#"match({"Read": allow()})"#.to_string());

        let source = state.build_starlark_source();
        assert!(source.contains("settings("));
        assert!(source.contains(r#"match({"Bash": {"git": allow()}})"#));
        assert!(source.contains(r#"match({"Read": allow()})"#));
        assert!(source.contains("policy("));
        assert!(source.contains("\"match\""));
        assert!(source.contains("\"allow\""));
    }

    #[test]
    fn test_build_starlark_source_with_sandbox() {
        let mut state = PlaygroundState::default();
        state
            .sandboxes
            .push(("sb".to_string(), r#"sandbox("sb", fs=[])"#.to_string()));
        state
            .rules
            .push(r#"match({"Bash": {"git": allow(sandbox=sb)}})"#.to_string());

        let source = state.build_starlark_source();
        assert!(source.contains(r#"sb = sandbox("sb", fs=[])"#));
        assert!(source.contains("policy("));
    }

    #[test]
    fn test_completer_starlark_functions() {
        let mut completer = PlaygroundCompleter;
        let suggestions = completer.complete("add rule ma", 11);
        assert!(
            suggestions.iter().any(|s| s.value == "match("),
            "expected match( completion, got: {:?}",
            suggestions.iter().map(|s| &s.value).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_completer_commands() {
        let mut completer = PlaygroundCompleter;
        let suggestions = completer.complete("he", 2);
        assert!(suggestions.iter().any(|s| s.value == "help"));

        let suggestions = completer.complete("add", 3);
        assert!(
            suggestions.iter().any(|s| s.value == "add rule"),
            "got: {:?}",
            suggestions.iter().map(|s| &s.value).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_completer_dot_methods() {
        let mut completer = PlaygroundCompleter;
        let suggestions = completer.complete("add rule cwd().al", 17);
        assert!(
            suggestions.iter().any(|s| s.value == ".allow()"),
            "expected .allow() completion, got: {:?}",
            suggestions.iter().map(|s| &s.value).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_match_toplevel_policy() {
        let mut state = PlaygroundState::default();

        // match() should work as a standalone policy
        match dispatch(
            r#"add rule match({"Bash": {"git": {"push": deny(), "status": allow()}}})"#,
            &mut state,
        ) {
            ControlFlow::Continue(output) => {
                assert!(output.contains("Rule added"), "got: {output}")
            }
            ControlFlow::Quit => panic!("unexpected quit"),
        }

        // Test against it
        match dispatch(r#"test Bash { "command": "git push" }"#, &mut state) {
            ControlFlow::Continue(output) => {
                assert!(output.contains("deny"), "expected deny, got: {output}");
            }
            ControlFlow::Quit => panic!("unexpected quit"),
        }

        match dispatch(r#"test Bash { "command": "git status" }"#, &mut state) {
            ControlFlow::Continue(output) => {
                assert!(output.contains("allow"), "expected allow, got: {output}");
            }
            ControlFlow::Quit => panic!("unexpected quit"),
        }
    }

    #[test]
    fn test_sandbox_with_rules() {
        let mut state = PlaygroundState::default();

        let result = dispatch(
            r#"add rule match({"Bash": {"git": allow(sandbox=sandbox("sb", fs=[cwd().allow(read=True, write=True)]))}})"#,
            &mut state,
        );
        match result {
            ControlFlow::Continue(output) => {
                assert!(output.contains("Rule added"), "got: {output}");
            }
            ControlFlow::Quit => panic!("unexpected quit"),
        }

        // show should include sandbox info in the tree
        match dispatch("show", &mut state) {
            ControlFlow::Continue(output) => {
                assert!(
                    output.contains("Decision tree:"),
                    "expected tree, got: {output}"
                );
            }
            ControlFlow::Quit => panic!("unexpected quit"),
        }
    }

    #[test]
    fn test_sandbox_with_match() {
        let mut state = PlaygroundState::default();

        let result = dispatch(
            r#"add rule match({"Bash": {"git": {"push": deny(), "status": allow(sandbox=sandbox("sb", fs=[cwd().allow(read=True)]))}}})"#,
            &mut state,
        );
        match result {
            ControlFlow::Continue(output) => {
                assert!(output.contains("Rule added"), "got: {output}");
            }
            ControlFlow::Quit => panic!("unexpected quit"),
        }
    }

    #[test]
    fn test_match_mixes_with_rules() {
        let mut state = PlaygroundState::default();
        dispatch(
            r#"add rule match({"Bash": {"cargo": allow()}})"#,
            &mut state,
        );

        // Multiple match() calls should mix fine
        match dispatch(
            r#"add rule match({"Bash": {"git": {"push": deny()}}})"#,
            &mut state,
        ) {
            ControlFlow::Continue(output) => {
                assert!(output.contains("Rule added"), "got: {output}");
            }
            ControlFlow::Quit => panic!("unexpected quit"),
        }
        assert_eq!(state.rules.len(), 2);
    }

    #[test]
    fn test_add_sandbox_and_use() {
        let mut state = PlaygroundState::default();

        match dispatch(
            r#"add sandbox sb sandbox("sb", fs=[cwd().allow(read=True, write=True)])"#,
            &mut state,
        ) {
            ControlFlow::Continue(output) => {
                assert!(output.contains("defined"), "got: {output}");
            }
            ControlFlow::Quit => panic!("unexpected quit"),
        }

        match dispatch(
            r#"add rule match({"Bash": {"git": allow(sandbox=sb)}})"#,
            &mut state,
        ) {
            ControlFlow::Continue(output) => {
                assert!(output.contains("Rule added"), "got: {output}");
            }
            ControlFlow::Quit => panic!("unexpected quit"),
        }

        // Show should display both sandbox and rules
        match dispatch("show", &mut state) {
            ControlFlow::Continue(output) => {
                assert!(output.contains("Sandboxes:"), "got: {output}");
                assert!(output.contains("sb ="), "got: {output}");
                assert!(output.contains("Decision tree:"), "got: {output}");
            }
            ControlFlow::Quit => panic!("unexpected quit"),
        }
    }
}
