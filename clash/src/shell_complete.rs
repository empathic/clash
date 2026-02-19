//! Tab-completion, prompt, and hinting for the interactive policy shell.
//!
//! Provides a context-aware [`ShellCompleter`] that walks the s-expression
//! grammar tree to determine what completions are valid at the cursor position.
//! The completer tracks paren depth and the keyword that opened each nesting
//! level to offer domain-specific candidates (exec args vs fs ops vs patterns).

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use reedline::{Completer, Prompt, Span, Suggestion};

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Mutable state shared between the REPL loop and the completer.
pub struct CompletionState {
    pub policy_names: Vec<String>,
    pub current_policy: String,
}

pub type SharedState = Arc<Mutex<CompletionState>>;

// ---------------------------------------------------------------------------
// Static candidate tables
// ---------------------------------------------------------------------------

const COMMANDS: &[(&str, &str)] = &[
    ("add", "Add a rule to a policy block"),
    ("remove", "Remove a rule by its text"),
    ("create", "Create a new policy block"),
    ("default", "Change the default effect"),
    ("use", "Switch active policy context"),
    ("show", "Display policy with pending changes"),
    ("rules", "List rules in a policy block"),
    ("test", "Test if a tool invocation is allowed"),
    ("diff", "Show pending changes as diff"),
    ("apply", "Write changes and exit"),
    ("abort", "Discard changes and exit"),
    ("help", "Show available commands"),
];

const EFFECTS: &[(&str, &str)] = &[
    ("allow", "Permit the capability"),
    ("deny", "Block the capability"),
    ("ask", "Prompt the user"),
];

const DOMAINS: &[(&str, &str)] = &[
    ("exec", "Command execution"),
    ("fs", "Filesystem access"),
    ("net", "Network access"),
    ("tool", "MCP tool use"),
];

const FS_OPS: &[(&str, &str)] = &[
    ("read", "File read"),
    ("write", "File write"),
    ("create", "File create"),
    ("delete", "File delete"),
];

const PATH_FILTER_FORMS: &[(&str, &str)] = &[
    ("(subpath ", "Match path and all children"),
    ("(or ", "Match any of several paths"),
    ("(not ", "Exclude a path"),
];

const PATH_EXPR_FORMS: &[(&str, &str)] = &[
    ("(env ", "Environment variable ($HOME, $PWD, ...)"),
    ("(join ", "Concatenate path segments"),
];

const COMMON_ENV_VARS: &[(&str, &str)] = &[
    ("PWD", "Current working directory"),
    ("HOME", "Home directory"),
];

const PATTERN_FORMS: &[(&str, &str)] = &[
    ("*", "Match anything (wildcard)"),
    ("(or ", "Match any of several values"),
    ("(not ", "Exclude a value"),
];

const TEST_TOOLS: &[(&str, &str)] = &[
    ("bash", "Shell command (alias for Bash)"),
    ("read", "File read (alias for Read)"),
    ("write", "File write (alias for Write)"),
    ("edit", "File edit (alias for Edit)"),
    ("Bash", "Bash tool"),
    ("Read", "Read tool"),
    ("Write", "Write tool"),
    ("Edit", "Edit tool"),
    ("Glob", "File glob tool"),
    ("Grep", "Content search tool"),
    ("WebFetch", "Web fetch tool"),
    ("WebSearch", "Web search tool"),
    ("NotebookEdit", "Notebook edit tool"),
];

// ---------------------------------------------------------------------------
// S-expression context analysis
// ---------------------------------------------------------------------------

/// What the completer should offer at a given cursor position.
#[derive(Debug)]
enum SexprContext {
    /// Depth 1: expecting an effect keyword (allow/deny/ask).
    Effect { partial: String },
    /// Depth 2: expecting a domain keyword (exec/fs/net/tool).
    DomainKeyword { partial: String },
    /// Inside `(exec ...)` — expecting patterns, `:has`, or `:sandbox`.
    ExecArgs {
        partial: String,
        arg_index: usize,
        saw_has: bool,
    },
    /// Inside `(fs ...)` — expecting op pattern or path filter.
    FsArgs { partial: String, arg_index: usize },
    /// Inside `(net ...)` — expecting a domain pattern.
    NetArgs { partial: String },
    /// Inside `(tool ...)` — expecting a tool name pattern.
    ToolArgs { partial: String },
    /// Inside `(or ...)` with known parent context.
    OrList {
        parent: Box<SexprContext>,
        partial: String,
    },
    /// Inside `(not ...)` with known parent context.
    NotArg { partial: String },
    /// Inside `(subpath ...)` — expecting a path expression.
    SubpathExpr { partial: String },
    /// Inside `(env ...)` — expecting an env var name.
    EnvName { partial: String },
    /// Inside `(join ...)` — expecting path expressions.
    JoinExpr { partial: String },
    /// After the rule s-expr closed, at depth 1 — keyword args like `:sandbox`.
    RuleKeywordArgs { partial: String },
    /// Fully closed or unknown — no completions.
    None,
}

/// Analyze the s-expression text (the part after the shell verb) to determine
/// what the cursor is positioned to receive.
fn analyze_sexpr(text: &str) -> SexprContext {
    // We walk the text tracking a stack of (keyword, arg_count) for each open paren.
    // When we reach the end, the stack tells us where we are.

    let mut stack: Vec<Frame> = Vec::new();
    let mut partial = String::new();
    let mut in_string = false;
    let mut in_regex = false;
    let mut escape_next = false;

    for ch in text.chars() {
        if escape_next {
            partial.push(ch);
            escape_next = false;
            continue;
        }

        if in_string {
            if ch == '\\' {
                escape_next = true;
                partial.push(ch);
            } else if ch == '"' {
                partial.push(ch);
                in_string = false;
            } else {
                partial.push(ch);
            }
            continue;
        }

        if in_regex {
            partial.push(ch);
            if ch == '/' {
                in_regex = false;
            }
            continue;
        }

        match ch {
            '"' => {
                partial.push(ch);
                in_string = true;
            }
            '/' if partial.is_empty() || partial.chars().all(|c| c.is_whitespace()) => {
                partial = "/".into();
                in_regex = true;
            }
            '(' => {
                // Start a new nesting level — the partial so far is discarded
                // (it was whitespace or nothing before the paren)
                stack.push(Frame {
                    keyword: String::new(),
                    arg_count: 0,
                    saw_has: false,
                });
                partial.clear();
            }
            ')' => {
                stack.pop();
                // After closing, the closed form counts as an arg to the parent
                if let Some(parent) = stack.last_mut() {
                    if parent.keyword.is_empty() {
                        // Shouldn't happen in valid input, but be defensive
                    } else {
                        parent.arg_count += 1;
                    }
                }
                partial.clear();
            }
            c if c.is_whitespace() => {
                let word = partial.trim().to_string();
                if !word.is_empty()
                    && let Some(frame) = stack.last_mut()
                {
                    if frame.keyword.is_empty() {
                        frame.keyword = word.clone();
                    } else {
                        if word == ":has" {
                            frame.saw_has = true;
                        }
                        frame.arg_count += 1;
                    }
                }
                partial.clear();
            }
            _ => {
                partial.push(ch);
            }
        }
    }

    // Now interpret the stack + remaining partial.
    let partial = partial.trim().to_string();

    if stack.is_empty() {
        // No open parens — either nothing typed or all parens closed.
        // If depth 0 and no parens at all, user needs to open one.
        if text.trim().is_empty() {
            return SexprContext::Effect { partial };
        }
        // All parens closed — check if we might be at rule keyword arg position
        // by seeing if there was a complete rule form
        return SexprContext::RuleKeywordArgs { partial };
    }

    let depth = stack.len();
    let frame = stack.last().unwrap();

    match depth {
        1 => {
            if frame.keyword.is_empty() {
                // Just typed `(` — offer effects
                SexprContext::Effect { partial }
            } else if frame.keyword == "or" {
                // `(or ...` at depth 1 — effects
                SexprContext::OrList {
                    parent: Box::new(SexprContext::Effect {
                        partial: String::new(),
                    }),
                    partial,
                }
            } else {
                // Have effect keyword, past the matcher — keyword args like :sandbox
                SexprContext::RuleKeywordArgs { partial }
            }
        }
        2 => {
            let parent_kw = &stack[0].keyword;
            let is_effect = parent_kw == "allow" || parent_kw == "deny" || parent_kw == "ask";

            if !is_effect {
                return SexprContext::None;
            }

            if frame.keyword.is_empty() {
                // Just typed `(allow (` — offer domains
                SexprContext::DomainKeyword { partial }
            } else {
                // Inside a domain matcher
                match frame.keyword.as_str() {
                    "exec" => SexprContext::ExecArgs {
                        partial,
                        arg_index: frame.arg_count,
                        saw_has: frame.saw_has,
                    },
                    "fs" => SexprContext::FsArgs {
                        partial,
                        arg_index: frame.arg_count,
                    },
                    "net" => SexprContext::NetArgs { partial },
                    "tool" => SexprContext::ToolArgs { partial },
                    "or" => {
                        // `(or ...` at depth 2 — domain keywords
                        SexprContext::OrList {
                            parent: Box::new(SexprContext::DomainKeyword {
                                partial: String::new(),
                            }),
                            partial,
                        }
                    }
                    _ => SexprContext::None,
                }
            }
        }
        _ => {
            // depth >= 3 — we need to figure out what context the inner form is in
            // by walking up the stack
            resolve_deep_context(&stack, &partial)
        }
    }
}

/// For depth >= 3, walk the stack to determine context.
fn resolve_deep_context(stack: &[Frame], partial: &str) -> SexprContext {
    let frame = stack.last().unwrap();
    let partial = partial.to_string();

    // Check what keyword opened this frame
    match frame.keyword.as_str() {
        "" => {
            // Just opened a paren — what does the parent expect?
            let parent_context = parent_expecting(stack);
            match parent_context {
                ParentExpects::Pattern => {
                    // Could be `(or`, `(not`, etc.
                    SexprContext::Effect { partial } // reuse: offer or/not as patterns
                }
                ParentExpects::FsOp => SexprContext::FsArgs {
                    partial,
                    arg_index: 0,
                },
                ParentExpects::PathFilter => {
                    // Inside path filter context, offer subpath/or/not
                    SexprContext::SubpathExpr { partial }
                }
                ParentExpects::PathExpr => SexprContext::SubpathExpr { partial },
                _ => SexprContext::None,
            }
        }
        "or" => {
            let parent_ctx = parent_expecting(stack);
            match parent_ctx {
                ParentExpects::Pattern => SexprContext::OrList {
                    parent: Box::new(SexprContext::ExecArgs {
                        partial: String::new(),
                        arg_index: 0,
                        saw_has: false,
                    }),
                    partial,
                },
                ParentExpects::FsOp => SexprContext::FsArgs {
                    partial,
                    arg_index: 0,
                },
                ParentExpects::PathFilter => SexprContext::OrList {
                    parent: Box::new(SexprContext::SubpathExpr {
                        partial: String::new(),
                    }),
                    partial,
                },
                _ => SexprContext::None,
            }
        }
        "not" => {
            let parent_ctx = parent_expecting(stack);
            match parent_ctx {
                ParentExpects::Pattern | ParentExpects::PathFilter => {
                    SexprContext::NotArg { partial }
                }
                _ => SexprContext::None,
            }
        }
        "subpath" => SexprContext::SubpathExpr { partial },
        "env" => SexprContext::EnvName { partial },
        "join" => SexprContext::JoinExpr { partial },
        // Domains at deeper nesting (shouldn't normally happen but be safe)
        "exec" => SexprContext::ExecArgs {
            partial,
            arg_index: frame.arg_count,
            saw_has: frame.saw_has,
        },
        "fs" => SexprContext::FsArgs {
            partial,
            arg_index: frame.arg_count,
        },
        "net" => SexprContext::NetArgs { partial },
        "tool" => SexprContext::ToolArgs { partial },
        _ => SexprContext::None,
    }
}

#[derive(Debug)]
enum ParentExpects {
    Pattern,
    FsOp,
    PathFilter,
    PathExpr,
    Unknown,
}

/// Walk up from current frame to determine what the parent context expects.
fn parent_expecting(stack: &[Frame]) -> ParentExpects {
    // Walk from second-to-last up
    for frame in stack.iter().rev().skip(1) {
        match frame.keyword.as_str() {
            "exec" => return ParentExpects::Pattern,
            "net" | "tool" => return ParentExpects::Pattern,
            "fs" => {
                // arg_index 0 → op pattern, 1+ → path filter
                if frame.arg_count == 0 {
                    return ParentExpects::FsOp;
                }
                return ParentExpects::PathFilter;
            }
            "subpath" => return ParentExpects::PathExpr,
            "join" => return ParentExpects::PathExpr,
            "or" | "not" => continue, // keep walking up
            _ => {}
        }
    }
    ParentExpects::Unknown
}

// We need Frame to be accessible from analyze_sexpr and resolve_deep_context.
// Move the struct definition up.
#[derive(Debug, Clone)]
struct Frame {
    keyword: String,
    arg_count: usize,
    saw_has: bool,
}

// ---------------------------------------------------------------------------
// ShellCompleter
// ---------------------------------------------------------------------------

pub struct ShellCompleter {
    state: SharedState,
}

impl ShellCompleter {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }

    fn completions(&self, line: &str, pos: usize) -> Vec<Suggestion> {
        let prefix = &line[..pos];
        let trimmed = prefix.trim_start();

        if trimmed.is_empty() {
            return Self::suggest_from(COMMANDS, "", 0, pos);
        }

        // Split into verb + rest
        let (verb, rest) = match trimmed.find(|c: char| c.is_whitespace()) {
            Some(i) => (&trimmed[..i], trimmed[i..].trim_start()),
            None => {
                return Self::suggest_from(COMMANDS, trimmed, pos - trimmed.len(), pos);
            }
        };

        match verb {
            "add" | "remove" => self.complete_add_remove(rest, pos),
            "default" => self.complete_default(rest, pos),
            "use" | "create" | "rules" => self.complete_policy_name(rest, pos),
            "test" => Self::complete_test(rest, pos),
            "help" => Self::complete_help(rest, pos),
            _ => vec![],
        }
    }

    /// Completions for `add`/`remove` — s-expression builder.
    fn complete_add_remove(&self, rest: &str, pos: usize) -> Vec<Suggestion> {
        // If nothing typed yet, or first non-paren word could be a policy name
        if rest.is_empty() {
            // Offer open-paren to start the s-expression, plus policy names
            let mut suggestions =
                vec![self.suggestion("(", "Start rule: (effect (domain ...))", pos, pos, false)];
            if let Ok(state) = self.state.lock() {
                for name in &state.policy_names {
                    suggestions.push(self.suggestion(
                        name,
                        "Target a specific policy block",
                        pos,
                        pos,
                        true,
                    ));
                }
            }
            return suggestions;
        }

        // If the first char is not `(`, the first word might be a policy name
        // followed by a space, then the s-expression
        if !rest.starts_with('(') {
            // Check if there's a space — if so, the first word is a policy name
            // and the rest is the s-expression
            if let Some(space_idx) = rest.find(|c: char| c.is_whitespace()) {
                let after_policy = rest[space_idx..].trim_start();
                if after_policy.is_empty() {
                    // Typed "policyname " — offer open paren
                    return vec![self.suggestion(
                        "(",
                        "Start rule: (effect (domain ...))",
                        pos,
                        pos,
                        false,
                    )];
                }
                // Has s-expr content after policy name
                return self.complete_sexpr_context(after_policy, pos);
            }
            // Still typing first word — could be a policy name
            return self.suggest_policies(rest, pos);
        }

        // Has s-expression content
        self.complete_sexpr_context(rest, pos)
    }

    /// Complete inside an s-expression using grammar-aware context analysis.
    fn complete_sexpr_context(&self, sexpr: &str, pos: usize) -> Vec<Suggestion> {
        let ctx = analyze_sexpr(sexpr);
        self.suggestions_for_context(ctx, pos)
    }

    /// Map a parsed context to concrete suggestions.
    fn suggestions_for_context(&self, ctx: SexprContext, pos: usize) -> Vec<Suggestion> {
        match ctx {
            SexprContext::Effect { ref partial } => {
                Self::suggest_from(EFFECTS, partial, pos - partial.len(), pos)
            }
            SexprContext::DomainKeyword { ref partial } => {
                Self::suggest_from(DOMAINS, partial, pos - partial.len(), pos)
            }
            SexprContext::ExecArgs {
                ref partial,
                arg_index,
                saw_has,
            } => self.complete_exec_args(partial, arg_index, saw_has, pos),
            SexprContext::FsArgs {
                ref partial,
                arg_index,
            } => self.complete_fs_args(partial, arg_index, pos),
            SexprContext::NetArgs { ref partial } => {
                Self::suggest_from(PATTERN_FORMS, partial, pos - partial.len(), pos)
            }
            SexprContext::ToolArgs { ref partial } => {
                Self::suggest_from(PATTERN_FORMS, partial, pos - partial.len(), pos)
            }
            SexprContext::OrList {
                ref parent,
                ref partial,
            } => {
                // Inside `(or ...)` — offer whatever the parent expects
                match parent.as_ref() {
                    SexprContext::Effect { .. } => {
                        Self::suggest_from(EFFECTS, partial, pos - partial.len(), pos)
                    }
                    SexprContext::DomainKeyword { .. } => {
                        Self::suggest_from(DOMAINS, partial, pos - partial.len(), pos)
                    }
                    SexprContext::ExecArgs { .. } => {
                        Self::suggest_from(PATTERN_FORMS, partial, pos - partial.len(), pos)
                    }
                    SexprContext::SubpathExpr { .. } => {
                        // or of path filters
                        let mut candidates: Vec<(&str, &str)> = PATH_FILTER_FORMS.to_vec();
                        candidates.push(("*", "Match any path"));
                        Self::suggest_from(&candidates, partial, pos - partial.len(), pos)
                    }
                    SexprContext::FsArgs { arg_index, .. } if *arg_index == 0 => {
                        // (or inside fs op position — offer fs ops
                        Self::suggest_from(FS_OPS, partial, pos - partial.len(), pos)
                    }
                    _ => Self::suggest_from(PATTERN_FORMS, partial, pos - partial.len(), pos),
                }
            }
            SexprContext::NotArg { ref partial, .. } => {
                // Inside `(not ...)` — same as parent but single value
                Self::suggest_from(PATTERN_FORMS, partial, pos - partial.len(), pos)
            }
            SexprContext::SubpathExpr { ref partial } => {
                // Expecting a path expression
                let mut candidates: Vec<(&str, &str)> = PATH_EXPR_FORMS.to_vec();
                // Also offer direct path filter forms if at the right level
                candidates.extend_from_slice(PATH_FILTER_FORMS);
                Self::suggest_from(&candidates, partial, pos - partial.len(), pos)
            }
            SexprContext::EnvName { ref partial } => {
                Self::suggest_from(COMMON_ENV_VARS, partial, pos - partial.len(), pos)
            }
            SexprContext::JoinExpr { ref partial } => {
                Self::suggest_from(PATH_EXPR_FORMS, partial, pos - partial.len(), pos)
            }
            SexprContext::RuleKeywordArgs { ref partial } => {
                // After the matcher closed — offer :sandbox
                let candidates: &[(&str, &str)] = &[(":sandbox", "Apply sandbox policy")];
                Self::suggest_from(candidates, partial, pos - partial.len(), pos)
            }
            SexprContext::None => vec![],
        }
    }

    /// Completions inside `(exec ...)`.
    fn complete_exec_args(
        &self,
        partial: &str,
        arg_index: usize,
        saw_has: bool,
        pos: usize,
    ) -> Vec<Suggestion> {
        let start = pos - partial.len();
        let mut suggestions = Vec::new();

        // Always offer pattern forms
        for (name, desc) in PATTERN_FORMS {
            if name.starts_with(partial) {
                suggestions.push(self.suggestion(name, desc, start, pos, true));
            }
        }

        // After the binary (arg_index >= 1), offer :has if not already seen
        if arg_index >= 1 && !saw_has && ":has".starts_with(partial) {
            suggestions.push(self.suggestion(
                ":has",
                "Match arguments in any order",
                start,
                pos,
                true,
            ));
        }

        suggestions
    }

    /// Completions inside `(fs ...)`.
    fn complete_fs_args(&self, partial: &str, arg_index: usize, pos: usize) -> Vec<Suggestion> {
        let start = pos - partial.len();
        match arg_index {
            0 => {
                // First arg: filesystem operation
                let mut suggestions = Vec::new();
                for (name, desc) in FS_OPS {
                    if name.starts_with(partial) {
                        suggestions.push(self.suggestion(name, desc, start, pos, true));
                    }
                }
                // Also offer wildcard and (or
                if "*".starts_with(partial) {
                    suggestions.push(self.suggestion("*", "Any operation", start, pos, true));
                }
                if "(or ".starts_with(partial) {
                    suggestions.push(self.suggestion(
                        "(or ",
                        "Multiple operations: (or read write)",
                        start,
                        pos,
                        false,
                    ));
                }
                suggestions
            }
            _ => {
                // Second arg: path filter
                let mut suggestions = Vec::new();
                for (name, desc) in PATH_FILTER_FORMS {
                    if name.starts_with(partial) {
                        suggestions.push(self.suggestion(name, desc, start, pos, false));
                    }
                }
                // Also offer wildcard and string literal hint
                if "*".starts_with(partial) {
                    suggestions.push(self.suggestion("*", "Any path", start, pos, true));
                }
                suggestions
            }
        }
    }

    // -- Non-sexpr command completions (unchanged) --

    fn complete_default(&self, rest: &str, pos: usize) -> Vec<Suggestion> {
        let parts: Vec<&str> = rest.split_whitespace().collect();
        match parts.len() {
            0 => Self::suggest_from(EFFECTS, "", pos, pos),
            1 if !rest.ends_with(char::is_whitespace) => {
                Self::suggest_from(EFFECTS, parts[0], pos - parts[0].len(), pos)
            }
            1 => self.suggest_policies("", pos),
            2 if !rest.ends_with(char::is_whitespace) => self.suggest_policies(parts[1], pos),
            _ => vec![],
        }
    }

    fn complete_policy_name(&self, rest: &str, pos: usize) -> Vec<Suggestion> {
        let partial = rest.split_whitespace().last().unwrap_or("");
        if rest.contains(char::is_whitespace) && rest.ends_with(char::is_whitespace) {
            return vec![];
        }
        self.suggest_policies(partial, pos)
    }

    fn complete_test(rest: &str, pos: usize) -> Vec<Suggestion> {
        let parts: Vec<&str> = rest.split_whitespace().collect();
        match parts.len() {
            0 => Self::suggest_from(TEST_TOOLS, "", pos, pos),
            1 if !rest.ends_with(char::is_whitespace) => {
                Self::suggest_from(TEST_TOOLS, parts[0], pos - parts[0].len(), pos)
            }
            _ => vec![],
        }
    }

    fn complete_help(rest: &str, pos: usize) -> Vec<Suggestion> {
        let partial = rest.split_whitespace().last().unwrap_or("");
        if rest.contains(char::is_whitespace) && rest.ends_with(char::is_whitespace) {
            return vec![];
        }
        Self::suggest_from(COMMANDS, partial, pos - partial.len(), pos)
    }

    // -- Helpers --

    fn suggest_policies(&self, partial: &str, pos: usize) -> Vec<Suggestion> {
        let start = pos - partial.len();
        let Ok(state) = self.state.lock() else {
            return vec![];
        };
        state
            .policy_names
            .iter()
            .filter(|n| n.starts_with(partial))
            .map(|name| Suggestion {
                value: name.clone(),
                description: Some("Policy block".into()),
                style: None,
                extra: None,
                span: Span::new(start, pos),
                append_whitespace: true,
                match_indices: None,
            })
            .collect()
    }

    fn suggest_from(
        candidates: &[(&str, &str)],
        prefix: &str,
        start: usize,
        end: usize,
    ) -> Vec<Suggestion> {
        candidates
            .iter()
            .filter(|(name, _)| name.starts_with(prefix))
            .map(|(name, desc)| Suggestion {
                value: (*name).into(),
                description: Some((*desc).into()),
                style: None,
                extra: None,
                span: Span::new(start, end),
                append_whitespace: true,
                match_indices: None,
            })
            .collect()
    }

    fn suggestion(
        &self,
        value: &str,
        desc: &str,
        start: usize,
        end: usize,
        append_ws: bool,
    ) -> Suggestion {
        Suggestion {
            value: value.into(),
            description: Some(desc.into()),
            style: None,
            extra: None,
            span: Span::new(start, end),
            append_whitespace: append_ws,
            match_indices: None,
        }
    }
}

impl Completer for ShellCompleter {
    fn complete(&mut self, line: &str, pos: usize) -> Vec<Suggestion> {
        self.completions(line, pos)
    }
}

// ---------------------------------------------------------------------------
// ShellPrompt
// ---------------------------------------------------------------------------

pub struct ShellPrompt {
    state: SharedState,
}

impl ShellPrompt {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }
}

impl Prompt for ShellPrompt {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        let policy = self
            .state
            .lock()
            .map(|s| s.current_policy.clone())
            .unwrap_or_else(|_| "?".into());
        Cow::Owned(format!("clash[{policy}]"))
    }

    fn render_prompt_right(&self) -> Cow<'_, str> {
        Cow::Borrowed("")
    }

    fn render_prompt_indicator(&self, _prompt_mode: reedline::PromptEditMode) -> Cow<'_, str> {
        Cow::Borrowed("> ")
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        Cow::Borrowed("... ")
    }

    fn render_prompt_history_search_indicator(
        &self,
        _history_search: reedline::PromptHistorySearch,
    ) -> Cow<'_, str> {
        Cow::Borrowed("(search) ")
    }

    fn get_prompt_color(&self) -> reedline::Color {
        reedline::Color::Cyan
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state(policies: &[&str], current: &str) -> SharedState {
        Arc::new(Mutex::new(CompletionState {
            policy_names: policies.iter().map(|s| s.to_string()).collect(),
            current_policy: current.into(),
        }))
    }

    fn values(suggestions: &[Suggestion]) -> Vec<&str> {
        suggestions.iter().map(|s| s.value.as_str()).collect()
    }

    #[test]
    fn empty_line_suggests_commands() {
        let state = make_state(&["main"], "main");
        let mut c = ShellCompleter::new(state);
        let s = c.complete("", 0);
        let v = values(&s);
        assert!(v.contains(&"add"));
        assert!(v.contains(&"help"));
        assert!(v.contains(&"apply"));
    }

    #[test]
    fn partial_command_filters() {
        let state = make_state(&["main"], "main");
        let mut c = ShellCompleter::new(state);
        let s = c.complete("he", 2);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].value, "help");
    }

    #[test]
    fn add_empty_offers_paren_and_policies() {
        let state = make_state(&["main", "sandbox"], "main");
        let mut c = ShellCompleter::new(state);
        let s = c.complete("add ", 4);
        let v = values(&s);
        assert!(v.contains(&"("), "should offer open paren");
        assert!(v.contains(&"main"), "should offer policy names");
        assert!(v.contains(&"sandbox"));
    }

    #[test]
    fn add_paren_suggests_effects() {
        let state = make_state(&["main"], "main");
        let mut c = ShellCompleter::new(state);
        let s = c.complete("add (", 5);
        let v = values(&s);
        assert!(v.contains(&"allow"));
        assert!(v.contains(&"deny"));
        assert!(v.contains(&"ask"));
    }

    #[test]
    fn add_partial_effect_filters() {
        let state = make_state(&["main"], "main");
        let mut c = ShellCompleter::new(state);
        let s = c.complete("add (al", 7);
        let v = values(&s);
        assert!(v.contains(&"allow"));
        assert!(!v.contains(&"deny"));
    }

    #[test]
    fn add_effect_space_paren_suggests_domains() {
        let state = make_state(&["main"], "main");
        let mut c = ShellCompleter::new(state);
        let s = c.complete("add (allow (", 12);
        let v = values(&s);
        assert!(v.contains(&"exec"));
        assert!(v.contains(&"fs"));
        assert!(v.contains(&"net"));
        assert!(v.contains(&"tool"));
    }

    #[test]
    fn add_partial_domain_filters() {
        let state = make_state(&["main"], "main");
        let mut c = ShellCompleter::new(state);
        let s = c.complete("add (allow (ex", 14);
        let v = values(&s);
        assert!(v.contains(&"exec"));
        assert!(!v.contains(&"fs"));
    }

    #[test]
    fn exec_args_offer_patterns_and_has() {
        let state = make_state(&["main"], "main");
        let mut c = ShellCompleter::new(state);
        // After `(exec "git" ` — arg_index=1, should offer :has and patterns
        let line = "add (allow (exec \"git\" ";
        let s = c.complete(line, line.len());
        let v = values(&s);
        assert!(v.contains(&":has"), "should offer :has after binary");
        assert!(v.contains(&"*"), "should offer wildcard");
    }

    #[test]
    fn exec_no_has_after_has() {
        let state = make_state(&["main"], "main");
        let mut c = ShellCompleter::new(state);
        // After :has, should NOT offer :has again
        let line = "add (allow (exec \"git\" :has ";
        let s = c.complete(line, line.len());
        let v = values(&s);
        assert!(!v.contains(&":has"), "should not offer :has twice");
        assert!(v.contains(&"*"), "should still offer wildcard");
    }

    #[test]
    fn fs_first_arg_offers_ops() {
        let state = make_state(&["main"], "main");
        let mut c = ShellCompleter::new(state);
        let s = c.complete("add (allow (fs ", 15);
        let v = values(&s);
        assert!(v.contains(&"read"));
        assert!(v.contains(&"write"));
        assert!(v.contains(&"create"));
        assert!(v.contains(&"delete"));
        assert!(v.contains(&"*"), "should offer wildcard op");
        assert!(v.contains(&"(or "), "should offer (or for multiple ops");
    }

    #[test]
    fn fs_second_arg_offers_path_filters() {
        let state = make_state(&["main"], "main");
        let mut c = ShellCompleter::new(state);
        let s = c.complete("add (allow (fs read ", 20);
        let v = values(&s);
        assert!(v.contains(&"(subpath "), "should offer subpath");
        assert!(v.contains(&"(or "), "should offer or");
        assert!(v.contains(&"(not "), "should offer not");
    }

    #[test]
    fn subpath_offers_path_exprs() {
        let state = make_state(&["main"], "main");
        let mut c = ShellCompleter::new(state);
        let line = "add (allow (fs read (subpath ";
        let s = c.complete(line, line.len());
        let v = values(&s);
        assert!(v.contains(&"(env "), "should offer env");
        assert!(v.contains(&"(join "), "should offer join");
    }

    #[test]
    fn env_offers_common_vars() {
        let state = make_state(&["main"], "main");
        let mut c = ShellCompleter::new(state);
        let line = "add (allow (fs read (subpath (env ";
        let s = c.complete(line, line.len());
        let v = values(&s);
        assert!(v.contains(&"PWD"));
        assert!(v.contains(&"HOME"));
    }

    #[test]
    fn net_offers_patterns() {
        let state = make_state(&["main"], "main");
        let mut c = ShellCompleter::new(state);
        let s = c.complete("add (allow (net ", 16);
        let v = values(&s);
        assert!(v.contains(&"*"), "should offer wildcard");
        assert!(v.contains(&"(or "), "should offer or");
    }

    #[test]
    fn tool_offers_patterns() {
        let state = make_state(&["main"], "main");
        let mut c = ShellCompleter::new(state);
        let s = c.complete("add (allow (tool ", 17);
        let v = values(&s);
        assert!(v.contains(&"*"));
    }

    #[test]
    fn default_suggests_effects() {
        let state = make_state(&["main", "sandbox"], "main");
        let mut c = ShellCompleter::new(state);
        let s = c.complete("default ", 8);
        let v = values(&s);
        assert!(v.contains(&"allow"));
        assert!(v.contains(&"deny"));
    }

    #[test]
    fn default_effect_suggests_policies() {
        let state = make_state(&["main", "sandbox"], "main");
        let mut c = ShellCompleter::new(state);
        let s = c.complete("default deny ", 13);
        let v = values(&s);
        assert!(v.contains(&"main"));
        assert!(v.contains(&"sandbox"));
    }

    #[test]
    fn use_suggests_policies() {
        let state = make_state(&["main", "sandbox"], "main");
        let mut c = ShellCompleter::new(state);
        let s = c.complete("use ", 4);
        let v = values(&s);
        assert!(v.contains(&"main"));
        assert!(v.contains(&"sandbox"));
    }

    #[test]
    fn test_suggests_tools() {
        let state = make_state(&["main"], "main");
        let mut c = ShellCompleter::new(state);
        let s = c.complete("test ", 5);
        let v = values(&s);
        assert!(v.contains(&"bash"));
        assert!(v.contains(&"Bash"));
        assert!(v.contains(&"WebFetch"));
    }

    #[test]
    fn help_suggests_commands() {
        let state = make_state(&["main"], "main");
        let mut c = ShellCompleter::new(state);
        let s = c.complete("help a", 6);
        let v = values(&s);
        assert!(v.contains(&"add"));
        assert!(v.contains(&"abort"));
        assert!(v.contains(&"apply"));
    }

    #[test]
    fn policy_prefix_then_paren() {
        let state = make_state(&["main", "sandbox"], "main");
        let mut c = ShellCompleter::new(state);
        // `add sandbox (` → should offer effects
        let s = c.complete("add sandbox (", 13);
        let v = values(&s);
        assert!(v.contains(&"allow"));
        assert!(v.contains(&"deny"));
    }

    #[test]
    fn closed_rule_offers_sandbox_keyword() {
        let state = make_state(&["main"], "main");
        let mut c = ShellCompleter::new(state);
        let line = "add (allow (exec \"git\" *)) :";
        let s = c.complete(line, line.len());
        let v = values(&s);
        assert!(
            v.contains(&":sandbox"),
            "should offer :sandbox after closed rule"
        );
    }

    #[test]
    fn fs_partial_op_filters() {
        let state = make_state(&["main"], "main");
        let mut c = ShellCompleter::new(state);
        let s = c.complete("add (allow (fs re", 17);
        let v = values(&s);
        assert!(v.contains(&"read"));
        assert!(!v.contains(&"write"));
    }
}
