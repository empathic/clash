//! Builder view — an example-driven workflow for building policy rules.
//!
//! Users type example tool invocations, tag them with desired outcomes,
//! and see evaluation results and suggested policy mutations live.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use super::tea::{Action, Component};
use crate::policy::match_tree::{CompiledPolicy, Decision, Node, PolicyManifest};
use crate::policy::{Effect, manifest_edit};

/// A single example line entered by the user.
struct Example {
    raw: String,
    parsed: Option<ParsedExample>,
    desired: Option<Effect>,
}

/// Successfully parsed example invocation.
struct ParsedExample {
    tool_name: String,
    tool_input: serde_json::Value,
}

/// Result of evaluating one example against the current policy.
#[allow(dead_code)]
struct TestResult {
    actual: Effect,
    desired: Effect,
    passed: bool,
    matched_rule: Option<String>,
    /// Index path through the tree to the matching node (for highlighting).
    match_path: Option<Vec<usize>>,
}

/// A suggested policy mutation for a failing example.
#[allow(dead_code)]
struct Mutation {
    node: Node,
    description: String,
    example_idx: usize,
}

/// Which pane has focus in the Builder tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderFocus {
    Examples,
    Tree,
}

/// Messages produced by the builder view.
pub enum Msg {
    /// Text was edited — re-evaluate.
    TextChanged,
    /// Accept the suggested fix for the current failing example.
    AcceptCurrentFix,
}

pub struct BuilderView {
    examples: Vec<Example>,
    results: Vec<Option<TestResult>>,
    mutations: Vec<Mutation>,
    cursor_line: usize,
    editor_cursor: usize,
    scroll_offset: usize,
    pub focus: BuilderFocus,
    /// Snapshot of the merged policy stats for display.
    inline_rule_count: usize,
    included_rule_count: usize,
    sandbox_names: Vec<String>,
}

impl BuilderView {
    pub fn new() -> Self {
        BuilderView {
            examples: vec![Example {
                raw: String::new(),
                parsed: None,
                desired: None,
            }],
            results: vec![None],
            mutations: Vec::new(),
            cursor_line: 0,
            editor_cursor: 0,
            scroll_offset: 0,
            focus: BuilderFocus::Examples,
            inline_rule_count: 0,
            included_rule_count: 0,
            sandbox_names: Vec::new(),
        }
    }

    /// Re-evaluate all examples against the current policy.
    pub fn re_evaluate(&mut self, manifest: &PolicyManifest, included: &CompiledPolicy) {
        // Build a merged policy for evaluation: inline rules first, then included.
        let mut merged = manifest.policy.clone();
        merged.tree.extend(included.tree.clone());
        for (k, v) in &included.sandboxes {
            merged
                .sandboxes
                .entry(k.clone())
                .or_insert_with(|| v.clone());
        }

        // Track policy stats for display
        self.inline_rule_count = count_rules(&manifest.policy.tree);
        self.included_rule_count = count_rules(&included.tree);
        self.sandbox_names = merged.sandboxes.keys().cloned().collect();
        self.sandbox_names.sort();

        self.results.clear();
        self.mutations.clear();

        for (idx, example) in self.examples.iter_mut().enumerate() {
            // Re-parse the raw line
            let (parsed, desired) = parse_example_line(&example.raw);
            example.parsed = parsed;
            example.desired = desired;

            let result = match (&example.parsed, &example.desired) {
                (Some(parsed), Some(desired)) => {
                    let decision = merged.evaluate(&parsed.tool_name, &parsed.tool_input);
                    let actual = decision.effect;
                    let passed = actual == *desired;
                    let matched_rule = decision
                        .trace
                        .matched_rules
                        .first()
                        .map(|m| m.description.clone());
                    let match_path =
                        merged.find_match_path(&parsed.tool_name, &parsed.tool_input);
                    Some(TestResult {
                        actual,
                        desired: *desired,
                        passed,
                        matched_rule,
                        match_path,
                    })
                }
                _ => None,
            };

            // Generate mutation for failing examples
            if let Some(ref res) = result {
                if !res.passed {
                    if let (Some(parsed), Some(desired)) = (&example.parsed, &example.desired) {
                        if let Some(mutation) = build_mutation(parsed, *desired, idx) {
                            self.mutations.push(mutation);
                        }
                    }
                }
            }

            self.results.push(result);
        }

    }
}

impl Component for BuilderView {
    type Msg = Msg;

    fn handle_key(&self, key: KeyEvent) -> Option<Msg> {
        // This is only called for keys that pass through handle_key_direct.
        // From examples pane, Ctrl-a applies the fix for the current line.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('a') {
            return Some(Msg::AcceptCurrentFix);
        }
        None
    }

    fn update(&mut self, msg: Msg, manifest: &mut PolicyManifest) -> Action {
        match msg {
            Msg::TextChanged => Action::None,
            Msg::AcceptCurrentFix => {
                // Find the mutation for the current cursor line
                if let Some(mutation) = self
                    .mutations
                    .iter()
                    .find(|m| m.example_idx == self.cursor_line)
                {
                    manifest_edit::upsert_rule(manifest, mutation.node.clone());
                    Action::Modified
                } else {
                    Action::Flash("No fix available for this line".into())
                }
            }
        }
    }

    fn view(&self, frame: &mut Frame, area: Rect, _manifest: &PolicyManifest) {
        // BuilderView renders only the examples pane.
        // The tree pane is rendered by App directly using TreeView.
        self.render_examples_pane(frame, area);
    }
}

impl BuilderView {
    /// Get the match path for the example at the current cursor line.
    ///
    /// Returns the tree index path to the matching node, used to highlight
    /// the matched rule in the tree view. The path uses inline tree indices;
    /// for included rules, the root index is offset by the inline tree length.
    pub fn current_match_path(&self, inline_len: usize) -> Option<Vec<usize>> {
        let result = self.results.get(self.cursor_line)?.as_ref()?;
        let path = result.match_path.as_ref()?;
        if path.is_empty() {
            return None;
        }
        // The match_path is relative to the merged tree (inline ++ included).
        // If root index >= inline_len, it's an included rule — offset for tree view.
        let root = path[0];
        if root >= inline_len {
            let mut adjusted = path.clone();
            adjusted[0] = 10000 + (root - inline_len);
            Some(adjusted)
        } else {
            Some(path.clone())
        }
    }

    /// Handle a key event directly (called from App for mutable access).
    /// Returns `true` if the key was consumed, `false` to pass through.
    pub fn handle_key_direct(&mut self, key: KeyEvent) -> bool {
        match self.focus {
            BuilderFocus::Examples => self.handle_examples_key(key),
            BuilderFocus::Tree => false, // Tree keys are handled by App via TreeView
        }
    }

    fn handle_examples_key(&mut self, key: KeyEvent) -> bool {
        // Let Esc through for quit
        if key.code == KeyCode::Esc {
            return false;
        }
        // Let all Ctrl-key combos through (Ctrl-s for save, etc.)
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            return false;
        }
        // Let Alt-key combos through
        if key.modifiers.contains(KeyModifiers::ALT) {
            return false;
        }
        // BackTab (Shift-Tab) switches to previous global tab
        if key.code == KeyCode::BackTab {
            return false;
        }

        match key.code {
            KeyCode::Char(c) => {
                if let Some(example) = self.examples.get_mut(self.cursor_line) {
                    let byte_pos = char_to_byte_pos(&example.raw, self.editor_cursor);
                    example.raw.insert(byte_pos, c);
                    self.editor_cursor += 1;
                }
                true
            }
            KeyCode::Backspace => {
                if let Some(example) = self.examples.get_mut(self.cursor_line) {
                    if self.editor_cursor > 0 {
                        self.editor_cursor -= 1;
                        let byte_pos = char_to_byte_pos(&example.raw, self.editor_cursor);
                        example.raw.remove(byte_pos);
                    } else if self.cursor_line > 0 {
                        // Merge with previous line
                        let current = self.examples.remove(self.cursor_line);
                        self.results.pop();
                        self.cursor_line -= 1;
                        if let Some(prev) = self.examples.get_mut(self.cursor_line) {
                            self.editor_cursor = prev.raw.chars().count();
                            prev.raw.push_str(&current.raw);
                        }
                    }
                }
                true
            }
            KeyCode::Delete => {
                if let Some(example) = self.examples.get_mut(self.cursor_line) {
                    let char_len = example.raw.chars().count();
                    if self.editor_cursor < char_len {
                        let byte_pos = char_to_byte_pos(&example.raw, self.editor_cursor);
                        example.raw.remove(byte_pos);
                    }
                }
                true
            }
            KeyCode::Enter => {
                // Split line at cursor or add new line
                let rest = if let Some(example) = self.examples.get_mut(self.cursor_line) {
                    let byte_pos = char_to_byte_pos(&example.raw, self.editor_cursor);
                    let rest = example.raw[byte_pos..].to_string();
                    example.raw.truncate(byte_pos);
                    rest
                } else {
                    String::new()
                };
                self.cursor_line += 1;
                self.examples.insert(
                    self.cursor_line,
                    Example {
                        raw: rest,
                        parsed: None,
                        desired: None,
                    },
                );
                self.results.push(None);
                self.editor_cursor = 0;
                true
            }
            KeyCode::Left => {
                if self.editor_cursor > 0 {
                    self.editor_cursor -= 1;
                }
                true
            }
            KeyCode::Right => {
                if let Some(example) = self.examples.get(self.cursor_line) {
                    let char_len = example.raw.chars().count();
                    if self.editor_cursor < char_len {
                        self.editor_cursor += 1;
                    }
                }
                true
            }
            KeyCode::Up => {
                if self.cursor_line > 0 {
                    self.cursor_line -= 1;
                    // Clamp editor cursor to new line length
                    if let Some(example) = self.examples.get(self.cursor_line) {
                        let char_len = example.raw.chars().count();
                        if self.editor_cursor > char_len {
                            self.editor_cursor = char_len;
                        }
                    }
                }
                true
            }
            KeyCode::Down => {
                if self.cursor_line + 1 < self.examples.len() {
                    self.cursor_line += 1;
                    if let Some(example) = self.examples.get(self.cursor_line) {
                        let char_len = example.raw.chars().count();
                        if self.editor_cursor > char_len {
                            self.editor_cursor = char_len;
                        }
                    }
                }
                true
            }
            KeyCode::Home => {
                self.editor_cursor = 0;
                true
            }
            KeyCode::End => {
                if let Some(example) = self.examples.get(self.cursor_line) {
                    self.editor_cursor = example.raw.chars().count();
                }
                true
            }
            KeyCode::Tab => {
                self.focus = BuilderFocus::Tree;
                true
            }
            KeyCode::Esc => false, // let app handle quit
            _ => true,
        }
    }

    fn render_examples_pane(&self, frame: &mut Frame, area: Rect) {
        let is_focused = self.focus == BuilderFocus::Examples;
        let border_style = if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        // Build title with policy summary
        let total_rules = self.inline_rule_count + self.included_rule_count;
        let title = if total_rules > 0 {
            let mut parts = Vec::new();
            if self.inline_rule_count > 0 {
                parts.push(format!("{} inline", self.inline_rule_count));
            }
            if self.included_rule_count > 0 {
                parts.push(format!("{} included", self.included_rule_count));
            }
            let sandbox_str = if self.sandbox_names.is_empty() {
                String::new()
            } else {
                format!(" | sbx: {}", self.sandbox_names.join(", "))
            };
            format!(
                " Examples — {} rules ({}){sandbox_str} ",
                total_rules,
                parts.join(", ")
            )
        } else {
            " Examples ".to_string()
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(title);

        let inner = block.inner(area);
        frame.render_widget(block, area);

        let visible_height = inner.height as usize;
        // Reserve 1 line for summary at bottom
        let examples_height = visible_height.saturating_sub(1);

        // Adjust scroll
        let scroll = if self.cursor_line < self.scroll_offset {
            self.cursor_line
        } else if self.cursor_line >= self.scroll_offset + examples_height {
            self.cursor_line - examples_height + 1
        } else {
            self.scroll_offset
        };

        let lines: Vec<Line> = self
            .examples
            .iter()
            .enumerate()
            .skip(scroll)
            .take(examples_height)
            .map(|(i, example)| {
                let is_current = i == self.cursor_line && is_focused;
                let result = self.results.get(i).and_then(|r| r.as_ref());

                if is_current {
                    // Active line: show text with cursor, result indicator at end
                    let raw = &example.raw;
                    let chars: Vec<char> = raw.chars().collect();
                    let before: String = chars[..self.editor_cursor].iter().collect();
                    let cursor_char = chars.get(self.editor_cursor).copied().unwrap_or(' ');
                    let after: String = if self.editor_cursor < chars.len() {
                        chars[self.editor_cursor + 1..].iter().collect()
                    } else {
                        String::new()
                    };

                    let bg = Color::DarkGray;
                    let mut spans = vec![
                        Span::styled(
                            format!("  {before}"),
                            Style::default().bg(bg).fg(Color::White),
                        ),
                        Span::styled(
                            cursor_char.to_string(),
                            Style::default().bg(Color::White).fg(Color::Black),
                        ),
                        Span::styled(after, Style::default().bg(bg).fg(Color::White)),
                    ];

                    // Inline result indicator
                    if let Some(res) = result {
                        let trace = res
                            .matched_rule
                            .as_deref()
                            .map(|r| format!(" via {r}"))
                            .unwrap_or_else(|| " (no rule matched)".into());
                        if res.passed {
                            spans.push(Span::styled(
                                format!("  \u{2713} {}{trace}", effect_label(res.actual)),
                                Style::default().bg(bg).fg(Color::Green),
                            ));
                        } else {
                            spans.push(Span::styled(
                                format!(
                                    "  \u{2717} got {}{trace}",
                                    effect_label(res.actual),
                                ),
                                Style::default().bg(bg).fg(Color::Red),
                            ));
                        }
                    }

                    return Line::from(spans);
                }

                // Non-active lines
                if example.raw.is_empty() {
                    return Line::from(Span::styled(
                        "  type: bash git status -> allow",
                        Style::default().fg(Color::DarkGray),
                    ));
                }

                // Show example text with inline result
                let mut spans = Vec::new();
                match result {
                    Some(res) if res.passed => {
                        spans.push(Span::styled(
                            format!("  \u{2713} {}", example.raw),
                            Style::default().fg(Color::Green),
                        ));
                        if let Some(ref rule) = res.matched_rule {
                            spans.push(Span::styled(
                                format!("  ({rule})"),
                                Style::default().fg(Color::DarkGray),
                            ));
                        }
                    }
                    Some(res) => {
                        spans.push(Span::styled(
                            format!("  \u{2717} {}", example.raw),
                            Style::default().fg(Color::Red),
                        ));
                        let trace = res
                            .matched_rule
                            .as_deref()
                            .map(|r| format!(" via {r}"))
                            .unwrap_or_else(|| " (no rule matched)".into());
                        spans.push(Span::styled(
                            format!("  got {}{trace}", effect_label(res.actual)),
                            Style::default()
                                .fg(Color::Red)
                                .add_modifier(Modifier::DIM),
                        ));
                    }
                    None => {
                        // Unparseable or incomplete
                        spans.push(Span::styled(
                            format!("  ? {}", example.raw),
                            Style::default().fg(Color::Yellow),
                        ));
                    }
                }

                Line::from(spans)
            })
            .collect();

        // Summary line at bottom
        let (total_all, passing_all) = self.results.iter().fold((0, 0), |(t, p), r| match r {
            Some(res) => (t + 1, if res.passed { p + 1 } else { p }),
            None => (t, p),
        });

        let mut all_lines = lines;
        // Pad to push summary to bottom
        while all_lines.len() < examples_height {
            all_lines.push(Line::from(""));
        }
        if total_all > 0 {
            let summary_style = if passing_all == total_all {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            };
            all_lines.push(Line::from(Span::styled(
                format!("  {passing_all}/{total_all} passing"),
                summary_style,
            )));
        } else {
            all_lines.push(Line::from(""));
        }

        let para = Paragraph::new(all_lines);
        frame.render_widget(para, inner);
    }

}

// ── Parsing ──────────────────────────────────────────────────────────

/// Parse an example line like "bash git push -> deny" into (ParsedExample, Effect).
fn parse_example_line(raw: &str) -> (Option<ParsedExample>, Option<Effect>) {
    let raw = raw.trim();
    if raw.is_empty() {
        return (None, None);
    }

    // Split on " -> " or " → "
    let (invocation, effect_str) = if let Some(pos) = raw.find(" -> ") {
        (&raw[..pos], &raw[pos + 4..])
    } else if let Some(pos) = raw.find(" → ") {
        let arrow_len = "→".len() + 2; // space + utf8 arrow + space
        (&raw[..pos], &raw[pos + arrow_len..])
    } else {
        return (None, None);
    };

    let effect = match effect_str.trim().to_lowercase().as_str() {
        "allow" => Some(Effect::Allow),
        "deny" => Some(Effect::Deny),
        "ask" => Some(Effect::Ask),
        _ => None,
    };

    let effect = match effect {
        Some(e) => e,
        None => return (None, None),
    };

    let parsed = parse_invocation(invocation.trim());
    (parsed, Some(effect))
}

/// Parse an invocation string into a tool name + tool input.
fn parse_invocation(invocation: &str) -> Option<ParsedExample> {
    if invocation.is_empty() {
        return None;
    }

    let lower = invocation.to_lowercase();

    // "bash <command>" — Bash tool
    if lower.starts_with("bash ") {
        let command = invocation[5..].trim();
        return Some(ParsedExample {
            tool_name: "Bash".to_string(),
            tool_input: serde_json::json!({"command": command}),
        });
    }

    // Split on first space
    let (tool, rest) = match invocation.find(' ') {
        Some(pos) => (&invocation[..pos], invocation[pos + 1..].trim()),
        None => (invocation, ""),
    };

    // Normalize tool name (capitalize first letter)
    let tool_name = normalize_tool_name(tool)?;

    let tool_input = match tool_name.as_str() {
        "Read" | "Write" | "Edit" => serde_json::json!({"file_path": rest}),
        "Glob" => serde_json::json!({"pattern": rest}),
        "Grep" => serde_json::json!({"pattern": rest}),
        "WebFetch" => serde_json::json!({"url": rest}),
        "WebSearch" => serde_json::json!({"query": rest}),
        _ => serde_json::json!({}),
    };

    Some(ParsedExample {
        tool_name,
        tool_input,
    })
}

/// Normalize a tool name: known tools get their canonical capitalization.
fn normalize_tool_name(name: &str) -> Option<String> {
    let lower = name.to_lowercase();
    match lower.as_str() {
        "bash" => Some("Bash".to_string()),
        "read" => Some("Read".to_string()),
        "write" => Some("Write".to_string()),
        "edit" => Some("Edit".to_string()),
        "glob" => Some("Glob".to_string()),
        "grep" => Some("Grep".to_string()),
        "webfetch" => Some("WebFetch".to_string()),
        "websearch" => Some("WebSearch".to_string()),
        "agent" => Some("Agent".to_string()),
        "skill" => Some("Skill".to_string()),
        _ => Some(name.to_string()), // pass through unknown tools as-is
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Count leaf decision rules in a tree.
fn count_rules(tree: &[Node]) -> usize {
    tree.iter()
        .map(|n| match n {
            Node::Decision(_) => 1,
            Node::Condition { children, .. } => count_rules(children),
        })
        .sum()
}

// ── Mutation generation ──────────────────────────────────────────────

/// Build a mutation node for a failing example.
fn build_mutation(parsed: &ParsedExample, desired: Effect, example_idx: usize) -> Option<Mutation> {
    let decision = effect_to_decision(desired);

    if parsed.tool_name == "Bash" {
        // Extract command and split into binary + args
        let command = parsed.tool_input.get("command")?.as_str()?;
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.is_empty() {
            return None;
        }
        let bin = parts[0];
        let args: Vec<&str> = parts[1..].to_vec();
        let node = manifest_edit::build_exec_rule(bin, &args, decision);
        let desc = if args.is_empty() {
            format!("exe(\"{bin}\") -> {}", effect_label(desired))
        } else {
            format!(
                "exe(\"{bin}\", {}) -> {}",
                args.iter()
                    .map(|a| format!("\"{a}\""))
                    .collect::<Vec<_>>()
                    .join(", "),
                effect_label(desired)
            )
        };
        Some(Mutation {
            node,
            description: desc,
            example_idx,
        })
    } else {
        let node = manifest_edit::build_tool_rule(&parsed.tool_name, decision);
        let desc = format!(
            "tool(\"{}\") -> {}",
            parsed.tool_name,
            effect_label(desired)
        );
        Some(Mutation {
            node,
            description: desc,
            example_idx,
        })
    }
}

fn effect_to_decision(effect: Effect) -> Decision {
    match effect {
        Effect::Allow => Decision::Allow(None),
        Effect::Deny => Decision::Deny,
        Effect::Ask => Decision::Ask(None),
    }
}

fn effect_label(effect: Effect) -> &'static str {
    match effect {
        Effect::Allow => "allow",
        Effect::Deny => "deny",
        Effect::Ask => "ask",
    }
}

/// Convert a char index to a byte position in a string.
fn char_to_byte_pos(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(byte_pos, _)| byte_pos)
        .unwrap_or(s.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::match_tree::*;
    use std::collections::HashMap;

    fn empty_manifest() -> PolicyManifest {
        PolicyManifest {
            includes: vec![],
            policy: CompiledPolicy {
                sandboxes: HashMap::new(),
                tree: vec![],
                default_effect: Effect::Deny,
                default_sandbox: None,
            },
        }
    }

    fn empty_included() -> CompiledPolicy {
        CompiledPolicy {
            sandboxes: HashMap::new(),
            tree: vec![],
            default_effect: Effect::Deny,
            default_sandbox: None,
        }
    }

    #[test]
    fn parse_bash_allow() {
        let (parsed, effect) = parse_example_line("bash git status -> allow");
        let parsed = parsed.unwrap();
        assert_eq!(parsed.tool_name, "Bash");
        assert_eq!(parsed.tool_input["command"], "git status");
        assert_eq!(effect, Some(Effect::Allow));
    }

    #[test]
    fn parse_bash_deny() {
        let (parsed, effect) = parse_example_line("bash git push -> deny");
        let parsed = parsed.unwrap();
        assert_eq!(parsed.tool_name, "Bash");
        assert_eq!(parsed.tool_input["command"], "git push");
        assert_eq!(effect, Some(Effect::Deny));
    }

    #[test]
    fn parse_read_tool() {
        let (parsed, effect) = parse_example_line("Read /etc/passwd -> deny");
        let parsed = parsed.unwrap();
        assert_eq!(parsed.tool_name, "Read");
        assert_eq!(parsed.tool_input["file_path"], "/etc/passwd");
        assert_eq!(effect, Some(Effect::Deny));
    }

    #[test]
    fn parse_unicode_arrow() {
        let (parsed, effect) = parse_example_line("bash ls → allow");
        let parsed = parsed.unwrap();
        assert_eq!(parsed.tool_name, "Bash");
        assert_eq!(parsed.tool_input["command"], "ls");
        assert_eq!(effect, Some(Effect::Allow));
    }

    #[test]
    fn parse_empty_line() {
        let (parsed, effect) = parse_example_line("");
        assert!(parsed.is_none());
        assert!(effect.is_none());
    }

    #[test]
    fn parse_no_arrow() {
        let (parsed, effect) = parse_example_line("bash git status");
        assert!(parsed.is_none());
        assert!(effect.is_none());
    }

    #[test]
    fn parse_bad_effect() {
        let (parsed, effect) = parse_example_line("bash git status -> unknown");
        assert!(parsed.is_none());
        assert!(effect.is_none());
    }

    #[test]
    fn parse_case_insensitive_tool() {
        let (parsed, _) = parse_example_line("read /tmp/foo -> allow");
        let parsed = parsed.unwrap();
        assert_eq!(parsed.tool_name, "Read");
    }

    #[test]
    fn parse_webfetch() {
        let (parsed, effect) = parse_example_line("WebFetch https://example.com -> allow");
        let parsed = parsed.unwrap();
        assert_eq!(parsed.tool_name, "WebFetch");
        assert_eq!(parsed.tool_input["url"], "https://example.com");
        assert_eq!(effect, Some(Effect::Allow));
    }

    #[test]
    fn evaluate_example_default_deny() {
        let manifest = empty_manifest();
        let included = empty_included();
        let mut view = BuilderView::new();
        view.examples[0].raw = "bash git status -> allow".to_string();
        view.re_evaluate(&manifest, &included);

        // Default policy is deny, so "want allow" should fail
        assert_eq!(view.results.len(), 1);
        let result = view.results[0].as_ref().unwrap();
        assert!(!result.passed);
        assert_eq!(result.actual, Effect::Deny);
        assert_eq!(result.desired, Effect::Allow);
        assert_eq!(view.mutations.len(), 1);
    }

    #[test]
    fn evaluate_example_matching_deny() {
        let manifest = empty_manifest();
        let included = empty_included();
        let mut view = BuilderView::new();
        view.examples[0].raw = "bash git status -> deny".to_string();
        view.re_evaluate(&manifest, &included);

        // Default deny matches desired deny -> pass
        let result = view.results[0].as_ref().unwrap();
        assert!(result.passed);
        assert!(view.mutations.is_empty());
    }

    #[test]
    fn evaluate_with_included_rules() {
        let manifest = empty_manifest();
        // Included policy allows Read tool
        let mut included = empty_included();
        included
            .tree
            .push(manifest_edit::build_tool_rule("Read", Decision::Allow(None)));

        let mut view = BuilderView::new();
        view.examples[0].raw = "Read /tmp/foo -> allow".to_string();
        view.re_evaluate(&manifest, &included);

        // Included rule allows Read, desired is allow -> pass
        let result = view.results[0].as_ref().unwrap();
        assert!(result.passed);
        assert_eq!(result.actual, Effect::Allow);
        assert!(view.mutations.is_empty());
    }

    #[test]
    fn evaluate_with_included_rules_conflict() {
        let manifest = empty_manifest();
        // Included policy allows Read, but user wants deny
        let mut included = empty_included();
        included
            .tree
            .push(manifest_edit::build_tool_rule("Read", Decision::Allow(None)));

        let mut view = BuilderView::new();
        view.examples[0].raw = "Read /tmp/foo -> deny".to_string();
        view.re_evaluate(&manifest, &included);

        // Included rule allows Read, but user wants deny -> fail + mutation
        let result = view.results[0].as_ref().unwrap();
        assert!(!result.passed);
        assert_eq!(result.actual, Effect::Allow);
        assert_eq!(result.desired, Effect::Deny);
        assert_eq!(view.mutations.len(), 1);
    }

    #[test]
    fn evaluate_tracks_included_sandboxes() {
        use crate::policy::sandbox_types::{Cap, NetworkPolicy, SandboxPolicy};

        let manifest = empty_manifest();
        let mut included = empty_included();
        included.sandboxes.insert(
            "dev".to_string(),
            SandboxPolicy {
                default: Cap::READ | Cap::EXECUTE,
                rules: vec![],
                network: NetworkPolicy::default(),
                doc: None,
            },
        );

        let mut view = BuilderView::new();
        view.re_evaluate(&manifest, &included);

        assert_eq!(view.sandbox_names, vec!["dev"]);
        assert_eq!(view.included_rule_count, 0);
    }

    #[test]
    fn evaluate_tracks_rule_counts() {
        let mut manifest = empty_manifest();
        manifest_edit::upsert_rule(
            &mut manifest,
            manifest_edit::build_tool_rule("Write", Decision::Deny),
        );

        let mut included = empty_included();
        included
            .tree
            .push(manifest_edit::build_tool_rule("Read", Decision::Allow(None)));
        included
            .tree
            .push(manifest_edit::build_exec_rule("git", &[], Decision::Allow(None)));

        let mut view = BuilderView::new();
        view.re_evaluate(&manifest, &included);

        assert_eq!(view.inline_rule_count, 1);
        assert_eq!(view.included_rule_count, 2);
    }

    #[test]
    fn mutation_for_bash_command() {
        let parsed = ParsedExample {
            tool_name: "Bash".to_string(),
            tool_input: serde_json::json!({"command": "git push"}),
        };
        let mutation = build_mutation(&parsed, Effect::Deny, 0).unwrap();
        assert!(mutation.description.contains("git"));
        assert!(mutation.description.contains("push"));
        assert!(mutation.description.contains("deny"));
    }

    #[test]
    fn mutation_for_tool() {
        let parsed = ParsedExample {
            tool_name: "Read".to_string(),
            tool_input: serde_json::json!({"file_path": "/etc/passwd"}),
        };
        let mutation = build_mutation(&parsed, Effect::Deny, 0).unwrap();
        assert!(mutation.description.contains("Read"));
        assert!(mutation.description.contains("deny"));
    }

    #[test]
    fn accept_current_fix_modifies_manifest() {
        let mut manifest = empty_manifest();
        let included = empty_included();
        let mut view = BuilderView::new();
        view.examples[0].raw = "bash git status -> allow".to_string();
        view.re_evaluate(&manifest, &included);

        assert!(!view.mutations.is_empty());
        // cursor_line is 0, which matches the failing example
        let action = view.update(Msg::AcceptCurrentFix, &mut manifest);
        assert!(matches!(action, Action::Modified));
        assert!(!manifest.policy.tree.is_empty());
    }

    #[test]
    fn accept_current_fix_no_mutation_flashes() {
        let mut manifest = empty_manifest();
        let included = empty_included();
        let mut view = BuilderView::new();
        view.examples[0].raw = "bash git status -> deny".to_string();
        view.re_evaluate(&manifest, &included);

        // This example passes (default deny matches), no mutation available
        assert!(view.mutations.is_empty());
        let action = view.update(Msg::AcceptCurrentFix, &mut manifest);
        assert!(matches!(action, Action::Flash(_)));
    }
}
