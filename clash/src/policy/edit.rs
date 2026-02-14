//! Comment-preserving editing for policy files (s-expr format).
//!
//! These functions operate on raw text via string-level operations,
//! avoiding parse roundtrips that would strip comments. After each edit, the
//! modified text is re-parsed to verify correctness.

use anyhow::{Result, bail};

use super::ast::{MatchExpr, Pattern};
use super::parse;

/// CLI-provided inline constraints to attach below a rule.
#[derive(Debug, Default)]
pub struct InlineConstraintArgs {
    /// Filesystem constraints: `"caps:filter_expr"` pairs.
    /// e.g. `"full:subpath(~/Library/Caches)"`, `"read+write:subpath(.)"`.
    pub fs: Vec<String>,
    /// URL domain patterns: `"github.com"` (require), `"!evil.com"` (forbid).
    pub url: Vec<String>,
    /// Argument constraints: `"--dry-run"` (require), `"!-delete"` (forbid).
    pub args: Vec<String>,
    /// Allow piping (stdin/stdout redirection between commands).
    pub pipe: Option<bool>,
    /// Allow shell redirects (>, >>, <).
    pub redirect: Option<bool>,
    /// Network policy: "allow" or "deny".
    pub network: Option<String>,
}

impl InlineConstraintArgs {
    /// Returns true if there are no constraints to emit.
    pub fn is_empty(&self) -> bool {
        self.fs.is_empty()
            && self.url.is_empty()
            && self.args.is_empty()
            && self.pipe.is_none()
            && self.network.is_none()
            && self.redirect.is_none()
    }

    /// Validate that all `--fs` entries have the required `caps:filter` format.
    pub fn validate(&self) -> Result<()> {
        for entry in &self.fs {
            if entry.split_once(':').is_none() {
                bail!(
                    "invalid --fs value '{}': expected 'caps:filter_expr' \
                     (e.g. 'full:subpath(~/dir)', 'read+write:subpath(.)') ",
                    entry
                );
            }
        }
        Ok(())
    }
}

/// Add a rule to a profile's rules block, preserving comments.
/// Returns the modified text.
pub fn add_rule(
    text: &str,
    profile: &str,
    rule: &str,
    constraints: &InlineConstraintArgs,
) -> Result<String> {
    add_rule_sexpr(text, profile, rule, constraints)
}

/// Remove a rule from a profile's rules block, preserving comments.
/// Returns the modified text.
pub fn remove_rule(text: &str, profile: &str, rule: &str) -> Result<String> {
    remove_rule_sexpr(text, profile, rule)
}

/// Resolve the target profile: use the provided override or fall back to the active profile.
pub fn resolve_profile(text: &str, profile_override: Option<&str>) -> Result<String> {
    match profile_override {
        Some(p) => Ok(p.to_string()),
        None => active_profile_sexpr(text),
    }
}

/// Set the sandbox block on a profile, replacing any existing one.
///
/// `statements` are sandbox statement strings like `"fs full subpath(.)"` or `"network deny"`.
/// An empty slice removes the sandbox block.
pub fn set_sandbox(text: &str, profile: &str, statements: &[&str]) -> Result<String> {
    set_sandbox_sexpr(text, profile, statements)
}

/// Get summary information about the policy for the `show` command.
pub struct PolicyInfo {
    pub default_permission: String,
    pub active_profile: String,
    pub profiles: Vec<String>,
}

/// Extract policy info from the text.
pub fn policy_info(text: &str) -> Result<PolicyInfo> {
    policy_info_sexpr(text)
}

/// Set the active profile in the `(default ...)` form, preserving comments.
/// Replaces `(profile <old>)` with `(profile <new>)` inside the default form.
pub fn set_active_profile(text: &str, new_profile: &str) -> Result<String> {
    set_active_profile_sexpr(text, new_profile)
}

// ---------------------------------------------------------------------------
// S-expr editing helpers
// ---------------------------------------------------------------------------

/// Skip whitespace and `;` comments, returning the byte offset of the next
/// meaningful character (or `text.len()` if exhausted).
fn skip_sexpr_whitespace(text: &str, mut pos: usize) -> usize {
    let bytes = text.as_bytes();
    while pos < bytes.len() {
        if bytes[pos].is_ascii_whitespace() {
            pos += 1;
        } else if bytes[pos] == b';' {
            // Skip to end of line
            while pos < bytes.len() && bytes[pos] != b'\n' {
                pos += 1;
            }
        } else {
            break;
        }
    }
    pos
}

/// Starting at an opening `(`, find the matching closing `)`.
/// Returns the byte offset *after* the closing paren.
fn skip_balanced_parens(text: &str, start: usize) -> usize {
    debug_assert_eq!(text.as_bytes()[start], b'(');
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut pos = start;
    while pos < bytes.len() {
        match bytes[pos] {
            b'(' => {
                depth += 1;
                pos += 1;
            }
            b')' => {
                depth -= 1;
                pos += 1;
                if depth == 0 {
                    return pos;
                }
            }
            b';' => {
                // Skip comment to end of line
                while pos < bytes.len() && bytes[pos] != b'\n' {
                    pos += 1;
                }
            }
            b'"' => {
                // Skip quoted string
                pos += 1;
                while pos < bytes.len() {
                    if bytes[pos] == b'\\' {
                        pos += 2; // skip escape
                    } else if bytes[pos] == b'"' {
                        pos += 1;
                        break;
                    } else {
                        pos += 1;
                    }
                }
            }
            _ => {
                pos += 1;
            }
        }
    }
    pos // unbalanced — return end
}

/// Find byte range `(start, end)` of a top-level `(profile <name> ...)` form.
fn find_sexpr_profile(text: &str, name: &str) -> Result<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        pos = skip_sexpr_whitespace(text, pos);
        if pos >= bytes.len() {
            break;
        }
        if bytes[pos] != b'(' {
            // Skip non-paren content (shouldn't happen in valid s-expr)
            pos += 1;
            continue;
        }
        let form_start = pos;
        let form_end = skip_balanced_parens(text, pos);

        // Check if this is `(profile <name> ...)`
        let inner = &text[form_start + 1..form_end.saturating_sub(1)];
        let inner_trimmed = inner.trim_start();
        if let Some(rest) = inner_trimmed.strip_prefix("profile")
            && rest.starts_with(|c: char| c.is_ascii_whitespace())
        {
            let after_kw = rest.trim_start();
            // Extract the profile name (next atom)
            let pname_end = after_kw
                .find(|c: char| c.is_ascii_whitespace() || c == '(' || c == ')')
                .unwrap_or(after_kw.len());
            let pname = &after_kw[..pname_end];
            if pname == name {
                return Ok((form_start, form_end));
            }
        }
        pos = form_end;
    }
    bail!("profile '{}' not found in s-expr policy", name)
}

/// List all profile names defined in an s-expr policy.
fn profile_names_sexpr(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut names = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        pos = skip_sexpr_whitespace(text, pos);
        if pos >= bytes.len() {
            break;
        }
        if bytes[pos] != b'(' {
            pos += 1;
            continue;
        }
        let form_start = pos;
        let form_end = skip_balanced_parens(text, pos);
        let inner = &text[form_start + 1..form_end.saturating_sub(1)];
        let inner_trimmed = inner.trim_start();
        if let Some(rest) = inner_trimmed.strip_prefix("profile")
            && rest.starts_with(|c: char| c.is_ascii_whitespace())
        {
            let after_kw = rest.trim_start();
            let pname_end = after_kw
                .find(|c: char| c.is_ascii_whitespace() || c == '(' || c == ')')
                .unwrap_or(after_kw.len());
            let pname = &after_kw[..pname_end];
            if !pname.is_empty() {
                names.push(pname.to_string());
            }
        }
        pos = form_end;
    }
    names
}

/// Extract the atom value from a labeled sub-form like `(keyword atom)` within
/// the given text. Returns `None` if the sub-form is not found.
fn extract_subform_atom(text: &str, keyword: &str) -> Option<String> {
    let prefix = format!("({}", keyword);
    let idx = text.find(&prefix)?;
    let after = &text[idx + prefix.len()..];
    // Must be followed by whitespace (not another identifier char)
    if !after.starts_with(|c: char| c.is_ascii_whitespace()) {
        return None;
    }
    let after = after.trim_start();
    let end = after.find(|c: char| c.is_ascii_whitespace() || c == ')' || c == '(')?;
    let atom = &after[..end];
    if atom.is_empty() {
        None
    } else {
        Some(atom.to_string())
    }
}

/// Extract the active profile name from an s-expr `(default (permission ...) (profile ...))` form.
fn active_profile_sexpr(text: &str) -> Result<String> {
    let bytes = text.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        pos = skip_sexpr_whitespace(text, pos);
        if pos >= bytes.len() {
            break;
        }
        if bytes[pos] != b'(' {
            pos += 1;
            continue;
        }
        let form_start = pos;
        let form_end = skip_balanced_parens(text, pos);
        let inner = &text[form_start + 1..form_end.saturating_sub(1)];
        let inner_trimmed = inner.trim_start();
        if let Some(rest) = inner_trimmed.strip_prefix("default")
            && rest.starts_with(|c: char| c.is_ascii_whitespace())
            && let Some(profile) = extract_subform_atom(rest, "profile")
        {
            return Ok(profile);
        }
        pos = form_end;
    }
    bail!("no (default ...) form found in s-expr policy")
}

/// Extract policy info from s-expr text.
fn policy_info_sexpr(text: &str) -> Result<PolicyInfo> {
    let profile = active_profile_sexpr(text)?;
    let names = profile_names_sexpr(text);

    // Parse the default permission from the (default (permission ...) ...) form
    let bytes = text.as_bytes();
    let mut permission = "ask".to_string();
    let mut pos = 0;
    while pos < bytes.len() {
        pos = skip_sexpr_whitespace(text, pos);
        if pos >= bytes.len() {
            break;
        }
        if bytes[pos] != b'(' {
            pos += 1;
            continue;
        }
        let form_start = pos;
        let form_end = skip_balanced_parens(text, pos);
        let inner = &text[form_start + 1..form_end.saturating_sub(1)];
        let inner_trimmed = inner.trim_start();
        if let Some(rest) = inner_trimmed.strip_prefix("default")
            && rest.starts_with(|c: char| c.is_ascii_whitespace())
            && let Some(perm) = extract_subform_atom(rest, "permission")
        {
            permission = perm;
        }
        pos = form_end;
    }

    Ok(PolicyInfo {
        default_permission: permission,
        active_profile: profile,
        profiles: names,
    })
}

/// Set the active profile by replacing `(profile <old>)` with `(profile <new>)`
/// inside the `(default ...)` form.
fn set_active_profile_sexpr(text: &str, new_profile: &str) -> Result<String> {
    let bytes = text.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        pos = skip_sexpr_whitespace(text, pos);
        if pos >= bytes.len() {
            break;
        }
        if bytes[pos] != b'(' {
            pos += 1;
            continue;
        }
        let form_start = pos;
        let form_end = skip_balanced_parens(text, pos);
        let inner = &text[form_start + 1..form_end.saturating_sub(1)];
        let inner_trimmed = inner.trim_start();
        if let Some(rest) = inner_trimmed.strip_prefix("default")
            && rest.starts_with(|c: char| c.is_ascii_whitespace())
        {
            // Find `(profile <name>)` within this default form and replace it.
            let default_inner = &text[form_start..form_end];
            let profile_prefix = "(profile ";
            if let Some(profile_idx) = default_inner.find(profile_prefix) {
                let abs_start = form_start + profile_idx;
                // Find the closing paren of (profile <name>)
                let after_prefix = abs_start + profile_prefix.len();
                let close = text[after_prefix..]
                    .find(')')
                    .map(|i| after_prefix + i + 1)
                    .unwrap_or(form_end);

                let mut result = String::with_capacity(text.len());
                result.push_str(&text[..abs_start]);
                result.push_str(&format!("(profile {})", new_profile));
                result.push_str(&text[close..]);

                // Re-parse to validate
                parse::parse_policy(&result).map_err(|e| {
                    anyhow::anyhow!("modified s-expr failed to parse: {}. This is a bug.", e)
                })?;

                return Ok(result);
            }
        }
        pos = form_end;
    }
    bail!("no (default ...) form found in s-expr policy")
}

/// Format a rule string ("allow bash git *") as an s-expr form.
/// If constraints are provided, they're appended as nested forms.
fn format_rule_sexpr(rule: &str, constraints: &InlineConstraintArgs) -> Result<String> {
    let (effect, verb, noun) = parse::parse_new_rule_key(rule).map_err(|e| {
        let hint = e.help().map(|h| format!(" {}", h)).unwrap_or_default();
        anyhow::anyhow!("invalid rule '{}': {}.{}", rule, e, hint)
    })?;

    let effect_str = format!("{}", effect).to_lowercase();
    let noun_str = pattern_to_string(&noun);

    // Quote the noun if it contains spaces or special chars
    let noun_formatted = if noun_str.contains(' ') || noun_str.contains('"') {
        format!(
            "\"{}\"",
            noun_str.replace('\\', "\\\\").replace('"', "\\\"")
        )
    } else {
        noun_str
    };

    let mut parts = vec![format!("({} {} {}", effect_str, verb, noun_formatted)];

    // Add constraint sub-forms
    if !constraints.fs.is_empty() {
        for entry in &constraints.fs {
            if let Some((caps, filter)) = entry.split_once(':') {
                let filter_sexpr = convert_filter_to_sexpr(filter.trim());
                parts.push(format!("    (fs ({} {}))", caps.trim(), filter_sexpr));
            }
        }
    }
    if !constraints.url.is_empty() {
        // (url "github.com" (not "evil.com"))
        let items: Vec<String> = constraints
            .url
            .iter()
            .map(|u| {
                if let Some(stripped) = u.strip_prefix('!') {
                    format!("(not \"{}\")", stripped)
                } else {
                    format!("\"{}\"", u)
                }
            })
            .collect();
        parts.push(format!("    (url {})", items.join(" ")));
    }
    if !constraints.args.is_empty() {
        // (args "--dry-run" (not "-delete"))
        let items: Vec<String> = constraints
            .args
            .iter()
            .map(|a| {
                if let Some(stripped) = a.strip_prefix('!') {
                    format!("(not \"{}\")", stripped)
                } else {
                    format!("\"{}\"", a)
                }
            })
            .collect();
        parts.push(format!("    (args {})", items.join(" ")));
    }
    if let Some(v) = constraints.pipe {
        parts.push(format!("    (pipe {})", if v { "allow" } else { "deny" }));
    }
    if let Some(v) = constraints.redirect {
        parts.push(format!(
            "    (redirect {})",
            if v { "allow" } else { "deny" }
        ));
    }
    if let Some(ref v) = constraints.network {
        parts.push(format!("    (network {})", v));
    }

    if parts.len() == 1 {
        // Simple rule, single line
        Ok(format!("{})", parts[0]))
    } else {
        // Multi-line rule with constraints
        let first = parts.remove(0);
        let mut result = first;
        for p in &parts {
            result.push('\n');
            result.push_str(p);
        }
        result.push(')');
        Ok(result)
    }
}

/// Find a sub-form within a profile by keyword (e.g., "sandbox").
/// Returns byte range `(start, end)` relative to the full text, or None.
fn find_subform_in_profile(
    text: &str,
    profile_start: usize,
    profile_end: usize,
    keyword: &str,
) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    // Skip past `(profile <name>` to get to the body
    let mut pos = profile_start + 1; // skip opening `(`
    // Skip "profile" keyword
    pos = skip_sexpr_whitespace(text, pos);
    // Skip "profile"
    while pos < profile_end && !bytes[pos].is_ascii_whitespace() && bytes[pos] != b'(' {
        pos += 1;
    }
    // Skip profile name
    pos = skip_sexpr_whitespace(text, pos);
    while pos < profile_end && !bytes[pos].is_ascii_whitespace() && bytes[pos] != b'(' {
        pos += 1;
    }

    // Now scan the body for sub-forms
    while pos < profile_end - 1 {
        pos = skip_sexpr_whitespace(text, pos);
        if pos >= profile_end - 1 {
            break;
        }
        if bytes[pos] != b'(' {
            pos += 1;
            continue;
        }
        let form_start = pos;
        let form_end = skip_balanced_parens(text, pos);
        // Check if this form starts with the keyword
        let inner_start = form_start + 1;
        let ws_end = skip_sexpr_whitespace(text, inner_start);
        let kw_end = text[ws_end..]
            .find(|c: char| c.is_ascii_whitespace() || c == '(' || c == ')')
            .map(|i| ws_end + i)
            .unwrap_or(form_end);
        if &text[ws_end..kw_end] == keyword {
            return Some((form_start, form_end));
        }
        pos = form_end;
    }
    None
}

/// Check if a rule form matches the given rule string.
/// The rule string is "effect verb noun" and we check the s-expr form `(effect verb noun ...)`.
fn sexpr_form_matches_rule(text: &str, form_start: usize, form_end: usize, rule: &str) -> bool {
    let (effect, verb, noun) = match parse::parse_new_rule_key(rule) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let inner = &text[form_start + 1..form_end.saturating_sub(1)];
    let inner_trimmed = inner.trim();
    // Parse the form's tokens
    let effect_str = format!("{}", effect).to_lowercase();
    // Check if form starts with the effect
    if let Some(rest) = inner_trimmed.strip_prefix(&effect_str) {
        if !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
            return false;
        }
        let rest = rest.trim_start();
        // Check verb
        let verb_end = rest
            .find(|c: char| c.is_ascii_whitespace() || c == '(' || c == ')')
            .unwrap_or(rest.len());
        if rest[..verb_end] != verb {
            return false;
        }
        let rest = rest[verb_end..].trim_start();
        // Extract noun (may be quoted)
        let found_noun = if let Some(inner) = rest.strip_prefix('"') {
            // Quoted noun — extract until closing quote
            if let Some(end_q) = inner.find('"') {
                &inner[..end_q]
            } else {
                return false;
            }
        } else {
            // Unquoted noun — up to next whitespace or paren or end
            let end = rest
                .find(|c: char| c.is_ascii_whitespace() || c == '(' || c == ')')
                .unwrap_or(rest.len());
            &rest[..end]
        };
        found_noun == pattern_to_string(&noun)
    } else {
        false
    }
}

/// Convert a Pattern to its string representation for matching.
fn pattern_to_string(pat: &Pattern) -> String {
    match pat {
        Pattern::Match(expr) => match_expr_to_string(expr),
        Pattern::Not(expr) => format!("!{}", match_expr_to_string(expr)),
    }
}

fn match_expr_to_string(expr: &MatchExpr) -> String {
    match expr {
        MatchExpr::Any => "*".to_string(),
        MatchExpr::Exact(s) => s.clone(),
        MatchExpr::Glob(s) => s.clone(),
        MatchExpr::Typed { entity_type, name } => match name {
            Some(n) => format!("{}:{}", entity_type, n),
            None => entity_type.clone(),
        },
    }
}

/// Add a rule to an s-expr profile.
fn add_rule_sexpr(
    text: &str,
    profile: &str,
    rule: &str,
    constraints: &InlineConstraintArgs,
) -> Result<String> {
    let (profile_start, profile_end) = find_sexpr_profile(text, profile)?;

    // Check idempotency: scan existing forms in the profile
    let bytes = text.as_bytes();
    let mut pos = profile_start + 1;
    // Skip "profile" keyword and name
    pos = skip_sexpr_whitespace(text, pos);
    while pos < profile_end && !bytes[pos].is_ascii_whitespace() && bytes[pos] != b'(' {
        pos += 1;
    }
    pos = skip_sexpr_whitespace(text, pos);
    while pos < profile_end && !bytes[pos].is_ascii_whitespace() && bytes[pos] != b'(' {
        pos += 1;
    }

    while pos < profile_end - 1 {
        pos = skip_sexpr_whitespace(text, pos);
        if pos >= profile_end - 1 {
            break;
        }
        if bytes[pos] != b'(' {
            pos += 1;
            continue;
        }
        let form_start = pos;
        let form_end = skip_balanced_parens(text, pos);
        if sexpr_form_matches_rule(text, form_start, form_end, rule) {
            // Rule already exists — idempotent
            return Ok(text.to_string());
        }
        pos = form_end;
    }

    // Format the new rule
    let new_form = format_rule_sexpr(rule, constraints)?;

    // Determine indentation from the profile body
    let indent = detect_profile_indent(text, profile_start, profile_end);

    // Insert before the closing `)` of the profile
    let close_paren = profile_end - 1;
    // Find the position just before the close paren, preserving whitespace
    let indented_form = indent_form(&new_form, &indent);

    let mut result = String::with_capacity(text.len() + indented_form.len() + 2);
    result.push_str(&text[..close_paren]);
    // Ensure there's a newline before the new form
    if !result.ends_with('\n') {
        result.push('\n');
    }
    result.push_str(&indented_form);
    result.push('\n');
    // Re-add the closing paren with proper indentation (same as profile opening)
    result.push(')');
    result.push_str(&text[profile_end..]);

    // Re-parse to validate
    parse::parse_policy(&result)
        .map_err(|e| anyhow::anyhow!("modified s-expr failed to parse: {}. This is a bug.", e))?;

    Ok(result)
}

/// Remove a rule from an s-expr profile.
fn remove_rule_sexpr(text: &str, profile: &str, rule: &str) -> Result<String> {
    let (profile_start, profile_end) = find_sexpr_profile(text, profile)?;

    let bytes = text.as_bytes();
    let mut pos = profile_start + 1;
    // Skip "profile" keyword and name
    pos = skip_sexpr_whitespace(text, pos);
    while pos < profile_end && !bytes[pos].is_ascii_whitespace() && bytes[pos] != b'(' {
        pos += 1;
    }
    pos = skip_sexpr_whitespace(text, pos);
    while pos < profile_end && !bytes[pos].is_ascii_whitespace() && bytes[pos] != b'(' {
        pos += 1;
    }

    while pos < profile_end - 1 {
        pos = skip_sexpr_whitespace(text, pos);
        if pos >= profile_end - 1 {
            break;
        }
        if bytes[pos] != b'(' {
            pos += 1;
            continue;
        }
        let form_start = pos;
        let form_end = skip_balanced_parens(text, pos);
        if sexpr_form_matches_rule(text, form_start, form_end, rule) {
            // Remove this form, including any preceding whitespace on its line
            let remove_start = line_start_of(text, form_start);
            // Also consume the trailing newline if present
            let remove_end = if form_end < text.len() && bytes[form_end] == b'\n' {
                form_end + 1
            } else {
                form_end
            };

            let mut result = String::with_capacity(text.len());
            result.push_str(&text[..remove_start]);
            result.push_str(&text[remove_end..]);

            // Re-parse to validate
            parse::parse_policy(&result).map_err(|e| {
                anyhow::anyhow!("modified s-expr failed to parse: {}. This is a bug.", e)
            })?;

            return Ok(result);
        }
        pos = form_end;
    }

    bail!("rule '{}' not found in profile '{}'", rule, profile)
}

/// Set/replace the sandbox block in an s-expr profile.
fn set_sandbox_sexpr(text: &str, profile: &str, statements: &[&str]) -> Result<String> {
    let (profile_start, profile_end) = find_sexpr_profile(text, profile)?;

    // Find existing sandbox form
    let existing = find_subform_in_profile(text, profile_start, profile_end, "sandbox");

    let indent = detect_profile_indent(text, profile_start, profile_end);

    if let Some((sb_start, sb_end)) = existing {
        if statements.is_empty() {
            // Remove the sandbox block
            let remove_start = line_start_of(text, sb_start);
            let remove_end = if sb_end < text.len() && text.as_bytes()[sb_end] == b'\n' {
                sb_end + 1
            } else {
                sb_end
            };
            let mut result = String::with_capacity(text.len());
            result.push_str(&text[..remove_start]);
            result.push_str(&text[remove_end..]);

            parse::parse_policy(&result).map_err(|e| {
                anyhow::anyhow!("modified s-expr failed to parse: {}. This is a bug.", e)
            })?;

            return Ok(result);
        }
        // Replace existing sandbox block
        let new_sandbox = format_sandbox_sexpr(statements, &indent);
        let replace_start = line_start_of(text, sb_start);
        let replace_end = if sb_end < text.len() && text.as_bytes()[sb_end] == b'\n' {
            sb_end + 1
        } else {
            sb_end
        };
        let mut result = String::with_capacity(text.len());
        result.push_str(&text[..replace_start]);
        result.push_str(&new_sandbox);
        if !new_sandbox.ends_with('\n') {
            result.push('\n');
        }
        result.push_str(&text[replace_end..]);

        parse::parse_policy(&result).map_err(|e| {
            anyhow::anyhow!("modified s-expr failed to parse: {}. This is a bug.", e)
        })?;

        return Ok(result);
    }

    if statements.is_empty() {
        return Ok(text.to_string());
    }

    // Insert new sandbox block before the closing `)` of the profile
    let new_sandbox = format_sandbox_sexpr(statements, &indent);
    let close_paren = profile_end - 1;

    let mut result = String::with_capacity(text.len() + new_sandbox.len() + 2);
    result.push_str(&text[..close_paren]);
    if !result.ends_with('\n') {
        result.push('\n');
    }
    result.push_str(&new_sandbox);
    if !new_sandbox.ends_with('\n') {
        result.push('\n');
    }
    result.push(')');
    result.push_str(&text[profile_end..]);

    parse::parse_policy(&result)
        .map_err(|e| anyhow::anyhow!("modified s-expr failed to parse: {}. This is a bug.", e))?;

    Ok(result)
}

/// Format sandbox statements as an s-expr `(sandbox ...)` form.
///
/// Statements come from the CLI in compact format like `"fs full subpath(.)"` or
/// `"network deny"`. This converts them to proper s-expr:
/// - `"fs full subpath(.)"` → `(fs full (subpath .))`
/// - `"network deny"` → `(network deny)`
fn format_sandbox_sexpr(statements: &[&str], indent: &str) -> String {
    let inner_indent = format!("{}  ", indent);
    let mut result = format!("{}(sandbox", indent);
    for stmt in statements {
        result.push('\n');
        result.push_str(&inner_indent);
        result.push('(');
        result.push_str(&convert_sandbox_stmt_to_sexpr(stmt));
        result.push(')');
    }
    result.push(')');
    result
}

/// Convert a compact sandbox statement to s-expr content (without outer parens).
///
/// `"fs full subpath(.)"` → `"fs full (subpath .)"`
/// `"network deny"` → `"network deny"`
fn convert_sandbox_stmt_to_sexpr(stmt: &str) -> String {
    let parts: Vec<&str> = stmt.split_whitespace().collect();
    if parts.is_empty() {
        return stmt.to_string();
    }
    match parts[0] {
        "fs" if parts.len() >= 3 => {
            // parts[1..n-1] are caps, parts[n-1] is the filter like "subpath(.)"
            let filter_raw = parts[parts.len() - 1];
            let caps = &parts[1..parts.len() - 1];
            // Convert "subpath(.)" → "(subpath .)"
            let filter_sexpr = convert_filter_to_sexpr(filter_raw);
            format!("fs {} {}", caps.join(" "), filter_sexpr)
        }
        _ => stmt.to_string(),
    }
}

/// Convert a compact filter expression to s-expr.
///
/// `"subpath(.)"` → `(subpath .)`
/// `"literal(.env)"` → `(literal .env)`
fn convert_filter_to_sexpr(filter: &str) -> String {
    // Try to parse "func(arg)" format
    if let Some(paren_pos) = filter.find('(')
        && filter.ends_with(')')
    {
        let func = &filter[..paren_pos];
        let arg = &filter[paren_pos + 1..filter.len() - 1];
        return format!("({} {})", func, arg);
    }
    // Fallback: wrap as-is
    filter.to_string()
}

/// Detect the indentation used for forms within a profile body.
fn detect_profile_indent(text: &str, profile_start: usize, profile_end: usize) -> String {
    let bytes = text.as_bytes();
    // Scan for the first `(` inside the profile body (after the name)
    let mut pos = profile_start + 1;
    pos = skip_sexpr_whitespace(text, pos);
    // Skip "profile"
    while pos < profile_end && !bytes[pos].is_ascii_whitespace() && bytes[pos] != b'(' {
        pos += 1;
    }
    // Skip name
    pos = skip_sexpr_whitespace(text, pos);
    while pos < profile_end && !bytes[pos].is_ascii_whitespace() && bytes[pos] != b'(' {
        pos += 1;
    }
    pos = skip_sexpr_whitespace(text, pos);

    if pos < profile_end && bytes[pos] == b'(' {
        // Find the start of this line to determine indentation
        let line_start = line_start_of(text, pos);
        let indent_len = pos - line_start;
        " ".repeat(indent_len)
    } else {
        "  ".to_string() // fallback
    }
}

/// Indent a (possibly multi-line) form string with the given indent prefix.
fn indent_form(form: &str, indent: &str) -> String {
    let mut result = String::new();
    for (i, line) in form.lines().enumerate() {
        if i > 0 {
            result.push('\n');
        }
        result.push_str(indent);
        result.push_str(line);
    }
    result
}

/// Find the byte offset of the start of the line containing `pos`.
fn line_start_of(text: &str, pos: usize) -> usize {
    text[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // S-expr format tests
    // -----------------------------------------------------------------------

    const TEST_SEXPR: &str = r#"; Test policy
(default (permission deny) (profile main))

(profile base
  (deny bash "rm *"))

(profile main
  (include base)
  ; Git rules
  (allow bash "git *")
  (deny bash "git push*"))
"#;

    #[test]
    fn test_sexpr_policy_info() {
        let info = policy_info(TEST_SEXPR).unwrap();
        assert_eq!(info.default_permission, "deny");
        assert_eq!(info.active_profile, "main");
        assert!(info.profiles.contains(&"main".to_string()));
        assert!(info.profiles.contains(&"base".to_string()));
    }

    #[test]
    fn test_sexpr_resolve_profile_default() {
        let profile = resolve_profile(TEST_SEXPR, None).unwrap();
        assert_eq!(profile, "main");
    }

    #[test]
    fn test_sexpr_resolve_profile_override() {
        let profile = resolve_profile(TEST_SEXPR, Some("base")).unwrap();
        assert_eq!(profile, "base");
    }

    #[test]
    fn test_sexpr_add_rule_basic() {
        let result = add_rule(
            TEST_SEXPR,
            "main",
            "allow bash cargo *",
            &InlineConstraintArgs::default(),
        )
        .unwrap();
        assert!(result.contains("(allow bash \"cargo *\")"));
        // Original rules still present
        assert!(result.contains("(allow bash \"git *\")"));
        assert!(result.contains("(deny bash \"git push*\")"));
        // Comment preserved
        assert!(result.contains("; Git rules"));
        assert!(result.contains("; Test policy"));
    }

    #[test]
    fn test_sexpr_add_rule_idempotent() {
        let result = add_rule(
            TEST_SEXPR,
            "main",
            "allow bash git *",
            &InlineConstraintArgs::default(),
        )
        .unwrap();
        assert_eq!(result, TEST_SEXPR);
    }

    #[test]
    fn test_sexpr_add_rule_to_base_profile() {
        let result = add_rule(
            TEST_SEXPR,
            "base",
            "deny bash sudo *",
            &InlineConstraintArgs::default(),
        )
        .unwrap();
        assert!(result.contains("(deny bash \"sudo *\")"));
        assert!(result.contains("(deny bash \"rm *\")"));
    }

    #[test]
    fn test_sexpr_add_rule_unknown_profile() {
        let result = add_rule(
            TEST_SEXPR,
            "nonexistent",
            "allow bash git *",
            &InlineConstraintArgs::default(),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_sexpr_remove_rule_basic() {
        let result = remove_rule(TEST_SEXPR, "main", "deny bash git push*").unwrap();
        assert!(!result.contains("git push*"));
        // Other rules still present
        assert!(result.contains("(allow bash \"git *\")"));
        assert!(result.contains("; Git rules"));
    }

    #[test]
    fn test_sexpr_remove_rule_not_found() {
        let result = remove_rule(TEST_SEXPR, "main", "allow bash cargo *");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_sexpr_add_then_remove_roundtrip() {
        let added = add_rule(
            TEST_SEXPR,
            "main",
            "allow bash cargo build *",
            &InlineConstraintArgs::default(),
        )
        .unwrap();
        assert!(added.contains("(allow bash \"cargo build *\")"));
        let removed = remove_rule(&added, "main", "allow bash cargo build *").unwrap();
        assert!(!removed.contains("cargo build"));
        assert!(removed.contains("(allow bash \"git *\")"));
    }

    #[test]
    fn test_sexpr_set_sandbox_basic() {
        let result =
            set_sandbox(TEST_SEXPR, "main", &["fs full subpath(.)", "network deny"]).unwrap();
        assert!(result.contains("(sandbox"), "result:\n{}", result);
        assert!(
            result.contains("(fs full (subpath .))"),
            "result:\n{}",
            result
        );
        assert!(result.contains("(network deny)"), "result:\n{}", result);
        // Rules still present
        assert!(result.contains("(allow bash \"git *\")"));
    }

    #[test]
    fn test_sexpr_set_sandbox_replaces_existing() {
        let with_sandbox = set_sandbox(TEST_SEXPR, "main", &["fs full subpath(.)"]).unwrap();
        assert!(with_sandbox.contains("(fs full (subpath .))"));

        let replaced = set_sandbox(
            &with_sandbox,
            "main",
            &["fs read subpath(/tmp)", "network allow"],
        )
        .unwrap();
        assert!(!replaced.contains("(fs full"));
        assert!(replaced.contains("(fs read (subpath /tmp))"));
        assert!(replaced.contains("(network allow)"));
    }

    #[test]
    fn test_sexpr_set_sandbox_empty_removes() {
        let with_sandbox = set_sandbox(TEST_SEXPR, "main", &["fs full subpath(.)"]).unwrap();
        assert!(with_sandbox.contains("(sandbox"));

        let removed = set_sandbox(&with_sandbox, "main", &[]).unwrap();
        assert!(!removed.contains("sandbox"));
        assert!(removed.contains("(allow bash \"git *\")"));
    }

    #[test]
    fn test_sexpr_set_sandbox_unknown_profile() {
        let result = set_sandbox(TEST_SEXPR, "nonexistent", &["fs full subpath(.)"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_sexpr_add_rule_with_url_constraints() {
        let constraints = InlineConstraintArgs {
            url: vec!["github.com".into(), "!evil.com".into()],
            ..Default::default()
        };
        let result = add_rule(TEST_SEXPR, "main", "allow webfetch *", &constraints).unwrap();
        assert!(result.contains("(allow webfetch *"));
        assert!(result.contains("\"github.com\""));
        assert!(result.contains("(not \"evil.com\")"));
    }

    #[test]
    fn test_sexpr_add_rule_with_args_constraints() {
        let constraints = InlineConstraintArgs {
            args: vec!["--dry-run".into(), "!-delete".into()],
            ..Default::default()
        };
        let result = add_rule(TEST_SEXPR, "main", "allow bash cargo *", &constraints).unwrap();
        assert!(result.contains("(allow bash \"cargo *\""));
        assert!(result.contains("(args \"--dry-run\" (not \"-delete\"))"));
    }

    #[test]
    fn test_fs_constraint_validate_ok() {
        let constraints = InlineConstraintArgs {
            fs: vec!["full:subpath(~/dir)".into()],
            ..Default::default()
        };
        assert!(constraints.validate().is_ok());
    }

    #[test]
    fn test_fs_constraint_validate_missing_colon() {
        let constraints = InlineConstraintArgs {
            fs: vec!["subpath(~/dir)".into()],
            ..Default::default()
        };
        assert!(constraints.validate().is_err());
    }
}
