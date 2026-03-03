//! Policy syntax versioning and deprecation framework.
//!
//! Each policy file may declare `(version N)`. When absent, version 1 is assumed
//! for backwards compatibility. The compiler validates that the declared version
//! is known and checks for deprecated features that should be migrated.
//!
//! To add a new deprecation:
//! 1. Bump `CURRENT_VERSION` if this is a new version boundary
//! 2. Add a `Deprecation` entry to `all_deprecations()`
//! 3. Implement the `check` function (returns true if the deprecated pattern is present)
//! 4. Optionally implement `fix` (returns the migrated source text)

use super::ast::*;

/// The current (latest) policy syntax version.
///
/// Bump this when making backwards-incompatible changes to the policy language.
/// Every bump must be accompanied by deprecation entries that describe what changed
/// and (ideally) an auto-fix function for `clash policy upgrade`.
pub const CURRENT_VERSION: u32 = 3;

/// A deprecated feature in the policy language.
pub struct Deprecation {
    /// The version in which this feature was deprecated.
    pub deprecated_in: u32,
    /// Human-readable description of what changed and what to do about it.
    pub message: String,
    /// Check whether the deprecated pattern is present in the source.
    /// Returns true if the deprecated feature is detected.
    pub check: fn(&str) -> bool,
    /// Optional auto-fix: transform the source to remove the deprecated pattern.
    /// Returns None if no fix is needed (check returned false).
    pub fix: Option<fn(&str) -> String>,
}

/// Extract the declared version from a parsed AST.
///
/// Returns `1` if no `(version N)` declaration is present (backwards compatibility).
/// Returns an error if multiple version declarations exist.
pub fn extract_version(ast: &[TopLevel]) -> anyhow::Result<u32> {
    let versions: Vec<u32> = ast
        .iter()
        .filter_map(|tl| match tl {
            TopLevel::Version(v) => Some(*v),
            _ => None,
        })
        .collect();

    match versions.len() {
        0 => Ok(1),
        1 => Ok(versions[0]),
        _ => anyhow::bail!("multiple (version) declarations found; only one is allowed"),
    }
}

/// Validate that a declared version is supported by this build of clash.
pub fn validate_version(version: u32) -> anyhow::Result<()> {
    if version > CURRENT_VERSION {
        anyhow::bail!(
            "policy declares (version {version}) but this build of clash only supports \
             up to version {CURRENT_VERSION}. Please update clash to a newer version."
        );
    }
    Ok(())
}

/// Return all known deprecations.
///
/// Add new entries here when making backwards-incompatible changes.
/// Each deprecation should have a `check` that detects the deprecated pattern
/// and (ideally) a `fix` that transforms the source to the new syntax.
///
/// Note: The v1 → v2 version bump is NOT a deprecation — v1 flat rules are
/// valid v2 syntax. The version bump is handled as a feature upgrade in
/// `upgrade_policy()` instead.
pub fn all_deprecations() -> Vec<Deprecation> {
    vec![
        Deprecation {
            deprecated_in: 2,
            message: "`(default ...)` is deprecated in v2. Use `(use \"name\")` and a bare effect in the policy body.".into(),
            check: |source| source.contains("(default "),
            fix: Some(fix_default_to_use),
        },
        Deprecation {
            deprecated_in: 2,
            message: "`proxy.domain` is deprecated. Use `ctx.http.domain`.".into(),
            check: |source| has_deprecated_observable(source, "proxy.domain"),
            fix: Some(|s| fix_observable_name(s, "proxy.domain", "ctx.http.domain")),
        },
        Deprecation {
            deprecated_in: 2,
            message: "`proxy.method` is deprecated. Use `ctx.http.method`.".into(),
            check: |source| has_deprecated_observable(source, "proxy.method"),
            fix: Some(|s| fix_observable_name(s, "proxy.method", "ctx.http.method")),
        },
        Deprecation {
            deprecated_in: 2,
            message: "`fs.action` is deprecated as an observable name. Use `ctx.fs.action`.".into(),
            check: |source| has_deprecated_observable(source, "fs.action"),
            fix: Some(|s| fix_observable_name(s, "fs.action", "ctx.fs.action")),
        },
        Deprecation {
            deprecated_in: 2,
            message: "`fs.path` is deprecated as an observable name. Use `ctx.fs.path`.".into(),
            check: |source| has_deprecated_observable(source, "fs.path"),
            fix: Some(|s| fix_observable_name(s, "fs.path", "ctx.fs.path")),
        },
        Deprecation {
            deprecated_in: 3,
            message: "`(sandbox ...)` is removed in v3. Constraints are now derived from match blocks in the decision tree. Run `clash policy upgrade` to migrate.".into(),
            check: |source| source.contains("(sandbox"),
            // Fix is handled at AST level in upgrade_policy (transform_v2_to_v3)
            // because the v3 parser rejects (sandbox ...) so text-level re-parse fails.
            fix: None,
        },
    ]
}

/// Check whether a deprecated observable name appears as a bare atom in the source.
///
/// Looks for the name surrounded by s-expression delimiters (whitespace, parens, brackets)
/// to avoid false positives inside string literals or unrelated identifiers.
fn has_deprecated_observable(source: &str, name: &str) -> bool {
    // Observable names appear as bare atoms, so they are delimited by
    // whitespace, '(', ')', '[', ']', or start/end of string.
    let is_delim = |c: char| c.is_whitespace() || matches!(c, '(' | ')' | '[' | ']');
    let mut search_from = 0;
    while let Some(pos) = source[search_from..].find(name) {
        let abs_pos = search_from + pos;
        let before_ok = abs_pos == 0
            || source[..abs_pos]
                .chars()
                .next_back()
                .is_some_and(|c| is_delim(c));
        let after_pos = abs_pos + name.len();
        let after_ok = after_pos >= source.len()
            || source[after_pos..]
                .chars()
                .next()
                .is_some_and(|c| is_delim(c));
        if before_ok && after_ok {
            return true;
        }
        search_from = abs_pos + name.len();
    }
    false
}

/// Replace a deprecated observable name with its `ctx.*` equivalent throughout source text.
///
/// Only replaces bare atoms (delimited by s-expression boundaries), not occurrences
/// inside string literals or other identifiers.
fn fix_observable_name(source: &str, old: &str, new: &str) -> String {
    let is_delim = |c: char| c.is_whitespace() || matches!(c, '(' | ')' | '[' | ']');
    let mut result = String::with_capacity(source.len());
    let mut search_from = 0;
    while let Some(pos) = source[search_from..].find(old) {
        let abs_pos = search_from + pos;
        let before_ok = abs_pos == 0
            || source[..abs_pos]
                .chars()
                .next_back()
                .is_some_and(|c| is_delim(c));
        let after_pos = abs_pos + old.len();
        let after_ok = after_pos >= source.len()
            || source[after_pos..]
                .chars()
                .next()
                .is_some_and(|c| is_delim(c));
        if before_ok && after_ok {
            result.push_str(&source[search_from..abs_pos]);
            result.push_str(new);
            search_from = after_pos;
        } else {
            result.push_str(&source[search_from..after_pos]);
            search_from = after_pos;
        }
    }
    result.push_str(&source[search_from..]);
    result
}

/// Migrate `(default effect "name")` → `(use "name")` + bare effect in the entry policy body.
fn fix_default_to_use(source: &str) -> String {
    let mut ast = match super::parse::parse(source) {
        Ok(a) => a,
        Err(_) => return source.to_string(),
    };

    // Find and remove the Default declaration, capturing its values.
    let default_info = ast.iter().find_map(|tl| match tl {
        TopLevel::Default { effect, policy } => Some((*effect, policy.clone())),
        _ => None,
    });

    let Some((effect, policy_name)) = default_info else {
        return source.to_string();
    };

    // Check if a (use ...) already exists — if so, only strip (default ...).
    let has_use = ast.iter().any(|tl| matches!(tl, TopLevel::Use(_)));

    // Replace Default with Use (or just remove Default if Use already exists).
    ast.retain(|tl| !matches!(tl, TopLevel::Default { .. }));
    if !has_use {
        // Insert (use "name") after (version N) if present, else at position 0.
        let pos = ast
            .iter()
            .position(|tl| !matches!(tl, TopLevel::Version(_)))
            .unwrap_or(0);
        ast.insert(pos, TopLevel::Use(policy_name.clone()));
    }

    // Append the effect to the entry policy body if not already present.
    let entry_name = ast
        .iter()
        .find_map(|tl| match tl {
            TopLevel::Use(n) => Some(n.clone()),
            _ => None,
        })
        .unwrap_or(policy_name);

    for tl in &mut ast {
        if let TopLevel::Policy { name, body } = tl {
            if *name == entry_name {
                let has_body_effect = body
                    .iter()
                    .any(|item| matches!(item, PolicyItem::Effect(_)));
                if !has_body_effect {
                    body.push(PolicyItem::Effect(effect));
                }
                break;
            }
        }
    }

    super::edit::serialize_ast(&ast)
}

// ---------------------------------------------------------------------------
// v2 → v3 AST transformation
// ---------------------------------------------------------------------------

/// Transform all `(sandbox ...)` blocks in policy bodies to inline match blocks.
///
/// Returns true if any transformation was performed.
fn transform_v2_to_v3(ast: &mut [TopLevel]) -> bool {
    let mut changed = false;
    for tl in ast.iter_mut() {
        if let TopLevel::Policy { body, .. } = tl {
            let new_body = lift_sandbox_items(body);
            if new_body != *body {
                *body = new_body;
                changed = true;
            }
        }
    }
    changed
}

/// Recursively lift sandbox items out of `(sandbox ...)` wrappers.
///
/// Each `SandboxItem::Match(block)` inside a sandbox becomes a `PolicyItem::Match(block)`.
/// `SandboxItem::Rule(...)` entries (from v1 migration) are dropped since constraints
/// are now derived from the decision tree in v3.
fn lift_sandbox_items(items: &[PolicyItem]) -> Vec<PolicyItem> {
    let mut result = Vec::new();
    for item in items {
        match item {
            PolicyItem::Sandbox { body } => {
                for si in body {
                    match si {
                        SandboxItem::Match(block) => {
                            result.push(PolicyItem::Match(block.clone()));
                        }
                        SandboxItem::Rule(_) => {
                            // v1 flat rules inside sandbox: drop them, constraints
                            // are derived from the decision tree in v3.
                        }
                    }
                }
            }
            PolicyItem::When {
                observable,
                pattern,
                body,
            } => {
                result.push(PolicyItem::When {
                    observable: observable.clone(),
                    pattern: pattern.clone(),
                    body: lift_sandbox_items(body),
                });
            }
            other => result.push(other.clone()),
        }
    }
    result
}

/// Check a policy source for deprecated features at the given version.
///
/// Returns a list of warning messages for any deprecated patterns found.
/// Fires when the policy's declared version is at or above the deprecation
/// boundary (the feature is deprecated *in* that version and later).
pub fn check_deprecations(source: &str, version: u32) -> Vec<String> {
    all_deprecations()
        .into_iter()
        .filter(|d| version >= d.deprecated_in && (d.check)(source))
        .map(|d| d.message)
        .collect()
}

/// Upgrade a policy source: transform v1 flat rules to v2 structured syntax
/// and bump to CURRENT_VERSION.
///
/// Returns the upgraded source text and a list of what changed.
/// Returns an empty changes list when nothing needs to be done.
pub fn upgrade_policy(source: &str) -> anyhow::Result<(String, Vec<String>)> {
    let mut ast = super::parse::parse(source)?;
    let version = extract_version(&ast)?;
    validate_version(version)?;

    let has_version_decl = ast.iter().any(|tl| matches!(tl, TopLevel::Version(_)));

    // Check if any deprecation fixes are needed even at current version.
    let has_deprecations = all_deprecations()
        .iter()
        .any(|d| version >= d.deprecated_in && (d.check)(source));

    if version == CURRENT_VERSION && has_version_decl && !has_deprecations {
        return Ok((source.to_string(), vec![]));
    }

    let mut changes = Vec::new();

    // Set version declaration first so that fixes producing v2 syntax can be re-parsed.
    let mut found_version = false;
    for tl in &mut ast {
        if let TopLevel::Version(v) = tl {
            *v = CURRENT_VERSION;
            found_version = true;
            break;
        }
    }
    if !found_version {
        ast.insert(0, TopLevel::Version(CURRENT_VERSION));
    }

    if version < CURRENT_VERSION {
        changes.push(format!("Set (version {CURRENT_VERSION})."));
    } else if !has_version_decl {
        changes.push(format!(
            "Added (version {CURRENT_VERSION}) declaration to policy."
        ));
    }

    // Transform v1 flat rules to v2 structured syntax BEFORE re-serializing,
    // because the v2 parser rejects flat rules.
    if version < 2 {
        let transformed = transform_v1_to_v2(&mut ast);
        if transformed {
            changes
                .push("Transformed flat rules to v2 structured syntax (when/match blocks).".into());
        }
    }

    // Transform v2 sandbox blocks to inline match blocks (v3 removes sandbox).
    if version < 3 {
        let transformed = transform_v2_to_v3(&mut ast);
        if transformed {
            changes.push("Replaced (sandbox ...) blocks with inline (match ...) blocks.".into());
        }
    }

    // Re-serialize with version set, so deprecation fixes can re-parse as v2.
    let mut text = super::edit::serialize_ast(&ast);

    // Apply deprecation fixes.
    for dep in all_deprecations() {
        if dep.deprecated_in <= CURRENT_VERSION && (dep.check)(&text) {
            if let Some(fix) = dep.fix {
                text = fix(&text);
                changes.push(dep.message);
                // Re-parse after text-level fixes.
                ast = super::parse::parse(&text)?;
            } else {
                changes.push(format!("{} (manual fix required)", dep.message));
            }
        }
    }

    Ok((super::edit::serialize_ast(&ast), changes))
}

// ---------------------------------------------------------------------------
// v1 → v2 AST transformation
// ---------------------------------------------------------------------------

use crate::policy::Effect;

/// Transform all v1 flat rules in policy bodies to v2 structured syntax.
///
/// Returns true if any transformation was performed.
fn transform_v1_to_v2(ast: &mut [TopLevel]) -> bool {
    let mut transformed = false;
    for tl in ast.iter_mut() {
        if let TopLevel::Policy { body, .. } = tl {
            let new_body = transform_policy_body(body);
            if new_body != *body {
                *body = new_body;
                transformed = true;
            }
        }
    }
    transformed
}

/// Transform a single policy body's flat rules into v2 when/sandbox blocks.
fn transform_policy_body(body: &[PolicyItem]) -> Vec<PolicyItem> {
    let mut result = Vec::new();
    let mut sandbox_fs_items: Vec<SandboxItem> = Vec::new();
    let mut sandbox_net_items: Vec<SandboxItem> = Vec::new();

    for item in body {
        match item {
            PolicyItem::Rule(rule) => {
                transform_rule(
                    rule,
                    &mut result,
                    &mut sandbox_fs_items,
                    &mut sandbox_net_items,
                );
            }
            // Include, When, Sandbox, Effect pass through unchanged.
            _ => result.push(item.clone()),
        }
    }

    // Wrap collected sandbox items in (when (command *) (sandbox ...)).
    let mut sandbox_body = Vec::new();
    sandbox_body.append(&mut sandbox_fs_items);
    sandbox_body.append(&mut sandbox_net_items);

    if !sandbox_body.is_empty() {
        result.push(PolicyItem::When {
            observable: Observable::Command,
            pattern: ArmPattern::Exec(ExecMatcher {
                bin: Pattern::Any,
                args: vec![],
                has_args: vec![],
            }),
            body: vec![PolicyItem::Sandbox { body: sandbox_body }],
        });
    }

    result
}

/// Transform a single flat rule into v2 when blocks.
///
/// For exec/tool rules: produces `(when (command/tool ...) :effect)`.
/// For fs/net rules: produces `(when (tool ...) :effect)` and collects
/// sandbox items for allow-effect rules.
fn transform_rule(
    rule: &Rule,
    result: &mut Vec<PolicyItem>,
    sandbox_fs: &mut Vec<SandboxItem>,
    sandbox_net: &mut Vec<SandboxItem>,
) {
    match &rule.matcher {
        CapMatcher::Exec(exec_matcher) => {
            let mut when_body = vec![PolicyItem::Effect(rule.effect)];

            // Inline sandbox rules transfer to a (sandbox ...) block.
            if let Some(SandboxRef::Inline(sandbox_rules)) = &rule.sandbox {
                let items = sandbox_rules
                    .iter()
                    .map(|r| SandboxItem::Rule(r.clone()))
                    .collect();
                when_body.push(PolicyItem::Sandbox { body: items });
            }
            // Named sandbox: inline the referenced policy's rules.
            // (Named refs are rare in practice; drop with a comment if unresolvable.)

            result.push(PolicyItem::When {
                observable: Observable::Command,
                pattern: ArmPattern::Exec(exec_matcher.clone()),
                body: when_body,
            });
        }
        CapMatcher::Tool(tool_matcher) => {
            result.push(PolicyItem::When {
                observable: Observable::Tool,
                pattern: ArmPattern::Single(tool_matcher.name.clone()),
                body: vec![PolicyItem::Effect(rule.effect)],
            });
        }
        CapMatcher::Fs(fs_matcher) => {
            let tool_names = fs_op_to_tool_names(&fs_matcher.op);
            let tool_pattern = names_to_pattern(&tool_names);
            result.push(PolicyItem::When {
                observable: Observable::Tool,
                pattern: ArmPattern::Single(tool_pattern),
                body: vec![PolicyItem::Effect(rule.effect)],
            });

            // For allow effects, also collect the fs rule as a sandbox item
            // so sandboxed commands get the filesystem capability.
            if rule.effect == Effect::Allow {
                sandbox_fs.push(SandboxItem::Rule(Rule {
                    effect: rule.effect,
                    matcher: rule.matcher.clone(),
                    sandbox: None,
                }));
            }
        }
        CapMatcher::Net(_) => {
            let tool_pattern = names_to_pattern(&["WebFetch", "WebSearch"]);
            result.push(PolicyItem::When {
                observable: Observable::Tool,
                pattern: ArmPattern::Single(tool_pattern),
                body: vec![PolicyItem::Effect(rule.effect)],
            });

            // For allow effects, also collect the net rule as a sandbox item.
            if rule.effect == Effect::Allow {
                sandbox_net.push(SandboxItem::Rule(Rule {
                    effect: rule.effect,
                    matcher: rule.matcher.clone(),
                    sandbox: None,
                }));
            }
        }
    }
}

/// Map fs operation patterns to the Claude Code tool names they correspond to.
fn fs_op_to_tool_names(op: &OpPattern) -> Vec<&'static str> {
    match op {
        OpPattern::Any => vec!["Read", "Glob", "Grep", "Write", "Edit"],
        OpPattern::Single(FsOp::Read) => vec!["Read", "Glob", "Grep"],
        OpPattern::Single(FsOp::Write | FsOp::Create | FsOp::Delete) => vec!["Write", "Edit"],
        OpPattern::Or(ops) => {
            let mut names = Vec::new();
            if ops.contains(&FsOp::Read) {
                names.extend_from_slice(&["Read", "Glob", "Grep"]);
            }
            if ops
                .iter()
                .any(|o| matches!(o, FsOp::Write | FsOp::Create | FsOp::Delete))
            {
                names.extend_from_slice(&["Write", "Edit"]);
            }
            if names.is_empty() {
                vec!["Read", "Glob", "Grep", "Write", "Edit"]
            } else {
                names
            }
        }
    }
}

/// Build a Pattern from a list of tool names.
fn names_to_pattern(names: &[&str]) -> Pattern {
    if names.len() == 1 {
        Pattern::Literal(names[0].to_string())
    } else {
        Pattern::Or(
            names
                .iter()
                .map(|n| Pattern::Literal(n.to_string()))
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_version_default() {
        let ast =
            super::super::parse::parse("(default deny \"main\")\n(policy \"main\")\n").unwrap();
        assert_eq!(extract_version(&ast).unwrap(), 1);
    }

    #[test]
    fn extract_version_explicit() {
        let ast =
            super::super::parse::parse("(version 1)\n(default deny \"main\")\n(policy \"main\")\n")
                .unwrap();
        assert_eq!(extract_version(&ast).unwrap(), 1);
    }

    #[test]
    fn extract_version_multiple_errors() {
        let ast = super::super::parse::parse(
            "(version 1)\n(version 2)\n(default deny \"main\")\n(policy \"main\")\n",
        )
        .unwrap();
        assert!(extract_version(&ast).is_err());
    }

    #[test]
    fn validate_version_current() {
        assert!(validate_version(CURRENT_VERSION).is_ok());
    }

    #[test]
    fn validate_version_future() {
        assert!(validate_version(CURRENT_VERSION + 1).is_err());
    }

    #[test]
    fn upgrade_adds_version_declaration() {
        let source = "(default deny \"main\")\n(policy \"main\")\n";
        let (upgraded, changes) = upgrade_policy(source).unwrap();
        assert!(
            upgraded.contains(&format!("(version {CURRENT_VERSION})")),
            "expected (version {CURRENT_VERSION}), got:\n{upgraded}"
        );
        // (default ...) should be migrated to (use ...) + body effect.
        assert!(
            upgraded.contains("(use \"main\")"),
            "expected (use \"main\") after upgrade, got:\n{upgraded}"
        );
        assert!(
            !upgraded.contains("(default "),
            "expected (default ...) removed after upgrade, got:\n{upgraded}"
        );
        assert!(!changes.is_empty());
        assert!(
            changes[0].contains(&format!("(version {CURRENT_VERSION})")),
            "expected version set note, got: {}",
            changes[0]
        );
    }

    #[test]
    fn upgrade_already_current_is_noop() {
        let source =
            &format!("(version {CURRENT_VERSION})\n(use \"main\")\n(policy \"main\"\n  :deny)\n");
        let (upgraded, changes) = upgrade_policy(source).unwrap();
        assert_eq!(upgraded, *source);
        assert!(changes.is_empty());
    }
}
