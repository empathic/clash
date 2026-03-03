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
pub const CURRENT_VERSION: u32 = 2;

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
    vec![]
}

/// Check a policy source for deprecated features at the given version.
///
/// Returns a list of warning messages for any deprecated patterns found.
pub fn check_deprecations(source: &str, version: u32) -> Vec<String> {
    all_deprecations()
        .into_iter()
        .filter(|d| d.deprecated_in > version && (d.check)(source))
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

    if version == CURRENT_VERSION && has_version_decl {
        return Ok((source.to_string(), vec![]));
    }

    let mut changes = Vec::new();

    // Apply deprecation fixes.
    // (Currently none, but the framework is here for future use.)
    let mut text = source.to_string();
    for dep in all_deprecations() {
        if dep.deprecated_in > version && dep.deprecated_in <= CURRENT_VERSION && (dep.check)(&text)
        {
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

    // Transform v1 flat rules to v2 structured syntax.
    if version < 2 {
        let transformed = transform_v1_to_v2(&mut ast);
        if transformed {
            changes.push(
                "Transformed flat rules to v2 structured syntax (when/sandbox blocks).".into(),
            );
        }
    }

    // Set version declaration.
    let mut found = false;
    for tl in &mut ast {
        if let TopLevel::Version(v) = tl {
            *v = CURRENT_VERSION;
            found = true;
            break;
        }
    }
    if !found {
        ast.insert(0, TopLevel::Version(CURRENT_VERSION));
    }

    if version < CURRENT_VERSION {
        changes.insert(0, format!("Set (version {CURRENT_VERSION})."));
    } else if !has_version_decl {
        changes.push(format!(
            "Added (version {CURRENT_VERSION}) declaration to policy."
        ));
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
            predicate: WhenPredicate::Command(ExecMatcher {
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
            let predicate = WhenPredicate::Command(exec_matcher.clone());
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
                predicate,
                body: when_body,
            });
        }
        CapMatcher::Tool(tool_matcher) => {
            result.push(PolicyItem::When {
                predicate: WhenPredicate::Tool(tool_matcher.clone()),
                body: vec![PolicyItem::Effect(rule.effect)],
            });
        }
        CapMatcher::Fs(fs_matcher) => {
            let tool_names = fs_op_to_tool_names(&fs_matcher.op);
            let tool_pattern = names_to_pattern(&tool_names);
            result.push(PolicyItem::When {
                predicate: WhenPredicate::Tool(ToolMatcher { name: tool_pattern }),
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
                predicate: WhenPredicate::Tool(ToolMatcher { name: tool_pattern }),
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
            &format!("(version {CURRENT_VERSION})\n(default deny \"main\")\n(policy \"main\")\n");
        let (upgraded, changes) = upgrade_policy(source).unwrap();
        assert_eq!(upgraded, *source);
        assert!(changes.is_empty());
    }
}
