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

use super::ast::TopLevel;

/// The current (latest) policy syntax version.
///
/// Bump this when making backwards-incompatible changes to the policy language.
/// Every bump must be accompanied by deprecation entries that describe what changed
/// and (ideally) an auto-fix function for `clash policy upgrade`.
pub const CURRENT_VERSION: u32 = 1;

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
/// Each deprecation is tied to the version that deprecated the old behavior.
pub fn all_deprecations() -> Vec<Deprecation> {
    vec![
        // Example for future use — the (env CWD) → (env PWD) rename was a pre-version
        // migration handled in settings.rs. When we add version 2, we'll add entries here.
        //
        // Deprecation {
        //     deprecated_in: 2,
        //     message: "description of what changed".into(),
        //     check: |source| source.contains("old_pattern"),
        //     fix: Some(|source| source.replace("old_pattern", "new_pattern")),
        // },
    ]
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

/// Upgrade a policy source: apply all auto-fixes and set the version to CURRENT_VERSION.
///
/// Returns the upgraded source text, or the original if no changes were needed.
/// Also returns a list of descriptions of what was changed.
pub fn upgrade_policy(source: &str) -> anyhow::Result<(String, Vec<String>)> {
    let ast = super::parse::parse(source)?;
    let version = extract_version(&ast)?;
    validate_version(version)?;

    if version == CURRENT_VERSION {
        // Check if the policy just needs a version declaration added.
        let has_version_decl = ast.iter().any(|tl| matches!(tl, TopLevel::Version(_)));
        if has_version_decl {
            return Ok((source.to_string(), vec![]));
        }
        // Add version declaration to an already-current policy.
        let upgraded = prepend_version(source, CURRENT_VERSION);
        return Ok((
            upgraded,
            vec![format!(
                "Added (version {CURRENT_VERSION}) declaration to policy."
            )],
        ));
    }

    let mut result = source.to_string();
    let mut changes = Vec::new();

    // Apply all auto-fixes for deprecations between the declared version and current.
    for dep in all_deprecations() {
        if dep.deprecated_in > version
            && dep.deprecated_in <= CURRENT_VERSION
            && (dep.check)(&result)
        {
            if let Some(fix) = dep.fix {
                result = fix(&result);
                changes.push(dep.message);
            } else {
                // No auto-fix available — warn but continue.
                changes.push(format!("{} (manual fix required)", dep.message));
            }
        }
    }

    // Update or add the version declaration.
    result = set_version(&result, CURRENT_VERSION)?;
    if !changes.is_empty() || version < CURRENT_VERSION {
        changes.insert(
            0,
            format!("Upgraded policy from version {version} to {CURRENT_VERSION}."),
        );
    }

    Ok((result, changes))
}

/// Prepend a `(version N)` declaration to policy source text.
fn prepend_version(source: &str, version: u32) -> String {
    format!("(version {version})\n{source}")
}

/// Set or update the `(version N)` declaration in a policy source.
fn set_version(source: &str, version: u32) -> anyhow::Result<String> {
    let mut ast = super::parse::parse(source)?;

    let mut found = false;
    for tl in &mut ast {
        if let TopLevel::Version(v) = tl {
            *v = version;
            found = true;
            break;
        }
    }

    if !found {
        ast.insert(0, TopLevel::Version(version));
    }

    Ok(super::edit::serialize_ast(&ast))
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
        assert!(upgraded.contains("(version 1)"));
        assert_eq!(changes.len(), 1);
        assert!(changes[0].contains("Added"));
    }

    #[test]
    fn upgrade_already_current_is_noop() {
        let source = "(version 1)\n(default deny \"main\")\n(policy \"main\")\n";
        let (upgraded, changes) = upgrade_policy(source).unwrap();
        assert_eq!(upgraded, source);
        assert!(changes.is_empty());
    }
}
