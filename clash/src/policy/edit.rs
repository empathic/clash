//! Comment-preserving YAML editing for policy files.
//!
//! These functions operate on the raw YAML text via string-level operations,
//! avoiding serde roundtrips that would strip comments. After each edit, the
//! modified text is re-parsed to verify correctness.

use anyhow::{Context, Result, bail};

use super::parse;

/// Compute the leading whitespace (indent) of a line.
fn get_indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Bail if the YAML is not in the new profile-based format.
fn ensure_new_format(yaml: &str) -> Result<()> {
    if !is_new_format(yaml) {
        bail!(
            "Old policy format detected. Run `clash init --force` to upgrade to the new profile-based format."
        );
    }
    Ok(())
}

/// Validate that a profile exists in the YAML, returning a helpful error if not.
fn validate_profile_exists(yaml: &str, profile: &str) -> Result<()> {
    let names = profile_names(yaml)?;
    if !names.iter().any(|n| n == profile) {
        let suggestion = super::error::suggest_closest(
            profile,
            &names.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        );
        if let Some(s) = suggestion {
            bail!("profile '{}' not found; did you mean '{}'?", profile, s);
        } else {
            bail!(
                "profile '{}' not found. Available profiles: {}",
                profile,
                names.join(", ")
            );
        }
    }
    Ok(())
}

/// Join lines into a single string, preserving the original trailing newline behavior.
fn reconstruct_yaml(lines: &[String], had_trailing_newline: bool) -> String {
    if had_trailing_newline {
        format!("{}\n", lines.join("\n"))
    } else {
        lines.join("\n")
    }
}

/// Check whether the given YAML text uses the new profile-based format.
///
/// New format has `default:` as a YAML mapping (with `permission` and `profile` keys).
/// Old format has `default:` as a scalar string or missing.
pub fn is_new_format(yaml: &str) -> bool {
    let value: serde_yaml::Value = match serde_yaml::from_str(yaml) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if let serde_yaml::Value::Mapping(map) = &value
        && let Some(default_val) = map.get(serde_yaml::Value::String("default".into()))
    {
        return default_val.is_mapping();
    }
    false
}

/// Resolve the active profile name from the YAML text.
fn active_profile(yaml: &str) -> Result<String> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(yaml).context("failed to parse policy YAML")?;
    let map = value
        .as_mapping()
        .ok_or_else(|| anyhow::anyhow!("policy YAML is not a mapping"))?;
    let default_val = map
        .get(serde_yaml::Value::String("default".into()))
        .ok_or_else(|| anyhow::anyhow!("missing 'default' key"))?;
    let default_map = default_val
        .as_mapping()
        .ok_or_else(|| anyhow::anyhow!("'default' is not a mapping"))?;
    let profile = default_map
        .get(serde_yaml::Value::String("profile".into()))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing 'default.profile'"))?;
    Ok(profile.to_string())
}

/// Return the list of profile names defined in the YAML text.
fn profile_names(yaml: &str) -> Result<Vec<String>> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(yaml).context("failed to parse policy YAML")?;
    let map = value
        .as_mapping()
        .ok_or_else(|| anyhow::anyhow!("policy YAML is not a mapping"))?;
    let profiles_val = match map.get(serde_yaml::Value::String("profiles".into())) {
        Some(v) => v,
        None => return Ok(Vec::new()),
    };
    let profiles_map = profiles_val
        .as_mapping()
        .ok_or_else(|| anyhow::anyhow!("'profiles' is not a mapping"))?;
    Ok(profiles_map
        .keys()
        .filter_map(|k| k.as_str().map(|s| s.to_string()))
        .collect())
}

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
}

impl InlineConstraintArgs {
    /// Returns true if there are no constraints to emit.
    pub fn is_empty(&self) -> bool {
        self.fs.is_empty()
            && self.url.is_empty()
            && self.args.is_empty()
            && self.pipe.is_none()
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

    /// Render constraint lines as YAML at the given indent level.
    fn to_yaml_lines(&self, indent: usize) -> Vec<String> {
        let mut lines = Vec::new();
        let pad = " ".repeat(indent);
        if !self.fs.is_empty() {
            lines.push(format!("{}fs:", pad));
            for entry in &self.fs {
                if let Some((caps, filter)) = entry.split_once(':') {
                    lines.push(format!("{}  {}: {}", pad, caps.trim(), filter.trim()));
                }
            }
        }
        if !self.url.is_empty() {
            let items: Vec<String> = self.url.iter().map(|u| format!("\"{}\"", u)).collect();
            lines.push(format!("{}url: [{}]", pad, items.join(", ")));
        }
        if !self.args.is_empty() {
            let items: Vec<String> = self.args.iter().map(|a| format!("\"{}\"", a)).collect();
            lines.push(format!("{}args: [{}]", pad, items.join(", ")));
        }
        if let Some(v) = self.pipe {
            lines.push(format!("{}pipe: {}", pad, v));
        }
        if let Some(v) = self.redirect {
            lines.push(format!("{}redirect: {}", pad, v));
        }
        lines
    }
}

/// Add a rule to a profile's rules block, preserving comments.
/// Returns the modified YAML text.
pub fn add_rule(
    yaml: &str,
    profile: &str,
    rule: &str,
    constraints: &InlineConstraintArgs,
) -> Result<String> {
    ensure_new_format(yaml)?;

    // Validate the rule string parses correctly
    parse::parse_new_rule_key(rule).map_err(|e| {
        let hint = e.help().map(|h| format!(" {}", h)).unwrap_or_default();
        anyhow::anyhow!("invalid rule '{}': {}.{}", rule, e, hint)
    })?;

    // Check that the profile exists
    validate_profile_exists(yaml, profile)?;

    let lines: Vec<&str> = yaml.lines().collect();

    // Find the profile's rules block
    let (rules_line_idx, rules_indent) = find_rules_block(&lines, profile)?;

    // The rule entries are at rules_indent + 2 (e.g., if `rules:` is at indent 4, entries at 6)
    let entry_indent = rules_indent + 2;

    // Format the rule as a YAML mapping key (trailing colon)
    let rule_trimmed = rule.trim();
    let rule_key = if rule_trimmed.ends_with(':') {
        rule_trimmed.to_string()
    } else {
        format!("{}:", rule_trimmed)
    };

    let new_line = format!("{}{}", " ".repeat(entry_indent), rule_key);

    // Check if the rule already exists (idempotent)
    let rule_without_colon = rule_key.strip_suffix(':').unwrap_or(&rule_key);
    for &line in &lines[(rules_line_idx + 1)..] {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        let line_indent = get_indent(line);
        if line_indent < entry_indent {
            break; // Left the rules block
        }
        if line_indent == entry_indent {
            let key_part = stripped.strip_suffix(':').unwrap_or(stripped);
            if key_part == rule_without_colon {
                // Rule already exists — idempotent, return unchanged
                return Ok(yaml.to_string());
            }
        }
    }

    // Find the insertion point: after the last entry in this rules block
    let mut insert_idx = rules_line_idx + 1;
    for (i, &line) in lines.iter().enumerate().skip(rules_line_idx + 1) {
        let stripped = line.trim();
        if stripped.is_empty() {
            // Empty lines within the block — keep scanning
            insert_idx = i + 1;
            continue;
        }
        if stripped.starts_with('#') {
            // Comment lines within the block — keep scanning
            insert_idx = i + 1;
            continue;
        }
        let line_indent = get_indent(line);
        if line_indent < entry_indent {
            // We've exited the rules block
            break;
        }
        insert_idx = i + 1;
    }

    // Build the modified text
    let mut result: Vec<String> = lines[..insert_idx].iter().map(|s| s.to_string()).collect();
    result.push(new_line);
    // Append constraint lines indented one level deeper than the rule key
    for constraint_line in constraints.to_yaml_lines(entry_indent + 2) {
        result.push(constraint_line);
    }
    for line in &lines[insert_idx..] {
        result.push(line.to_string());
    }

    // Reconstruct the YAML text
    let modified = reconstruct_yaml(&result, yaml.ends_with('\n'));

    // Re-parse to validate the result
    parse::parse_yaml(&modified)
        .map_err(|e| anyhow::anyhow!("modified YAML failed to parse: {}. This is a bug.", e))?;

    Ok(modified)
}

/// Remove a rule from a profile's rules block, preserving comments.
/// Returns the modified YAML text.
pub fn remove_rule(yaml: &str, profile: &str, rule: &str) -> Result<String> {
    ensure_new_format(yaml)?;

    // Check that the profile exists
    validate_profile_exists(yaml, profile)?;

    let lines: Vec<&str> = yaml.lines().collect();

    // Find the profile's rules block
    let (rules_line_idx, rules_indent) = find_rules_block(&lines, profile)?;
    let entry_indent = rules_indent + 2;

    // Normalize the rule for matching
    let rule_trimmed = rule.trim();
    let rule_normalized = rule_trimmed.strip_suffix(':').unwrap_or(rule_trimmed);

    // Find the rule line and any constraint lines below it
    let mut found_start: Option<usize> = None;
    let mut found_end: Option<usize> = None;

    for (i, &line) in lines.iter().enumerate().skip(rules_line_idx + 1) {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        let line_indent = get_indent(line);
        if line_indent < entry_indent {
            break;
        }
        if line_indent == entry_indent {
            if found_start.is_some() {
                // We've hit the next rule — stop
                found_end = Some(i);
                break;
            }
            let key_part = stripped.strip_suffix(':').unwrap_or(stripped);
            if key_part == rule_normalized {
                found_start = Some(i);
            }
        } else if found_start.is_some() {
            // This is a constraint line belonging to the matched rule — it'll be removed
        }
    }

    let start = match found_start {
        Some(s) => s,
        None => bail!("rule '{}' not found in profile '{}'", rule, profile),
    };

    // If we didn't find the end by hitting the next rule, scan to find where the block ends
    let end = found_end.unwrap_or_else(|| {
        let mut e = start + 1;
        for (i, &line) in lines.iter().enumerate().skip(start + 1) {
            let stripped = line.trim();
            if stripped.is_empty() || stripped.starts_with('#') {
                e = i + 1;
                continue;
            }
            let line_indent = get_indent(line);
            if line_indent <= entry_indent {
                break;
            }
            e = i + 1;
        }
        e
    });

    // Remove lines [start..end]
    let mut result: Vec<String> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if i >= start && i < end {
            continue;
        }
        result.push(line.to_string());
    }

    let modified = reconstruct_yaml(&result, yaml.ends_with('\n'));

    // Re-parse to validate
    parse::parse_yaml(&modified)
        .map_err(|e| anyhow::anyhow!("modified YAML failed to parse: {}. This is a bug.", e))?;

    Ok(modified)
}

/// Resolve the target profile: use the provided override or fall back to the active profile.
pub fn resolve_profile(yaml: &str, profile_override: Option<&str>) -> Result<String> {
    match profile_override {
        Some(p) => Ok(p.to_string()),
        None => active_profile(yaml),
    }
}

/// Find the `rules:` line within a given profile block.
///
/// Returns `(line_index, indent_of_rules_key)`.
fn find_rules_block(lines: &[&str], profile: &str) -> Result<(usize, usize)> {
    // Step 1: Find `profiles:` at indent 0
    let profiles_idx = lines
        .iter()
        .position(|line| {
            let stripped = line.trim();
            stripped == "profiles:" && get_indent(line) == 0
        })
        .ok_or_else(|| anyhow::anyhow!("no 'profiles:' key found in policy"))?;

    // Step 2: Find `  {profile}:` at indent 2
    let profile_key = format!("{}:", profile);
    let mut profile_idx = None;
    for (i, &line) in lines.iter().enumerate().skip(profiles_idx + 1) {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        let indent = get_indent(line);
        if indent == 0 {
            break; // Left the profiles block
        }
        if indent == 2 && stripped == profile_key {
            profile_idx = Some(i);
            break;
        }
    }
    let profile_idx = profile_idx
        .ok_or_else(|| anyhow::anyhow!("profile '{}' not found in profiles block", profile))?;

    // Step 3: Find `    rules:` at indent 4 within this profile
    let mut rules_idx = None;
    for (i, &line) in lines.iter().enumerate().skip(profile_idx + 1) {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        let indent = get_indent(line);
        if indent <= 2 {
            break; // Left this profile block
        }
        if indent == 4 && stripped == "rules:" {
            rules_idx = Some(i);
            break;
        }
    }

    match rules_idx {
        Some(idx) => Ok((idx, 4)),
        None => {
            bail!(
                "profile '{}' has no 'rules:' block. Add `    rules:` to the profile first.",
                profile
            );
        }
    }
}

/// Get summary information about the policy for the `show` command.
pub struct PolicyInfo {
    pub default_permission: String,
    pub active_profile: String,
    pub profiles: Vec<String>,
}

/// Extract policy info from the YAML text.
pub fn policy_info(yaml: &str) -> Result<PolicyInfo> {
    ensure_new_format(yaml)?;

    let profile = active_profile(yaml)?;
    let names = profile_names(yaml)?;

    // Get default permission
    let value: serde_yaml::Value =
        serde_yaml::from_str(yaml).context("failed to parse policy YAML")?;
    let permission = value
        .as_mapping()
        .and_then(|m| m.get(serde_yaml::Value::String("default".into())))
        .and_then(|v| v.as_mapping())
        .and_then(|m| m.get(serde_yaml::Value::String("permission".into())))
        .and_then(|v| v.as_str())
        .unwrap_or("ask")
        .to_string();

    Ok(PolicyInfo {
        default_permission: permission,
        active_profile: profile,
        profiles: names,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_POLICY: &str = r#"# Test policy
default:
  permission: ask
  profile: main

profiles:
  base:
    rules:
      deny bash rm *:
  main:
    include: [base]
    rules:
      # Git rules
      allow bash git *:
      deny bash git push*:
"#;

    #[test]
    fn test_add_rule_basic() {
        let result = add_rule(
            TEST_POLICY,
            "main",
            "allow bash cargo *",
            &InlineConstraintArgs::default(),
        )
        .unwrap();
        assert!(result.contains("allow bash cargo *:"));
        // Original rules still present
        assert!(result.contains("allow bash git *:"));
        assert!(result.contains("deny bash git push*:"));
        // Comment preserved
        assert!(result.contains("# Git rules"));
        assert!(result.contains("# Test policy"));
    }

    #[test]
    fn test_add_rule_idempotent() {
        let result = add_rule(
            TEST_POLICY,
            "main",
            "allow bash git *",
            &InlineConstraintArgs::default(),
        )
        .unwrap();
        assert_eq!(result, TEST_POLICY);
    }

    #[test]
    fn test_add_rule_to_base_profile() {
        let result = add_rule(
            TEST_POLICY,
            "base",
            "deny bash sudo *",
            &InlineConstraintArgs::default(),
        )
        .unwrap();
        assert!(result.contains("deny bash sudo *:"));
        assert!(result.contains("deny bash rm *:"));
    }

    #[test]
    fn test_add_rule_invalid_rule() {
        let result = add_rule(
            TEST_POLICY,
            "main",
            "invalid",
            &InlineConstraintArgs::default(),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid rule"));
    }

    #[test]
    fn test_add_rule_unknown_profile() {
        let result = add_rule(
            TEST_POLICY,
            "nonexistent",
            "allow bash git *",
            &InlineConstraintArgs::default(),
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not found"), "got: {}", err);
    }

    #[test]
    fn test_add_rule_old_format_error() {
        let old_yaml = "default: ask\nrules:\n  - allow bash git *\n";
        let result = add_rule(
            old_yaml,
            "main",
            "allow bash cargo *",
            &InlineConstraintArgs::default(),
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Old policy format")
        );
    }

    #[test]
    fn test_remove_rule_basic() {
        let result = remove_rule(TEST_POLICY, "main", "deny bash git push*").unwrap();
        assert!(!result.contains("deny bash git push*:"));
        // Other rules still present
        assert!(result.contains("allow bash git *:"));
        assert!(result.contains("# Git rules"));
    }

    #[test]
    fn test_remove_rule_not_found() {
        let result = remove_rule(TEST_POLICY, "main", "allow bash cargo *");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_remove_rule_with_constraints() {
        let yaml = r#"default:
  permission: ask
  profile: main

profiles:
  main:
    rules:
      allow bash *:
        fs:
          read + write: subpath(.)
      deny bash rm *:
"#;
        let result = remove_rule(yaml, "main", "allow bash *").unwrap();
        assert!(!result.contains("allow bash *:"));
        assert!(!result.contains("subpath(.)"));
        // Other rules still present
        assert!(result.contains("deny bash rm *:"));
    }

    #[test]
    fn test_remove_rule_old_format_error() {
        let old_yaml = "default: ask\nrules:\n  - allow bash git *\n";
        let result = remove_rule(old_yaml, "main", "allow bash git *");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Old policy format")
        );
    }

    #[test]
    fn test_remove_rule_unknown_profile() {
        let result = remove_rule(TEST_POLICY, "nonexistent", "allow bash git *");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_is_new_format() {
        assert!(is_new_format(TEST_POLICY));
        assert!(!is_new_format(
            "default: ask\nrules:\n  - allow bash git *\n"
        ));
    }

    #[test]
    fn test_active_profile() {
        assert_eq!(active_profile(TEST_POLICY).unwrap(), "main");
    }

    #[test]
    fn test_profile_names() {
        let names = profile_names(TEST_POLICY).unwrap();
        assert!(names.contains(&"base".to_string()));
        assert!(names.contains(&"main".to_string()));
    }

    #[test]
    fn test_policy_info() {
        let info = policy_info(TEST_POLICY).unwrap();
        assert_eq!(info.default_permission, "ask");
        assert_eq!(info.active_profile, "main");
        assert!(info.profiles.contains(&"main".to_string()));
        assert!(info.profiles.contains(&"base".to_string()));
    }

    #[test]
    fn test_resolve_profile_default() {
        let profile = resolve_profile(TEST_POLICY, None).unwrap();
        assert_eq!(profile, "main");
    }

    #[test]
    fn test_resolve_profile_override() {
        let profile = resolve_profile(TEST_POLICY, Some("base")).unwrap();
        assert_eq!(profile, "base");
    }

    #[test]
    fn test_add_then_remove_roundtrip() {
        let added = add_rule(
            TEST_POLICY,
            "main",
            "allow bash cargo build *",
            &InlineConstraintArgs::default(),
        )
        .unwrap();
        assert!(added.contains("allow bash cargo build *:"));
        let removed = remove_rule(&added, "main", "allow bash cargo build *").unwrap();
        assert!(!removed.contains("allow bash cargo build *:"));
        // Original content still valid
        assert!(removed.contains("allow bash git *:"));
    }

    #[test]
    fn test_add_rule_with_trailing_colon() {
        // Rule provided with trailing colon should work the same
        let result = add_rule(
            TEST_POLICY,
            "main",
            "allow bash cargo *:",
            &InlineConstraintArgs::default(),
        )
        .unwrap();
        assert!(result.contains("allow bash cargo *:"));
    }

    #[test]
    fn test_add_rule_default_policy() {
        // Test against the actual default policy template
        let default_policy = include_str!("../default_policy.yaml");
        let result = add_rule(
            default_policy,
            "main",
            "allow bash cargo *",
            &InlineConstraintArgs::default(),
        )
        .unwrap();
        assert!(result.contains("allow bash cargo *:"));
    }

    #[test]
    fn test_remove_rule_default_policy() {
        let default_policy = include_str!("../default_policy.yaml");
        let result = remove_rule(default_policy, "main", "deny bash git push*").unwrap();
        assert!(!result.contains("deny bash git push*:"));
    }

    #[test]
    fn test_add_rule_with_url_constraints() {
        let constraints = InlineConstraintArgs {
            url: vec!["github.com".into(), "!evil.com".into()],
            ..Default::default()
        };
        let result = add_rule(TEST_POLICY, "main", "allow webfetch *", &constraints).unwrap();
        assert!(result.contains("allow webfetch *:"));
        assert!(result.contains(r#"url: ["github.com", "!evil.com"]"#));
    }

    #[test]
    fn test_add_rule_with_args_constraints() {
        let constraints = InlineConstraintArgs {
            args: vec!["--dry-run".into(), "!-delete".into()],
            ..Default::default()
        };
        let _existing = add_rule(TEST_POLICY, "main", "allow bash git *", &constraints).unwrap();
        // Idempotency check matches on the rule key, so use a different rule:
        let result = add_rule(TEST_POLICY, "main", "allow bash cargo *", &constraints).unwrap();
        assert!(result.contains("allow bash cargo *:"));
        assert!(result.contains(r#"args: ["--dry-run", "!-delete"]"#));
    }

    #[test]
    fn test_add_rule_with_pipe_redirect() {
        let constraints = InlineConstraintArgs {
            pipe: Some(false),
            redirect: Some(false),
            ..Default::default()
        };
        let result = add_rule(TEST_POLICY, "main", "deny bash curl *", &constraints).unwrap();
        assert!(result.contains("deny bash curl *:"));
        assert!(result.contains("pipe: false"));
        assert!(result.contains("redirect: false"));
    }

    #[test]
    fn test_add_rule_with_fs_constraint() {
        let constraints = InlineConstraintArgs {
            fs: vec!["full:subpath(~/Library/Caches)".into()],
            ..Default::default()
        };
        let result = add_rule(TEST_POLICY, "main", "allow * *", &constraints).unwrap();
        assert!(result.contains("allow * *:"));
        assert!(result.contains("fs:"));
        assert!(result.contains("full: subpath(~/Library/Caches)"));
    }

    #[test]
    fn test_add_rule_with_multi_cap_fs() {
        let constraints = InlineConstraintArgs {
            fs: vec![
                "read+write:subpath(.)".into(),
                "execute:subpath(./bin)".into(),
            ],
            ..Default::default()
        };
        let result = add_rule(TEST_POLICY, "main", "allow bash *", &constraints).unwrap();
        assert!(result.contains("fs:"));
        assert!(result.contains("read+write: subpath(.)"));
        assert!(result.contains("execute: subpath(./bin)"));
    }

    #[test]
    fn test_add_rule_with_fs_and_url() {
        let constraints = InlineConstraintArgs {
            fs: vec!["read:subpath(.)".into()],
            url: vec!["github.com".into()],
            ..Default::default()
        };
        let result = add_rule(TEST_POLICY, "main", "allow webfetch *", &constraints).unwrap();
        assert!(result.contains("fs:"));
        assert!(result.contains("read: subpath(.)"));
        assert!(result.contains(r#"url: ["github.com"]"#));
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
