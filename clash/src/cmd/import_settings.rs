//! Import permissions from a coding agent's settings and generate a Clash policy.

use anyhow::Result;

use claude_settings::permission::{Permission, PermissionPattern};

use crate::agents::AgentKind;

// ---------------------------------------------------------------------------
// Posture — for the interactive prompt when nothing to import
// ---------------------------------------------------------------------------

/// A starting posture for policy generation when no permissions exist to import.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Posture {
    Strict,
    Balanced,
    Permissive,
}

impl crate::dialog::SelectItem for Posture {
    fn label(&self) -> &str {
        match self {
            Posture::Strict => "Strict",
            Posture::Balanced => "Balanced",
            Posture::Permissive => "Permissive",
        }
    }

    fn description(&self) -> &str {
        match self {
            Posture::Strict => "deny by default, read-only project access",
            Posture::Balanced => "ask by default, read+write project access",
            Posture::Permissive => "allow by default, full workspace access (sandboxed)",
        }
    }

    fn variants() -> &'static [Self] {
        &[Posture::Strict, Posture::Balanced, Posture::Permissive]
    }
}

impl Posture {
    /// The Starlark default effect for this posture.
    fn default_effect(&self) -> &str {
        match self {
            Posture::Strict => "deny",
            Posture::Balanced => "ask",
            Posture::Permissive => "allow",
        }
    }

    /// The sandbox preset name for this posture.
    fn sandbox_preset(&self) -> &str {
        match self {
            Posture::Strict => "readonly",
            Posture::Balanced => "project",
            Posture::Permissive => "workspace",
        }
    }
}

// ---------------------------------------------------------------------------
// Settings analysis
// ---------------------------------------------------------------------------

/// Categorized analysis of a Claude Code settings file.
#[derive(Debug, Default)]
struct ImportAnalysis {
    /// Tool-only allows (e.g., "Edit" with no pattern).
    tool_allows: Vec<String>,
    /// Tool-only denies.
    tool_denies: Vec<String>,
    /// Tool-only asks.
    tool_asks: Vec<String>,
    /// Bash prefix allows — each entry is a list of command segments.
    /// e.g., "Bash(git:*)" → vec!["git"], "Bash(cargo check:*)" → vec!["cargo", "check"]
    bash_allows: Vec<Vec<String>>,
    /// Bash prefix denies.
    bash_denies: Vec<Vec<String>>,
    /// Bash prefix asks.
    bash_asks: Vec<Vec<String>>,
    /// Exact file path denies (tool, path).
    file_denies: Vec<(String, String)>,
    /// Whether bypass_permissions is set.
    bypass_permissions: bool,
    /// Whether the permissions set is empty (nothing to import).
    is_empty: bool,
    /// Permissions that were skipped (globs, MCP tools) — for user warnings.
    skipped: Vec<String>,
}

impl ImportAnalysis {
    /// Returns true if there are no meaningful permissions to import.
    fn needs_posture_prompt(&self) -> bool {
        self.is_empty || self.bypass_permissions
    }
}

/// Analyze Claude Code settings and classify permissions into categories.
fn analyze_settings(settings: &claude_settings::Settings) -> ImportAnalysis {
    let perms = &settings.permissions;
    let mut analysis = ImportAnalysis {
        bypass_permissions: settings.bypass_permissions.unwrap_or(false),
        is_empty: perms.is_empty(),
        ..Default::default()
    };

    if analysis.is_empty || analysis.bypass_permissions {
        return analysis;
    }

    for perm in perms.allowed() {
        classify_permission(perm, "allow", &mut analysis);
    }
    for perm in perms.denied() {
        classify_permission(perm, "deny", &mut analysis);
    }
    for perm in perms.asking() {
        classify_permission(perm, "ask", &mut analysis);
    }

    analysis
}

/// Classify a single permission into the appropriate analysis bucket.
fn classify_permission(perm: &Permission, effect: &str, analysis: &mut ImportAnalysis) {
    let tool = perm.tool();

    // Skip MCP tools
    if tool.starts_with("mcp__") {
        analysis.skipped.push(perm.to_string());
        return;
    }

    match perm.pattern() {
        None => {
            // Tool-only permission (e.g., "Read", "Edit")
            match effect {
                "allow" => analysis.tool_allows.push(tool.to_string()),
                "deny" => analysis.tool_denies.push(tool.to_string()),
                "ask" => analysis.tool_asks.push(tool.to_string()),
                _ => {}
            }
        }
        Some(PermissionPattern::Prefix(prefix)) if tool == "Bash" => {
            // Bash prefix (e.g., "Bash(git:*)" or "Bash(cargo check:*)")
            let segments: Vec<String> = prefix.split_whitespace().map(String::from).collect();
            match effect {
                "allow" => analysis.bash_allows.push(segments),
                "deny" => analysis.bash_denies.push(segments),
                "ask" => analysis.bash_asks.push(segments),
                _ => {}
            }
        }
        Some(PermissionPattern::Exact(path)) => {
            // Exact file match (e.g., "Read(.env)")
            match effect {
                "deny" => analysis.file_denies.push((tool.to_string(), path.clone())),
                // Exact allows/asks on file tools are unusual, treat as tool-level
                "allow" => analysis.tool_allows.push(tool.to_string()),
                "ask" => analysis.tool_asks.push(tool.to_string()),
                _ => {}
            }
        }
        Some(PermissionPattern::Glob(_)) => {
            // Glob patterns — skip with warning (no direct Clash equivalent)
            analysis.skipped.push(perm.to_string());
        }
        Some(PermissionPattern::Prefix(_)) => {
            // Non-Bash prefix (unusual) — treat as tool-level
            match effect {
                "allow" => analysis.tool_allows.push(tool.to_string()),
                "deny" => analysis.tool_denies.push(tool.to_string()),
                "ask" => analysis.tool_asks.push(tool.to_string()),
                _ => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point (stub — implemented in Task 9)
// ---------------------------------------------------------------------------

/// Import settings from the agent and generate a Clash policy.
pub fn run(agent: Option<AgentKind>) -> Result<()> {
    let _agent = match agent {
        Some(a) => a,
        None => *crate::dialog::select::<AgentKind>("Which coding agent are you using?")?,
    };

    anyhow::bail!("import not yet implemented — use `clash init --no-import` for now")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_empty_settings() {
        let settings = claude_settings::Settings::default();
        let analysis = analyze_settings(&settings);
        assert!(analysis.is_empty);
        assert!(analysis.needs_posture_prompt());
    }

    #[test]
    fn test_analyze_bypass_permissions() {
        let settings = claude_settings::Settings::default().with_bypass_permissions(true);
        let analysis = analyze_settings(&settings);
        assert!(analysis.bypass_permissions);
        assert!(analysis.needs_posture_prompt());
    }

    #[test]
    fn test_analyze_basic_permissions() {
        use claude_settings::permission::PermissionSet;
        let perms = PermissionSet::new()
            .allow("Bash(git:*)")
            .allow("Read")
            .deny("Read(.env)")
            .ask("Write");
        let settings = claude_settings::Settings::default().with_permissions(perms);
        let analysis = analyze_settings(&settings);

        assert!(!analysis.needs_posture_prompt());
        assert_eq!(analysis.bash_allows, vec![vec!["git".to_string()]]);
        assert!(analysis.tool_allows.contains(&"Read".to_string()));
        assert_eq!(analysis.file_denies, vec![("Read".into(), ".env".into())]);
        assert!(analysis.tool_asks.contains(&"Write".to_string()));
    }

    #[test]
    fn test_analyze_multi_word_prefix() {
        use claude_settings::permission::PermissionSet;
        let perms = PermissionSet::new().allow("Bash(cargo check:*)");
        let settings = claude_settings::Settings::default().with_permissions(perms);
        let analysis = analyze_settings(&settings);

        assert_eq!(
            analysis.bash_allows,
            vec![vec!["cargo".to_string(), "check".to_string()]]
        );
    }

    #[test]
    fn test_analyze_skips_mcp() {
        use claude_settings::permission::PermissionSet;
        let perms = PermissionSet::new()
            .allow("mcp__server__tool")
            .allow("Read");
        let settings = claude_settings::Settings::default().with_permissions(perms);
        let analysis = analyze_settings(&settings);

        assert_eq!(analysis.tool_allows, vec!["Read".to_string()]);
        assert_eq!(analysis.skipped.len(), 1);
        assert!(analysis.skipped[0].contains("mcp__"));
    }

    #[test]
    fn test_analyze_skips_globs() {
        use claude_settings::permission::PermissionSet;
        let perms = PermissionSet::new()
            .allow("Read(**/*.rs)")
            .allow("Edit");
        let settings = claude_settings::Settings::default().with_permissions(perms);
        let analysis = analyze_settings(&settings);

        assert_eq!(analysis.tool_allows, vec!["Edit".to_string()]);
        assert_eq!(analysis.skipped.len(), 1);
    }
}
