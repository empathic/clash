//! Import permissions from a coding agent's settings and generate a Clash policy.

use anyhow::{Context, Result};

use claude_settings::permission::{Permission, PermissionPattern};

use crate::agents::AgentKind;
use crate::settings::ClashSettings;
use crate::style;
use crate::ui;

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
// Starlark code generation
// ---------------------------------------------------------------------------

use std::collections::BTreeSet;

use clash_starlark::codegen::ast::{DictEntry, Expr, Stmt};
use clash_starlark::codegen::builder::*;

/// Generate a minimal Starlark policy from a posture choice.
pub(crate) fn generate_starlark_from_posture(posture: Posture) -> String {
    let effect_name = posture.default_effect();
    let preset = posture.sandbox_preset();

    let stmts = vec![
        load_builtin(),
        load_std(&["policy", "settings", "allow", "ask", "deny"]),
        load_sandboxes(&[preset]),
        Stmt::Blank,
        Stmt::Expr(settings(
            Expr::call(effect_name, vec![]),
            Some(Expr::ident(preset)),
        )),
        Stmt::Blank,
        Stmt::Expr(policy(
            "default",
            Expr::call(effect_name, vec![]),
            vec![],
            None,
        )),
    ];

    clash_starlark::codegen::serialize(&stmts)
}

/// Build a `when({"Bash": {("git","cargo"): {glob("**"): effect}}})` rule
/// from a list of command segments. Multi-segment commands are flattened to
/// the first segment — `glob("**")` handles subcommand matching.
fn build_bash_rules(commands: &[Vec<String>], effect: Expr) -> Expr {
    let mut bins: BTreeSet<&str> = BTreeSet::new();
    for cmd in commands {
        if let Some(first) = cmd.first() {
            bins.insert(first.as_str());
        }
    }
    let sorted: Vec<&str> = bins.into_iter().collect();

    let key: MatchKey = if sorted.len() == 1 {
        sorted[0].into()
    } else {
        sorted.as_slice().into()
    };

    let glob_entry = DictEntry::new(
        Expr::call("glob", vec![Expr::string("**")]),
        effect,
    );
    let glob_dict = Expr::dict(vec![glob_entry]);

    match_rule(vec![(
        "Bash".into(),
        MatchValue::Nested(vec![(key, MatchValue::Effect(glob_dict))]),
    )])
}

/// Generate a full Starlark policy from analyzed settings.
pub(crate) fn generate_starlark_from_analysis(analysis: &ImportAnalysis) -> String {
    let mut stmts = vec![
        Stmt::comment("Imported from Claude Code settings"),
        load_builtin(),
        load_std(&[
            "when", "policy", "settings", "sandbox", "cwd", "home", "allow", "ask", "deny",
        ]),
        load_sandboxes(&["project"]),
        Stmt::Blank,
    ];

    // Sandbox for file-access tools
    let rw = clash_starlark::kwargs!(read = true, write = true);
    let fs_box = sandbox(
        "cwd",
        vec![(
            "fs",
            Expr::list(vec![
                cwd(clash_starlark::kwargs!(follow_worktrees = true))
                    .recurse()
                    .allow_kwargs(rw.clone()),
                home().child(".claude").recurse().allow_kwargs(rw),
            ]),
        )],
    );
    stmts.push(Stmt::comment(
        "Sandbox for file-access tools (scoped to project + ~/.claude)",
    ));
    stmts.push(Stmt::assign("project_files", fs_box));
    stmts.push(Stmt::Blank);

    stmts.push(Stmt::Expr(settings(
        Expr::ident("ask"),
        Some(Expr::ident("project")),
    )));
    stmts.push(Stmt::Blank);

    // Build rules list
    let mut rules: Vec<Expr> = vec![];

    // 1. File denies first
    for (tool, path) in &analysis.file_denies {
        let expr = match_rule(vec![(
            tool.as_str().into(),
            MatchValue::Nested(vec![(
                path.as_str().into(),
                MatchValue::Effect(deny()),
            )]),
        )]);
        rules.push(Expr::commented(&format!("deny {} on {}", tool, path), expr));
    }

    // 2. Bash denies
    if !analysis.bash_denies.is_empty() {
        let expr = build_bash_rules(&analysis.bash_denies, deny());
        rules.push(Expr::commented("denied bash commands", expr));
    }

    // 3. Bash allows
    if !analysis.bash_allows.is_empty() {
        let expr = build_bash_rules(&analysis.bash_allows, allow_with_sandbox(Expr::ident("project")));
        rules.push(Expr::commented("allowed bash commands (sandboxed)", expr));
    }

    // 4. Bash asks
    if !analysis.bash_asks.is_empty() {
        let expr = build_bash_rules(&analysis.bash_asks, ask());
        rules.push(Expr::commented("bash commands requiring confirmation", expr));
    }

    // 5. Tool denies
    if !analysis.tool_denies.is_empty() {
        let names: Vec<&str> = analysis.tool_denies.iter().map(|s| s.as_str()).collect();
        let expr = tool_match(&names, deny());
        rules.push(Expr::commented("denied tools", expr));
    }

    // 6. Read tools with project_files sandbox
    let read_tools: Vec<&str> = ["Read", "Glob", "Grep"]
        .iter()
        .filter(|t| analysis.tool_allows.contains(&t.to_string()))
        .copied()
        .collect();
    if !read_tools.is_empty() {
        let expr = tool_match(&read_tools, allow_with_sandbox(Expr::ident("project_files")));
        rules.push(Expr::commented("read-only fs tools", expr));
    }

    // 7. Write tools with project_files sandbox
    let write_tools: Vec<&str> = ["Write", "Edit", "NotebookEdit"]
        .iter()
        .filter(|t| analysis.tool_allows.contains(&t.to_string()))
        .copied()
        .collect();
    if !write_tools.is_empty() {
        let expr = tool_match(&write_tools, allow_with_sandbox(Expr::ident("project_files")));
        rules.push(Expr::commented("write fs tools", expr));
    }

    // 8. Other tool allows
    let fs_tools: &[&str] = &["Read", "Glob", "Grep", "Write", "Edit", "NotebookEdit"];
    let other_allows: Vec<&str> = analysis
        .tool_allows
        .iter()
        .filter(|t| !fs_tools.contains(&t.as_str()))
        .map(|s| s.as_str())
        .collect();
    if !other_allows.is_empty() {
        let expr = tool_match(&other_allows, allow());
        rules.push(Expr::commented("other allowed tools", expr));
    }

    // 9. Tool asks
    if !analysis.tool_asks.is_empty() {
        let names: Vec<&str> = analysis.tool_asks.iter().map(|s| s.as_str()).collect();
        let expr = tool_match(&names, ask());
        rules.push(Expr::commented("tools requiring confirmation", expr));
    }

    stmts.push(Stmt::Expr(policy(
        "imported",
        Expr::ident("ask"),
        rules,
        None,
    )));

    clash_starlark::codegen::serialize(&stmts)
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Import settings from the agent and generate a Clash policy.
pub fn run(agent: Option<AgentKind>) -> Result<()> {
    let agent = match agent {
        Some(a) => a,
        None => *crate::dialog::select::<AgentKind>("Which coding agent are you using?")?,
    };

    // Read effective Claude settings
    let claude = claude_settings::ClaudeSettings::new();
    let settings = claude.effective().unwrap_or_default();
    let analysis = analyze_settings(&settings);

    // Generate policy
    let policy_content = if analysis.needs_posture_prompt() {
        if analysis.bypass_permissions {
            ui::info("Claude Code is running with bypass_permissions enabled.");
        } else {
            ui::info("No existing permissions found in Claude Code settings.");
        }
        println!();
        let posture = crate::dialog::select::<Posture>("Pick a starting posture")?;
        generate_starlark_from_posture(*posture)
    } else {
        print_import_summary(&analysis);
        generate_starlark_from_analysis(&analysis)
    };

    // Write policy file
    let policy_path = write_policy(&policy_content)?;
    ui::success(&format!("Policy written to {}", policy_path.display()));

    // Install agent plugin
    super::init::install_agent_plugin(agent)?;

    // Install statusline for Claude
    if agent == AgentKind::Claude {
        if let Err(e) = super::statusline::install() {
            tracing::warn!(error = %e, "Could not install status line");
        }
    }

    // Print next steps
    println!();
    println!(
        "  Run {} to tweak your policy.",
        style::bold("clash policy edit")
    );
    println!(
        "  Run {} to verify the setup.",
        style::bold(&format!("clash doctor --agent {agent}"))
    );

    Ok(())
}

/// Print a summary of what was found in the settings.
fn print_import_summary(analysis: &ImportAnalysis) {
    println!();
    ui::info("Importing permissions from Claude Code settings:");

    if !analysis.bash_allows.is_empty() {
        let bins: Vec<&str> = analysis
            .bash_allows
            .iter()
            .filter_map(|segs| segs.first().map(|s| s.as_str()))
            .collect();
        ui::success(&format!("  Bash commands: {}", bins.join(", ")));
    }

    let all_tools: Vec<&str> = analysis
        .tool_allows
        .iter()
        .chain(analysis.tool_asks.iter())
        .map(|s| s.as_str())
        .collect();
    if !all_tools.is_empty() {
        ui::success(&format!("  Tools: {}", all_tools.join(", ")));
    }

    if !analysis.file_denies.is_empty() {
        let denied: Vec<String> = analysis
            .file_denies
            .iter()
            .map(|(tool, path)| format!("{tool}({path})"))
            .collect();
        ui::success(&format!("  Denied: {}", denied.join(", ")));
    }

    if !analysis.skipped.is_empty() {
        ui::warn(&format!(
            "  Skipped {} unsupported patterns: {}",
            analysis.skipped.len(),
            analysis.skipped.join(", ")
        ));
    }

    println!();
}

/// Write a policy string to the user's policy file.
fn write_policy(content: &str) -> Result<std::path::PathBuf> {
    let policy_path = ClashSettings::policy_file()
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".clash")
                .join("policy.star")
        })
        .with_extension("star");

    if let Some(parent) = policy_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }

    std::fs::write(&policy_path, content)
        .with_context(|| format!("writing policy to {}", policy_path.display()))?;

    Ok(policy_path)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialog::SelectItem;

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

    #[test]
    fn test_generate_compiles() {
        use claude_settings::permission::PermissionSet;
        let perms = PermissionSet::new()
            .allow("Bash(git:*)")
            .allow("Bash(cargo:*)")
            .allow("Bash(npm:*)")
            .allow("Read")
            .allow("Glob")
            .allow("Grep")
            .allow("Write")
            .allow("Edit")
            .deny("Read(.env)");
        let settings = claude_settings::Settings::default().with_permissions(perms);
        let analysis = analyze_settings(&settings);
        let starlark = generate_starlark_from_analysis(&analysis);

        let output = clash_starlark::evaluate(&starlark, "<test>", std::path::Path::new("."))
            .expect("starlark evaluation failed");
        crate::policy::compile::compile_to_tree(&output.json)
            .expect("generated policy must compile");
    }

    #[test]
    fn test_generate_posture_compiles() {
        for posture in Posture::variants() {
            let starlark = generate_starlark_from_posture(*posture);
            let output = clash_starlark::evaluate(&starlark, "<test>", std::path::Path::new("."))
                .unwrap_or_else(|e| panic!("posture {:?} failed to evaluate: {e}", posture));
            crate::policy::compile::compile_to_tree(&output.json)
                .unwrap_or_else(|e| panic!("posture {:?} failed to compile: {e}", posture));
        }
    }

    #[test]
    fn test_generate_groups_bash_prefixes() {
        use claude_settings::permission::PermissionSet;
        let perms = PermissionSet::new()
            .allow("Bash(git:*)")
            .allow("Bash(cargo:*)")
            .allow("Bash(npm:*)");
        let settings = claude_settings::Settings::default().with_permissions(perms);
        let analysis = analyze_settings(&settings);
        let starlark = generate_starlark_from_analysis(&analysis);

        assert!(
            starlark.contains("(\"cargo\", \"git\", \"npm\")"),
            "expected grouped tuple key, got:\n{starlark}"
        );
    }

    #[test]
    fn test_generate_denies_first() {
        use claude_settings::permission::PermissionSet;
        let perms = PermissionSet::new()
            .allow("Read")
            .deny("Read(.env)");
        let settings = claude_settings::Settings::default().with_permissions(perms);
        let analysis = analyze_settings(&settings);
        let starlark = generate_starlark_from_analysis(&analysis);

        let deny_pos = starlark.find("deny()").expect("should contain deny");
        let allow_pos = starlark.find("allow(").expect("should contain allow");
        assert!(
            deny_pos < allow_pos,
            "deny rules should come before allow rules"
        );
    }
}
