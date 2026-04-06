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
        self.is_empty || self.bypass_permissions || self.has_no_actionable_rules()
    }

    /// True when all permissions were skipped (e.g., only MCP/glob patterns).
    fn has_no_actionable_rules(&self) -> bool {
        self.tool_allows.is_empty()
            && self.tool_denies.is_empty()
            && self.tool_asks.is_empty()
            && self.bash_allows.is_empty()
            && self.bash_denies.is_empty()
            && self.bash_asks.is_empty()
            && self.file_denies.is_empty()
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

/// Deduplicate a Vec<String> in place, preserving order.
fn dedup_stable(v: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    v.retain(|item| seen.insert(item.clone()));
}

/// Generate a minimal Starlark policy from a posture choice.
fn generate_starlark_from_posture(posture: Posture, detection: &EcosystemDetection) -> String {
    let effect_name = posture.default_effect();
    let preset = posture.sandbox_preset();

    let mut stmts = vec![load_builtin(), load_sandboxes(&[preset])];
    stmts.push(Stmt::load(
        "@clash//claude_compat.star",
        &["from_claude_settings"],
    ));
    stmts.extend(detection.loads.iter().cloned());

    let eco_rules = crate::policy_gen::ecosystems::ecosystem_rules(&detection.ecosystems, preset);

    stmts.extend([
        Stmt::Blank,
        Stmt::Expr(settings(
            Expr::call(effect_name, vec![]),
            Some(Expr::ident(preset)),
        )),
        Stmt::Blank,
        Stmt::Expr({
            let mut all_rules = vec![Expr::call("from_claude_settings", vec![])];
            all_rules.extend(eco_rules);
            policy("default", Expr::call(effect_name, vec![]), all_rules, None)
        }),
    ]);

    clash_starlark::codegen::serialize(&stmts)
}

/// Build a `"Bash": {("git","cargo"): {glob("**"): effect}}` match entry
/// from a list of command segments. Multi-segment commands are flattened to
/// the first segment — `glob("**")` handles subcommand matching.
fn build_bash_entry(commands: &[Vec<String>], effect: Expr) -> (MatchKey, MatchValue) {
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

    let glob_entry = DictEntry::new(Expr::call("glob", vec![Expr::string("**")]), effect);
    let glob_dict = Expr::dict(vec![glob_entry]);

    (
        "Bash".into(),
        MatchValue::Nested(vec![(key, MatchValue::Effect(glob_dict))]),
    )
}

/// Build a match entry for one or more tool names with the given effect.
fn tool_entry(names: &[&str], effect: Expr) -> (MatchKey, MatchValue) {
    let key: MatchKey = if names.len() == 1 {
        MatchKey::Single(names[0].to_owned())
    } else {
        MatchKey::Tuple(names.iter().map(|s| (*s).to_owned()).collect())
    };
    (key, MatchValue::Effect(effect))
}

/// Generate a full Starlark policy from analyzed settings.
fn generate_starlark_from_analysis(
    analysis: &mut ImportAnalysis,
    detection: &EcosystemDetection,
) -> String {
    // Deduplicate tool lists — the same tool name can appear multiple times
    // when a tool has both bare and patterned permissions (e.g. "Bash" +
    // "Bash(exact_path)").
    dedup_stable(&mut analysis.tool_allows);
    dedup_stable(&mut analysis.tool_denies);
    dedup_stable(&mut analysis.tool_asks);
    let mut stmts = vec![
        Stmt::comment("Imported from Claude Code settings"),
        load_builtin(),
    ];
    stmts.push(Stmt::load(
        "@clash//claude_compat.star",
        &["from_claude_settings"],
    ));
    stmts.extend(detection.loads.iter().cloned());
    stmts.push(Stmt::Blank);

    use crate::policy_gen::sandboxes::{self, PROJECT_FILES_SANDBOX};
    stmts.extend(sandboxes::project_files_sandbox());
    stmts.push(Stmt::Blank);

    stmts.push(Stmt::Expr(settings(
        ask(),
        Some(Expr::ident(PROJECT_FILES_SANDBOX)),
    )));
    stmts.push(Stmt::Blank);

    // Collect ecosystem binary names so we can filter them from import rules.
    // Ecosystem sandboxes have proper toolchain access (execute on ~/.cargo etc.)
    // while the generic project_files sandbox does not.
    let eco_binaries: BTreeSet<&str> = detection
        .ecosystems
        .iter()
        .flat_map(|e| e.binaries.iter().copied())
        .collect();

    // Remove ecosystem-covered binaries from the import analysis so they
    // don't get a generic project_files rule that lacks execute permissions.
    analysis.bash_allows.retain(|segs| {
        segs.first()
            .map_or(true, |bin| !eco_binaries.contains(bin.as_str()))
    });

    // Build rules list — one dict per concern. Canonicalization merges
    // consecutive uncommented dicts automatically.
    let mut rules: Vec<Expr> = vec![];

    // 1. File denies
    for (tool, path) in &analysis.file_denies {
        let expr = match_rule(vec![(
            tool.as_str().into(),
            MatchValue::Nested(vec![(path.as_str().into(), MatchValue::Effect(deny()))]),
        )]);
        rules.push(Expr::commented(&format!("deny {} on {}", tool, path), expr));
    }

    // 2. Bash denies
    if !analysis.bash_denies.is_empty() {
        let expr = match_rule(vec![build_bash_entry(&analysis.bash_denies, deny())]);
        rules.push(Expr::commented("denied bash commands", expr));
    }

    // 3. Tool denies
    if !analysis.tool_denies.is_empty() {
        let names: Vec<&str> = analysis.tool_denies.iter().map(|s| s.as_str()).collect();
        rules.push(match_rule(vec![tool_entry(&names, deny())]));
    }

    // 4. Ecosystem sandbox routing — BEFORE generic import allows so that
    //    binaries like cargo/git get proper toolchain sandboxes instead of
    //    the generic project_files sandbox.
    rules.extend(crate::policy_gen::ecosystems::ecosystem_rules(
        &detection.ecosystems,
        PROJECT_FILES_SANDBOX,
    ));

    // 5–7. Allow rules — comment only the first, leave the rest uncommented
    //       so canonicalization collapses them.
    let mut allow_rules: Vec<Expr> = vec![];

    if !analysis.bash_allows.is_empty() {
        allow_rules.push(match_rule(vec![build_bash_entry(
            &analysis.bash_allows,
            allow_with_sandbox(Expr::ident(PROJECT_FILES_SANDBOX)),
        )]));
    }

    use crate::policy_gen::tools::{FS_ALL_TOOLS, is_fs_tool};
    let fs_tool_names: Vec<&str> = FS_ALL_TOOLS
        .iter()
        .filter(|t| analysis.tool_allows.contains(&t.to_string()))
        .copied()
        .collect();
    if !fs_tool_names.is_empty() {
        allow_rules.push(match_rule(vec![tool_entry(
            &fs_tool_names,
            allow_with_sandbox(Expr::ident(PROJECT_FILES_SANDBOX)),
        )]));
    }

    let other_allows: Vec<&str> = analysis
        .tool_allows
        .iter()
        .filter(|t| !is_fs_tool(t) && t.as_str() != "Bash")
        .map(|s| s.as_str())
        .collect();
    if !other_allows.is_empty() {
        allow_rules.push(match_rule(vec![tool_entry(&other_allows, allow())]));
    }

    // Comment only the first allow rule; the rest stay bare for merging.
    if let Some(first) = allow_rules.first_mut() {
        *first = Expr::commented("allowed (sandboxed)", first.clone());
    }
    rules.extend(allow_rules);

    // 8–9. Ask rules — same pattern: comment the first only.
    let mut ask_rules: Vec<Expr> = vec![];

    if !analysis.bash_asks.is_empty() {
        ask_rules.push(match_rule(vec![build_bash_entry(
            &analysis.bash_asks,
            ask(),
        )]));
    }
    if !analysis.tool_asks.is_empty() {
        let names: Vec<&str> = analysis.tool_asks.iter().map(|s| s.as_str()).collect();
        ask_rules.push(match_rule(vec![tool_entry(&names, ask())]));
    }

    if let Some(first) = ask_rules.first_mut() {
        *first = Expr::commented("requires confirmation", first.clone());
    }
    rules.extend(ask_rules);

    // Prepend from_claude_settings() as lowest-priority base.
    rules.insert(0, Expr::call("from_claude_settings", vec![]));
    stmts.push(Stmt::Expr(policy("imported", ask(), rules, None)));

    // Canonicalize (merges consecutive dicts, collapses dict siblings, etc.)
    clash_starlark::codegen::canonicalize::canonicalize(&mut stmts)
        .expect("canonicalize generated AST");

    clash_starlark::codegen::serialize(&stmts)
}

// ---------------------------------------------------------------------------
// Ecosystem detection
// ---------------------------------------------------------------------------

/// Result of ecosystem detection: load statements + the detected definitions.
struct EcosystemDetection {
    loads: Vec<Stmt>,
    ecosystems: Vec<&'static crate::ecosystem::EcosystemDef>,
}

/// Detect ecosystems and return load statements + definitions, or empty if declined.
fn detect_ecosystem_loads() -> Result<EcosystemDetection> {
    println!();
    let scan = crate::dialog::confirm(
        "Scan your project and command history to recommend sandboxes?",
        false,
    )?;
    if !scan {
        return Ok(EcosystemDetection {
            loads: vec![],
            ecosystems: vec![],
        });
    }

    let cwd = std::env::current_dir().context("getting current directory")?;
    let observed = crate::cmd::from_trace::mine_binaries_from_history();
    let observed_refs: Vec<&str> = observed.iter().map(|s| s.as_str()).collect();
    let detected = crate::ecosystem::detect_ecosystems(&cwd, &observed_refs);

    if detected.is_empty() {
        ui::info("No ecosystems detected.");
        return Ok(EcosystemDetection {
            loads: vec![],
            ecosystems: vec![],
        });
    }

    println!();
    ui::info("Detected ecosystems:");
    println!();
    for eco in &detected {
        ui::success(&format!("  {}", eco.name));
    }
    println!();

    let include = crate::dialog::confirm("Include these sandboxes in your policy?", false)?;
    if !include {
        return Ok(EcosystemDetection {
            loads: vec![],
            ecosystems: vec![],
        });
    }

    // Build load statements for each detected ecosystem
    let mut loads = Vec::new();
    let mut sandbox_imports: Vec<&str> = Vec::new();
    for eco in &detected {
        if eco.star_file == "sandboxes.star" {
            if let Some(safe) = eco.safe_sandbox {
                if !sandbox_imports.contains(&safe) {
                    sandbox_imports.push(safe);
                }
            }
            if !sandbox_imports.contains(&eco.full_sandbox) {
                sandbox_imports.push(eco.full_sandbox);
            }
        }
    }
    if !sandbox_imports.is_empty() {
        loads.push(load_sandboxes(&sandbox_imports));
    }
    for eco in &detected {
        if eco.star_file == "sandboxes.star" {
            continue;
        }
        let mut names: Vec<&str> = Vec::new();
        if let Some(safe) = eco.safe_sandbox {
            names.push(safe);
        }
        names.push(eco.full_sandbox);
        loads.push(load_ecosystem(eco.star_file, &names));
    }

    Ok(EcosystemDetection {
        loads,
        ecosystems: detected,
    })
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
    let mut analysis = analyze_settings(&settings);

    // Detect ecosystems
    let detection = detect_ecosystem_loads()?;

    // Generate policy
    let policy_content = if analysis.needs_posture_prompt() {
        if analysis.bypass_permissions {
            ui::info("Claude Code is running with bypass_permissions enabled.");
        } else {
            ui::info("No existing permissions found in Claude Code settings.");
        }
        println!();
        let posture = crate::dialog::select::<Posture>("Pick a starting posture")?;
        generate_starlark_from_posture(*posture, &detection)
    } else {
        print_import_summary(&analysis);
        generate_starlark_from_analysis(&mut analysis, &detection)
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
        let perms = PermissionSet::new().allow("Read(**/*.rs)").allow("Edit");
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
        let mut analysis = analyze_settings(&settings);
        let starlark = generate_starlark_from_analysis(
            &mut analysis,
            &EcosystemDetection {
                loads: vec![],
                ecosystems: vec![],
            },
        );

        let output = clash_starlark::evaluate(&starlark, "<test>", std::path::Path::new("."))
            .expect("starlark evaluation failed");
        crate::policy::compile::compile_to_tree(&output.json)
            .expect("generated policy must compile");
    }

    #[test]
    fn test_generate_posture_compiles() {
        for posture in Posture::variants() {
            let starlark = generate_starlark_from_posture(
                *posture,
                &EcosystemDetection {
                    loads: vec![],
                    ecosystems: vec![],
                },
            );
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
        let mut analysis = analyze_settings(&settings);
        let starlark = generate_starlark_from_analysis(
            &mut analysis,
            &EcosystemDetection {
                loads: vec![],
                ecosystems: vec![],
            },
        );

        assert!(
            starlark.contains("(\"cargo\", \"git\", \"npm\")"),
            "expected grouped tuple key, got:\n{starlark}"
        );
    }

    #[test]
    fn test_generate_denies_first() {
        use claude_settings::permission::PermissionSet;
        let perms = PermissionSet::new().allow("Read").deny("Read(.env)");
        let settings = claude_settings::Settings::default().with_permissions(perms);
        let mut analysis = analyze_settings(&settings);
        let starlark = generate_starlark_from_analysis(
            &mut analysis,
            &EcosystemDetection {
                loads: vec![],
                ecosystems: vec![],
            },
        );

        // Find deny() and allow(sandbox = ...) within the policy section, not in
        // the settings/sandbox definitions above it.
        let rules_start = starlark.find("policy(").expect("should contain policy");
        let rules_section = &starlark[rules_start..];
        let deny_pos = rules_section
            .find("deny()")
            .expect("should contain deny in rules");
        let allow_pos = rules_section
            .find("allow(sandbox")
            .expect("should contain allow in rules");
        assert!(
            deny_pos < allow_pos,
            "deny rules should come before allow rules in:\n{rules_section}"
        );
    }

    #[test]
    fn test_no_duplicate_tools_or_bash_in_other_allows() {
        use claude_settings::permission::PermissionSet;
        // Bash appears as both prefix-allows AND bare tool allow + exact match.
        // Previously this produced ("Bash", "WebFetch", "Bash", "Bash"): allow().
        let perms = PermissionSet::new()
            .allow("Bash(git:*)")
            .allow("Bash(cargo:*)")
            .allow("Bash")
            .allow("WebFetch");
        let settings = claude_settings::Settings::default().with_permissions(perms);
        let mut analysis = analyze_settings(&settings);
        let starlark = generate_starlark_from_analysis(
            &mut analysis,
            &EcosystemDetection {
                loads: vec![],
                ecosystems: vec![],
            },
        );

        // "Bash" should not appear in the other-tools rule at all —
        // it's handled by the bash-commands rule.
        let rules_start = starlark.find("policy(").expect("should contain policy");
        let rules_section = &starlark[rules_start..];

        // The other-allows rule should be just WebFetch, not a tuple with Bash.
        assert!(
            rules_section.contains("\"WebFetch\": allow()"),
            "expected WebFetch as sole other-allowed tool, got:\n{rules_section}"
        );
        assert!(
            !rules_section.contains("(\"Bash\""),
            "Bash should not appear in tool tuple:\n{rules_section}"
        );

        // Must still compile
        let output = clash_starlark::evaluate(&starlark, "<test>", std::path::Path::new("."))
            .expect("starlark evaluation failed");
        crate::policy::compile::compile_to_tree(&output.json)
            .expect("generated policy must compile");
    }

    #[test]
    fn test_project_files_sandbox_used_consistently() {
        use claude_settings::permission::PermissionSet;
        let perms = PermissionSet::new()
            .allow("Bash(git:*)")
            .allow("Read")
            .allow("Edit");
        let settings = claude_settings::Settings::default().with_permissions(perms);
        let mut analysis = analyze_settings(&settings);
        let starlark = generate_starlark_from_analysis(
            &mut analysis,
            &EcosystemDetection {
                loads: vec![],
                ecosystems: vec![],
            },
        );

        // settings and tool rules should reference project_files, not project
        assert!(
            starlark.contains("default_sandbox = project_files"),
            "settings should use project_files sandbox:\n{starlark}"
        );
        // Bash sandbox should also use project_files
        assert!(
            starlark.contains("sandbox = project_files"),
            "bash rules should use project_files sandbox:\n{starlark}"
        );
        // Should not import from sandboxes.star or std.star (symbols are globals)
        assert!(
            !starlark.contains("sandboxes.star"),
            "should not import from sandboxes.star:\n{starlark}"
        );
        assert!(
            !starlark.contains("std.star"),
            "should not import from std.star (symbols are pre-injected globals):\n{starlark}"
        );
    }

    #[test]
    fn test_generate_with_ecosystems_compiles() {
        use claude_settings::permission::PermissionSet;
        let perms = PermissionSet::new()
            .allow("Bash(git:*)")
            .allow("Bash(cargo:*)")
            .allow("Read");
        let settings = claude_settings::Settings::default().with_permissions(perms);
        let mut analysis = analyze_settings(&settings);

        let ecosystems: Vec<&crate::ecosystem::EcosystemDef> = crate::ecosystem::ECOSYSTEMS
            .iter()
            .filter(|e| e.name == "git" || e.name == "rust")
            .collect();

        let detection = EcosystemDetection {
            loads: {
                use clash_starlark::codegen::builder::*;
                vec![
                    load_sandboxes(&["git_safe", "git_full"]),
                    load_ecosystem("rust.star", &["rust_safe", "rust_full"]),
                ]
            },
            ecosystems,
        };

        let starlark = generate_starlark_from_analysis(&mut analysis, &detection);

        // Must contain ecosystem routing rules
        assert!(
            starlark.contains("git_full"),
            "should route git through git_full:\n{starlark}"
        );
        assert!(
            starlark.contains("rust_full"),
            "should route rust through rust_full:\n{starlark}"
        );

        let output = clash_starlark::evaluate(&starlark, "<test>", std::path::Path::new("."))
            .expect("starlark evaluation failed");
        crate::policy::compile::compile_to_tree(&output.json)
            .expect("generated policy with ecosystems must compile");
    }
}
