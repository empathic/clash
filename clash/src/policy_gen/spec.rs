//! PolicySpec — single pipeline for all policy generation.
//!
//! Every generator (from_posture, from_trace, from_manifest, etc.) builds a
//! `PolicySpec`, then calls `to_starlark()` to produce the final output.

use std::collections::BTreeSet;

use clash_starlark::codegen::ast::{DictEntry, Expr, Stmt};
use clash_starlark::codegen::builder::*;

use crate::ecosystem::EcosystemDef;
use crate::policy_gen::ecosystems;
use crate::policy_gen::loads;
use crate::policy_gen::sandboxes;
use crate::policy_gen::tools::{FS_ALL_TOOLS, is_fs_tool};

/// A custom rule to include in the generated policy.
#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub expr: Expr,
}

/// Everything a generated policy needs, in a structured form.
///
/// Build one of these via a constructor (`from_posture`, etc.), then call
/// `to_starlark()` to produce the final Starlark source.
pub struct PolicySpec {
    /// Policy name (e.g. "default", "imported").
    pub name: String,
    /// Default effect: "allow", "deny", or "ask".
    pub default_effect: String,
    /// Sandbox preset for settings() (e.g. "project", "readonly", "workspace").
    pub default_sandbox: Option<String>,
    /// Whether to define the project_files inline sandbox.
    pub define_project_files_sandbox: bool,
    /// Sandbox presets to load from sandboxes.star.
    pub sandbox_presets: Vec<String>,
    /// Detected ecosystems.
    pub ecosystems: Vec<&'static EcosystemDef>,
    /// Whether to generate mode-based routing (plan/edit/unrestricted).
    pub mode_routing: bool,
    /// Custom rules to append.
    pub rules: Vec<PolicyRule>,
    /// Whether to include `from_claude_settings()` in rules.
    pub include_claude_settings: bool,
    /// Whether to auto-generate ecosystem routing rules in `to_starlark()`.
    /// Set to false when the caller builds ecosystem rules manually (e.g. from_analysis).
    pub auto_ecosystem_rules: bool,
    /// Whether to canonicalize the output.
    pub canonicalize: bool,
    /// Optional header comment.
    pub header_comment: Option<String>,
    /// Whether to emit a `settings()` call.
    pub emit_settings: bool,
}

impl PolicySpec {
    /// Build a spec from a posture choice (strict/balanced/permissive).
    pub fn from_posture(
        effect: &str,
        sandbox_preset: &str,
        ecosystems: &[&'static EcosystemDef],
    ) -> Self {
        Self {
            name: "default".to_string(),
            default_effect: effect.to_string(),
            default_sandbox: Some(sandbox_preset.to_string()),
            define_project_files_sandbox: false,
            sandbox_presets: vec![sandbox_preset.to_string()],
            ecosystems: ecosystems.to_vec(),
            mode_routing: false,
            rules: vec![],
            include_claude_settings: true,
            auto_ecosystem_rules: true,
            canonicalize: false,
            header_comment: None,
            emit_settings: true,
        }
    }

    /// Build a spec from an import analysis (Claude Code settings).
    ///
    /// Moves the rule-building logic from `generate_starlark_from_analysis`
    /// into the spec pipeline. The caller passes a mutable analysis (for
    /// dedup/filtering) and the detected ecosystems.
    pub(crate) fn from_analysis(
        analysis: &mut crate::cmd::import_settings::ImportAnalysis,
        ecosystems: &[&'static EcosystemDef],
    ) -> Self {
        // Deduplicate tool lists
        dedup_stable(&mut analysis.tool_allows);
        dedup_stable(&mut analysis.tool_denies);
        dedup_stable(&mut analysis.tool_asks);

        // Collect ecosystem binary names so we can filter them from import
        // rules. Ecosystem sandboxes have proper toolchain access while the
        // generic project_files sandbox does not.
        let eco_binaries: BTreeSet<&str> = ecosystems
            .iter()
            .flat_map(|e| e.binaries.iter().copied())
            .collect();

        // Remove ecosystem-covered binaries from bash_allows.
        analysis.bash_allows.retain(|segs| {
            segs.first()
                .map_or(true, |bin| !eco_binaries.contains(bin.as_str()))
        });

        // Build rules list in order: denies → ecosystems → allows → asks.
        let mut rules: Vec<PolicyRule> = vec![];

        // 1. File denies
        for (tool, path) in &analysis.file_denies {
            let expr = match_rule(vec![(
                tool.as_str().into(),
                MatchValue::Nested(vec![(path.as_str().into(), MatchValue::Effect(deny()))]),
            )]);
            rules.push(PolicyRule {
                expr: Expr::commented(&format!("deny {} on {}", tool, path), expr),
            });
        }

        // 2. Bash denies
        if !analysis.bash_denies.is_empty() {
            let expr = match_rule(vec![build_bash_entry(&analysis.bash_denies, deny())]);
            rules.push(PolicyRule {
                expr: Expr::commented("denied bash commands", expr),
            });
        }

        // 3. Tool denies
        if !analysis.tool_denies.is_empty() {
            let names: Vec<&str> = analysis.tool_denies.iter().map(|s| s.as_str()).collect();
            rules.push(PolicyRule {
                expr: match_rule(vec![tool_entry(&names, deny())]),
            });
        }

        // 4. Ecosystem sandbox routing
        let eco_rules = ecosystems::ecosystem_rules(ecosystems, sandboxes::PROJECT_FILES_SANDBOX);
        for expr in eco_rules {
            rules.push(PolicyRule { expr });
        }

        // 5–7. Allow rules — comment only the first, leave the rest
        //       uncommented so MergeConsecutiveWhens collapses them.
        let mut allow_rules: Vec<Expr> = vec![];

        if !analysis.bash_allows.is_empty() {
            allow_rules.push(match_rule(vec![build_bash_entry(
                &analysis.bash_allows,
                allow_with_sandbox(Expr::ident(sandboxes::PROJECT_FILES_SANDBOX)),
            )]));
        }

        let fs_tool_names: Vec<&str> = FS_ALL_TOOLS
            .iter()
            .filter(|t| analysis.tool_allows.contains(&t.to_string()))
            .copied()
            .collect();
        if !fs_tool_names.is_empty() {
            allow_rules.push(match_rule(vec![tool_entry(
                &fs_tool_names,
                allow_with_sandbox(Expr::ident(sandboxes::PROJECT_FILES_SANDBOX)),
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
        for expr in allow_rules {
            rules.push(PolicyRule { expr });
        }

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
        for expr in ask_rules {
            rules.push(PolicyRule { expr });
        }

        Self {
            name: "imported".to_string(),
            default_effect: "ask".to_string(),
            default_sandbox: Some("project_files".to_string()),
            define_project_files_sandbox: true,
            sandbox_presets: vec![],
            ecosystems: ecosystems.to_vec(),
            mode_routing: false,
            rules,
            include_claude_settings: false,
            auto_ecosystem_rules: false,
            canonicalize: true,
            header_comment: Some("Imported from Claude Code settings".to_string()),
            emit_settings: true,
        }
    }

    /// Build a spec from a session trace analysis.
    ///
    /// Moves the rule-building logic from `from_trace::generate_starlark` into the
    /// spec pipeline. The caller provides a `TraceAnalysis` with observed tools and
    /// binaries; we categorize them into sandboxed FS rules, net rules, git safety
    /// denies, and binary-specific sandbox rules.
    pub(crate) fn from_trace(analysis: &crate::cmd::from_trace::TraceAnalysis) -> Self {
        use crate::policy_gen::sandboxes::PROJECT_FILES_SANDBOX;
        use crate::policy_gen::tools::{
            FS_READ_TOOLS, FS_WRITE_TOOLS, NET_TOOLS, is_categorized_tool,
        };
        use clash_starlark::codegen::builder::*;

        // Categorize tools
        let read_tools: Vec<&str> = FS_READ_TOOLS
            .iter()
            .filter(|t| analysis.tools.contains(**t))
            .copied()
            .collect();
        let write_tools: Vec<&str> = FS_WRITE_TOOLS
            .iter()
            .filter(|t| analysis.tools.contains(**t))
            .copied()
            .collect();
        let net_tools: Vec<&str> = NET_TOOLS
            .iter()
            .filter(|t| analysis.tools.contains(**t))
            .copied()
            .collect();
        let other_tools: Vec<&String> = analysis
            .tools
            .iter()
            .filter(|t| !is_categorized_tool(t))
            .collect();

        let mut rules: Vec<PolicyRule> = vec![];

        // Read-only fs tools — sandboxed to project_files
        if !read_tools.is_empty() {
            let expr = tool_match(
                &read_tools,
                allow_with_sandbox(Expr::ident(PROJECT_FILES_SANDBOX)),
            );
            rules.push(PolicyRule {
                expr: Expr::commented("Read-only fs tools — observed in session", expr),
            });
        }

        // Write fs tools — sandboxed to project_files
        if !write_tools.is_empty() {
            let expr = tool_match(
                &write_tools,
                allow_with_sandbox(Expr::ident(PROJECT_FILES_SANDBOX)),
            );
            rules.push(PolicyRule {
                expr: Expr::commented("Write fs tools — observed in session", expr),
            });
        }

        // Network tools — prompt user (safer default)
        if !net_tools.is_empty() {
            let expr = tool_match(&net_tools, ask());
            rules.push(PolicyRule {
                expr: Expr::commented("Network tools — prompt before allowing", expr),
            });
        }

        // Other tools (e.g., Agent) — allow without sandbox
        for t in &other_tools {
            rules.push(PolicyRule {
                expr: tool_match(&[t.as_str()], allow()),
            });
        }

        // Deny destructive git ops if git was observed
        if analysis.binaries.contains("git") {
            let expr = clash_starlark::match_tree! {
                "Bash" => {
                    "git" => {
                        "push" => {
                            "--force" => deny(),
                            "--force-with-lease" => deny(),
                        },
                        "reset" => {
                            "--hard" => deny(),
                        },
                    },
                },
            };
            rules.push(PolicyRule {
                expr: Expr::commented("Deny destructive git ops", expr),
            });
        }

        // Binary-specific rules — sandboxed to the "project" preset
        if !analysis.binaries.is_empty() {
            let bins: Vec<&str> = analysis.binaries.iter().map(|s| s.as_str()).collect();
            let key: MatchKey = if bins.len() == 1 {
                bins[0].into()
            } else {
                bins.as_slice().into()
            };
            let expr = clash_starlark::match_tree! {
                "Bash" => {
                    key => allow_with_sandbox(Expr::ident("project")),
                },
            };
            rules.push(PolicyRule {
                expr: Expr::commented("Observed binaries — sandboxed", expr),
            });
        }

        // Generic Bash fallback when Bash was observed but no specific binaries extracted
        let saw_bash = analysis.total_invocations > 0
            && analysis.binaries.is_empty()
            && analysis.tools.len() < analysis.total_invocations;
        if saw_bash {
            let expr = clash_starlark::match_tree! {
                "Bash" => allow_with_sandbox(Expr::ident("project")),
            };
            rules.push(PolicyRule {
                expr: Expr::commented(
                    "Bash commands observed (binaries unknown) — sandboxed",
                    expr,
                ),
            });
        }

        Self {
            name: "default".to_string(),
            default_effect: "ask".to_string(),
            default_sandbox: Some("project_files".to_string()),
            define_project_files_sandbox: true,
            sandbox_presets: vec!["project".to_string()],
            ecosystems: vec![],
            mode_routing: false,
            rules,
            include_claude_settings: false,
            auto_ecosystem_rules: false,
            canonicalize: false,
            header_comment: None,
            emit_settings: true,
        }
    }

    /// Build a spec for mode-based routing from detected ecosystems.
    ///
    /// Produces a policy with plan/edit+default/unrestricted modes, where each
    /// mode has its own sandbox level and ecosystem-specific bash routing.
    pub fn from_ecosystems(ecosystems: &[&'static EcosystemDef]) -> Self {
        // Only base presets go in sandbox_presets (loaded from sandboxes.star).
        // Ecosystem-specific sandboxes are handled by standard_loads via the
        // ecosystems field.
        let sandbox_presets: Vec<String> =
            vec!["readonly".into(), "project".into(), "workspace".into()];

        Self {
            name: "default".to_string(),
            default_effect: "deny".to_string(),
            default_sandbox: None,
            define_project_files_sandbox: false,
            sandbox_presets,
            ecosystems: ecosystems.to_vec(),
            mode_routing: true,
            rules: vec![],
            // NOTE: from_claude_settings() produces nodes whose JSON shape
            // ("children" at top level) is incompatible with compile_to_tree().
            // Disabled until that compatibility issue is resolved.
            include_claude_settings: false,
            auto_ecosystem_rules: false,
            canonicalize: false,
            header_comment: None,
            emit_settings: false,
        }
    }

    /// Build the mode-routing dict for plan/edit+default/unrestricted modes.
    fn build_mode_dict(&self) -> Expr {
        let mut mode_entries: Vec<DictEntry> = Vec::new();

        // Plan mode: readonly catch-all + ecosystem bash routing with safe sandboxes
        let plan_bash = Self::build_bash_routing(&self.ecosystems, true);
        let mut plan_inner = vec![DictEntry::new(
            Expr::call("glob", vec![Expr::string("**")]),
            allow_with_sandbox(Expr::ident("readonly")),
        )];
        if !plan_bash.is_empty() {
            plan_inner.push(DictEntry::new(
                Expr::call("tool", vec![Expr::string("Bash")]),
                Expr::dict(plan_bash),
            ));
        }
        mode_entries.push(DictEntry::new(
            Expr::call("mode", vec![Expr::string("plan")]),
            Expr::dict(plan_inner),
        ));

        // Edit/default mode: project catch-all + ecosystem bash routing with full sandboxes
        let edit_bash = Self::build_bash_routing(&self.ecosystems, false);
        let mut edit_inner = vec![DictEntry::new(
            Expr::call("glob", vec![Expr::string("**")]),
            allow_with_sandbox(Expr::ident("project")),
        )];
        if !edit_bash.is_empty() {
            edit_inner.push(DictEntry::new(
                Expr::call("tool", vec![Expr::string("Bash")]),
                Expr::dict(edit_bash),
            ));
        }
        mode_entries.push(DictEntry::new(
            Expr::tuple(vec![
                Expr::call("mode", vec![Expr::string("edit")]),
                Expr::call("mode", vec![Expr::string("default")]),
            ]),
            Expr::dict(edit_inner),
        ));

        // Unrestricted mode: workspace catch-all
        mode_entries.push(DictEntry::new(
            Expr::call("mode", vec![Expr::string("unrestricted")]),
            Expr::dict(vec![DictEntry::new(
                Expr::call("glob", vec![Expr::string("**")]),
                allow_with_sandbox(Expr::ident("workspace")),
            )]),
        ));

        Expr::dict(mode_entries)
    }

    /// Build Bash routing entries for ecosystems.
    /// If `use_safe` is true, prefer `_safe` variants (plan mode).
    fn build_bash_routing(ecosystems: &[&'static EcosystemDef], use_safe: bool) -> Vec<DictEntry> {
        let mut entries = Vec::new();

        for eco in ecosystems {
            let sandbox_name = if use_safe {
                eco.safe_sandbox.unwrap_or(eco.full_sandbox)
            } else {
                eco.full_sandbox
            };

            let key = if eco.binaries.len() == 1 {
                Expr::string(eco.binaries[0])
            } else {
                Expr::tuple(eco.binaries.iter().map(|b| Expr::string(*b)).collect())
            };

            let glob_entry = DictEntry::new(
                Expr::call("glob", vec![Expr::string("**")]),
                allow_with_sandbox(Expr::ident(sandbox_name)),
            );

            entries.push(DictEntry::new(key, Expr::dict(vec![glob_entry])));
        }

        entries
    }

    /// Generate the Starlark source from this spec.
    pub fn to_starlark(&self) -> String {
        let mut stmts = Vec::new();

        // Header comment
        if let Some(comment) = &self.header_comment {
            stmts.push(Stmt::comment(comment));
        }

        // Load statements
        let preset_refs: Vec<&str> = self.sandbox_presets.iter().map(|s| s.as_str()).collect();
        let eco_refs: Vec<&EcosystemDef> = self.ecosystems.iter().copied().collect();
        stmts.extend(loads::standard_loads(&preset_refs, &eco_refs));

        // Claude compat load
        if self.include_claude_settings {
            stmts.push(Stmt::load(
                "@clash//claude_compat.star",
                &["from_claude_settings"],
            ));
        }

        stmts.push(Stmt::Blank);

        // Project files sandbox definition
        if self.define_project_files_sandbox {
            stmts.extend(sandboxes::project_files_sandbox());
            stmts.push(Stmt::Blank);
        }

        // Settings call
        if self.emit_settings {
            let default_expr = Expr::call(&self.default_effect, vec![]);
            let sandbox_expr = self.default_sandbox.as_ref().map(|s| Expr::ident(s));
            stmts.push(Stmt::Expr(settings(default_expr, sandbox_expr)));
            stmts.push(Stmt::Blank);
        }

        if self.mode_routing {
            // Mode-based routing: use the dict form of policy() with the mode
            // dict as the second positional arg, plus a rules= kwarg for
            // from_claude_settings() and any custom rules.
            let mode_dict = self.build_mode_dict();

            let mut kwargs: Vec<(&str, Expr)> = Vec::new();

            // Collect rules for the rules= kwarg
            let mut rules: Vec<Expr> = Vec::new();
            if self.include_claude_settings {
                rules.push(Expr::call("from_claude_settings", vec![]));
            }
            for rule in &self.rules {
                rules.push(rule.expr.clone());
            }
            if !rules.is_empty() {
                kwargs.push(("rules", Expr::list(rules)));
            }

            stmts.push(Stmt::Expr(Expr::call_kwargs(
                "policy",
                vec![Expr::string(&self.name), mode_dict],
                kwargs,
            )));
        } else {
            // Standard rules-based policy.
            let mut rules: Vec<Expr> = Vec::new();

            if self.include_claude_settings {
                rules.push(Expr::call("from_claude_settings", vec![]));
            }

            // Ecosystem rules (non-mode-routing, auto only)
            if self.auto_ecosystem_rules && !self.ecosystems.is_empty() {
                let fs_sandbox = self
                    .default_sandbox
                    .as_deref()
                    .unwrap_or(sandboxes::PROJECT_FILES_SANDBOX);
                rules.extend(ecosystems::ecosystem_rules(&eco_refs, fs_sandbox));
            }

            // Custom rules
            for rule in &self.rules {
                rules.push(rule.expr.clone());
            }

            let default_expr = Expr::call(&self.default_effect, vec![]);
            stmts.push(Stmt::Expr(policy(&self.name, default_expr, rules, None)));
        }

        // Canonicalize
        if self.canonicalize {
            clash_starlark::codegen::canonicalize::canonicalize(&mut stmts)
                .expect("canonicalize generated AST");
        }

        clash_starlark::codegen::serialize(&stmts)
    }
}

/// Deduplicate a Vec<String> in place, preserving order.
pub(crate) fn dedup_stable(v: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    v.retain(|item| seen.insert(item.clone()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn eval(code: &str) -> Result<clash_starlark::EvalOutput, anyhow::Error> {
        clash_starlark::evaluate(code, "test.star", &PathBuf::from("."))
    }

    #[test]
    fn from_posture_produces_valid_starlark() {
        let spec = PolicySpec::from_posture("ask", "project", &[]);
        let code = spec.to_starlark();

        let result = eval(&code);
        assert!(
            result.is_ok(),
            "from_posture should produce evaluable Starlark: {:?}\n\nGenerated:\n{}",
            result.err(),
            code,
        );
    }

    #[test]
    fn from_posture_includes_from_claude_settings() {
        let spec = PolicySpec::from_posture("deny", "readonly", &[]);
        let code = spec.to_starlark();

        assert!(
            code.contains("from_claude_settings"),
            "output should include from_claude_settings\n\nGenerated:\n{}",
            code,
        );
        assert!(
            code.contains("claude_compat.star"),
            "output should load claude_compat.star\n\nGenerated:\n{}",
            code,
        );
    }

    #[test]
    fn from_posture_with_ecosystems_includes_routing() {
        let rust = crate::ecosystem::ECOSYSTEMS
            .iter()
            .find(|e| e.name == "rust")
            .unwrap();

        let spec = PolicySpec::from_posture("ask", "project", &[rust]);
        let code = spec.to_starlark();

        assert!(
            code.contains("rust"),
            "output should include ecosystem routing\n\nGenerated:\n{}",
            code,
        );
        assert!(
            code.contains("\"Bash\""),
            "output should include Bash routing\n\nGenerated:\n{}",
            code,
        );

        let result = eval(&code);
        assert!(
            result.is_ok(),
            "from_posture with ecosystems should evaluate: {:?}\n\nGenerated:\n{}",
            result.err(),
            code,
        );
    }

    #[test]
    fn from_posture_emits_settings_call() {
        let spec = PolicySpec::from_posture("allow", "workspace", &[]);
        let code = spec.to_starlark();

        assert!(
            code.contains("settings("),
            "output should include settings() call\n\nGenerated:\n{}",
            code,
        );
        assert!(
            code.contains("default_sandbox = workspace"),
            "output should include default_sandbox\n\nGenerated:\n{}",
            code,
        );
    }

    #[test]
    fn from_trace_produces_valid_starlark() {
        use std::collections::BTreeSet;
        let analysis = crate::cmd::from_trace::TraceAnalysis {
            total_invocations: 5,
            tools: BTreeSet::from(["Read".into(), "Write".into(), "Grep".into()]),
            binaries: BTreeSet::from(["git".into(), "cargo".into()]),
        };

        let spec = PolicySpec::from_trace(&analysis);
        let code = spec.to_starlark();

        let result = eval(&code);
        assert!(
            result.is_ok(),
            "from_trace should produce evaluable Starlark: {:?}\n\nGenerated:\n{}",
            result.err(),
            code,
        );

        // Should include project_files sandbox definition
        assert!(
            code.contains("project_files"),
            "output should define project_files sandbox\n\nGenerated:\n{}",
            code,
        );

        // Should include tool rules
        assert!(
            code.contains("allow(sandbox = project_files)"),
            "should sandbox fs tools to project_files\n\nGenerated:\n{}",
            code,
        );

        // Should include git safety denies
        assert!(
            code.contains("deny()"),
            "should deny destructive git ops\n\nGenerated:\n{}",
            code,
        );

        // Should include settings with ask default
        assert!(
            code.contains("settings("),
            "should include settings call\n\nGenerated:\n{}",
            code,
        );
        assert!(
            code.contains("default = ask()"),
            "should use ask() as default\n\nGenerated:\n{}",
            code,
        );
    }

    #[test]
    fn from_trace_no_claude_settings() {
        use std::collections::BTreeSet;
        let analysis = crate::cmd::from_trace::TraceAnalysis {
            total_invocations: 1,
            tools: BTreeSet::from(["Read".into()]),
            binaries: BTreeSet::new(),
        };

        let spec = PolicySpec::from_trace(&analysis);
        let code = spec.to_starlark();

        assert!(
            !code.contains("from_claude_settings"),
            "from_trace should not include from_claude_settings\n\nGenerated:\n{}",
            code,
        );
        assert!(
            !code.contains("claude_compat.star"),
            "from_trace should not load claude_compat.star\n\nGenerated:\n{}",
            code,
        );
    }

    #[test]
    fn from_posture_all_effects() {
        for (effect, preset) in [
            ("deny", "readonly"),
            ("ask", "project"),
            ("allow", "workspace"),
        ] {
            let spec = PolicySpec::from_posture(effect, preset, &[]);
            let code = spec.to_starlark();
            assert!(
                code.contains(&format!("default = {effect}()")),
                "should use {effect} as default\n\nGenerated:\n{}",
                code,
            );
            let result = eval(&code);
            assert!(
                result.is_ok(),
                "{effect}/{preset} should evaluate: {:?}\n\nGenerated:\n{}",
                result.err(),
                code,
            );
        }
    }

    #[test]
    fn from_ecosystems_produces_valid_starlark() {
        let rust = crate::ecosystem::ECOSYSTEMS
            .iter()
            .find(|e| e.name == "rust")
            .unwrap();
        let git = crate::ecosystem::ECOSYSTEMS
            .iter()
            .find(|e| e.name == "git")
            .unwrap();

        let spec = PolicySpec::from_ecosystems(&[git, rust]);
        let code = spec.to_starlark();

        let result = eval(&code);
        assert!(
            result.is_ok(),
            "from_ecosystems should produce evaluable Starlark: {:?}\n\nGenerated:\n{}",
            result.err(),
            code,
        );

        // Should have mode-based routing
        assert!(
            code.contains("mode(\"plan\")"),
            "should have plan mode\n\nGenerated:\n{}",
            code
        );
        assert!(
            code.contains("mode(\"edit\")"),
            "should have edit mode\n\nGenerated:\n{}",
            code
        );
        assert!(
            code.contains("mode(\"unrestricted\")"),
            "should have unrestricted mode\n\nGenerated:\n{}",
            code
        );

        // Should have ecosystem sandboxes
        assert!(
            code.contains("rust_safe"),
            "should have rust_safe\n\nGenerated:\n{}",
            code
        );
        assert!(
            code.contains("rust_full"),
            "should have rust_full\n\nGenerated:\n{}",
            code
        );
        assert!(
            code.contains("git_safe"),
            "should have git_safe\n\nGenerated:\n{}",
            code
        );
        assert!(
            code.contains("git_full"),
            "should have git_full\n\nGenerated:\n{}",
            code
        );

        // Should not emit settings
        assert!(
            !code.contains("settings("),
            "should not emit settings()\n\nGenerated:\n{}",
            code
        );

        // Should have base sandbox presets
        assert!(
            code.contains("readonly"),
            "should have readonly\n\nGenerated:\n{}",
            code
        );
        assert!(
            code.contains("project"),
            "should have project\n\nGenerated:\n{}",
            code
        );
        assert!(
            code.contains("workspace"),
            "should have workspace\n\nGenerated:\n{}",
            code
        );
    }

    #[test]
    fn from_ecosystems_empty() {
        let spec = PolicySpec::from_ecosystems(&[]);
        let code = spec.to_starlark();

        let result = eval(&code);
        assert!(
            result.is_ok(),
            "from_ecosystems with no ecosystems should evaluate: {:?}\n\nGenerated:\n{}",
            result.err(),
            code,
        );
    }

    #[test]
    fn from_ecosystems_compiles() {
        let rust = crate::ecosystem::ECOSYSTEMS
            .iter()
            .find(|e| e.name == "rust")
            .unwrap();

        let spec = PolicySpec::from_ecosystems(&[rust]);
        let code = spec.to_starlark();

        let output = eval(&code).expect("should evaluate");
        crate::policy::compile::compile_to_tree(&output.json)
            .expect("from_ecosystems policy should compile");
    }
}
