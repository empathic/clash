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
                MatchValue::Nested(vec![(
                    path.as_str().into(),
                    MatchValue::Effect(deny()),
                )]),
            )]);
            rules.push(PolicyRule {
                expr: Expr::commented(
                    &format!("deny {} on {}", tool, path),
                    expr,
                ),
            });
        }

        // 2. Bash denies
        if !analysis.bash_denies.is_empty() {
            let expr = match_rule(vec![build_bash_entry(
                &analysis.bash_denies,
                deny(),
            )]);
            rules.push(PolicyRule {
                expr: Expr::commented("denied bash commands", expr),
            });
        }

        // 3. Tool denies
        if !analysis.tool_denies.is_empty() {
            let names: Vec<&str> =
                analysis.tool_denies.iter().map(|s| s.as_str()).collect();
            rules.push(PolicyRule {
                expr: match_rule(vec![tool_entry(&names, deny())]),
            });
        }

        // 4. Ecosystem sandbox routing
        let eco_rules = ecosystems::ecosystem_rules(
            ecosystems,
            sandboxes::PROJECT_FILES_SANDBOX,
        );
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
            allow_rules.push(match_rule(vec![tool_entry(
                &other_allows,
                allow(),
            )]));
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
            let names: Vec<&str> =
                analysis.tool_asks.iter().map(|s| s.as_str()).collect();
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

        // Build rules list
        let mut rules: Vec<Expr> = Vec::new();

        // from_claude_settings() rule
        if self.include_claude_settings {
            rules.push(Expr::call("from_claude_settings", vec![]));
        }

        // Ecosystem rules (non-mode-routing, auto only)
        if self.auto_ecosystem_rules && !self.mode_routing && !self.ecosystems.is_empty() {
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

        // Policy call
        let default_expr = Expr::call(&self.default_effect, vec![]);
        stmts.push(Stmt::Expr(policy(&self.name, default_expr, rules, None)));

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
            code.contains("when("),
            "output should include when() rules\n\nGenerated:\n{}",
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
}
