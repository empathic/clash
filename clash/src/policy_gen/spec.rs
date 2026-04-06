//! PolicySpec — single pipeline for all policy generation.
//!
//! Every generator (from_posture, from_trace, from_manifest, etc.) builds a
//! `PolicySpec`, then calls `to_starlark()` to produce the final output.

use clash_starlark::codegen::ast::{Expr, Stmt};
use clash_starlark::codegen::builder::*;

use crate::ecosystem::EcosystemDef;
use crate::policy_gen::ecosystems;
use crate::policy_gen::loads;
use crate::policy_gen::sandboxes;

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
            canonicalize: false,
            header_comment: None,
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

        // Ecosystem rules (non-mode-routing)
        if !self.mode_routing && !self.ecosystems.is_empty() {
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
