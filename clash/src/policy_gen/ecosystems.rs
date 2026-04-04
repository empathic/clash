//! Ecosystem-aware rule generation for policy files.

use clash_starlark::codegen::ast::{DictEntry, Expr};
use clash_starlark::codegen::builder::*;

use super::tools::FS_ALL_TOOLS;
use crate::ecosystem::EcosystemDef;

/// Build `when()` routing rules for detected ecosystems.
///
/// Generates two kinds of rules:
/// 1. File-access tools → `fs_sandbox` sandbox
/// 2. Bash binary routing → ecosystem-specific sandboxes
pub fn ecosystem_rules(ecosystems: &[&EcosystemDef], fs_sandbox: &str) -> Vec<Expr> {
    if ecosystems.is_empty() {
        return vec![];
    }

    let mut rules = Vec::new();

    // File-access tools — allow within the given sandbox
    rules.push(Expr::commented(
        "file-access tools — sandboxed to project",
        tool_match(FS_ALL_TOOLS, allow_with_sandbox(Expr::ident(fs_sandbox))),
    ));

    // Bash binary routing
    let mut bash_entries: Vec<(MatchKey, MatchValue)> = Vec::new();
    for eco in ecosystems {
        let key: MatchKey = if eco.binaries.len() == 1 {
            eco.binaries[0].into()
        } else {
            eco.binaries.into()
        };
        let sandbox_expr = allow_with_sandbox(Expr::ident(eco.full_sandbox));
        let glob_entry = Expr::dict(vec![DictEntry::new(
            Expr::call("glob", vec![Expr::string("**")]),
            sandbox_expr,
        )]);
        bash_entries.push((key, MatchValue::Effect(glob_entry)));
    }

    rules.push(Expr::commented(
        "ecosystem sandboxes (detected)",
        match_rule(vec![("Bash".into(), MatchValue::Nested(bash_entries))]),
    ));

    rules
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn empty_ecosystems_returns_empty() {
        let rules = ecosystem_rules(&[], "project");
        assert!(rules.is_empty());
    }

    #[test]
    fn ecosystem_rules_produces_two_rules() {
        let rust = crate::ecosystem::ECOSYSTEMS
            .iter()
            .find(|e| e.name == "rust")
            .unwrap();
        let rules = ecosystem_rules(&[rust], "project");
        assert_eq!(
            rules.len(),
            2,
            "expected fs-tools rule + ecosystem routing rule"
        );
    }
}
