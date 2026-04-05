//! Standard load statement generation for policy files.

use clash_starlark::codegen::ast::Stmt;
use clash_starlark::codegen::builder::*;

use crate::ecosystem::EcosystemDef;

/// Generate all load statements needed for a policy with the given
/// sandbox presets and ecosystems.
///
/// Always includes `load("@clash//builtin.star", "builtins")`.
/// Adds sandbox preset loads and ecosystem-specific loads as needed.
pub fn standard_loads(sandbox_presets: &[&str], ecosystems: &[&EcosystemDef]) -> Vec<Stmt> {
    let mut stmts = vec![load_builtin()];

    // Collect sandbox names from presets + ecosystem sandboxes that live in sandboxes.star
    let mut sandbox_names: Vec<&str> = sandbox_presets.to_vec();
    for eco in ecosystems {
        if eco.star_file == "sandboxes.star" {
            if let Some(safe) = eco.safe_sandbox {
                if !sandbox_names.contains(&safe) {
                    sandbox_names.push(safe);
                }
            }
            if !sandbox_names.contains(&eco.full_sandbox) {
                sandbox_names.push(eco.full_sandbox);
            }
        }
    }
    if !sandbox_names.is_empty() {
        stmts.push(load_sandboxes(&sandbox_names));
    }

    // Ecosystem-specific loads (non-sandboxes.star files)
    for eco in ecosystems {
        if eco.star_file == "sandboxes.star" {
            continue;
        }
        let mut names: Vec<&str> = Vec::new();
        if let Some(safe) = eco.safe_sandbox {
            names.push(safe);
        }
        names.push(eco.full_sandbox);
        stmts.push(load_ecosystem(eco.star_file, &names));
    }

    stmts
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn standard_loads_with_no_extras() {
        let stmts = standard_loads(&[], &[]);
        assert_eq!(stmts.len(), 1, "should have just builtin load");
        let code = clash_starlark::codegen::serialize(&stmts);
        assert!(code.contains("builtin.star"));
    }

    #[test]
    fn standard_loads_with_preset() {
        let stmts = standard_loads(&["project"], &[]);
        assert_eq!(stmts.len(), 2);
        let code = clash_starlark::codegen::serialize(&stmts);
        assert!(code.contains("sandboxes.star"));
        assert!(code.contains("project"));
    }

    #[test]
    fn standard_loads_with_ecosystem() {
        let rust = crate::ecosystem::ECOSYSTEMS
            .iter()
            .find(|e| e.name == "rust")
            .unwrap();
        let stmts = standard_loads(&[], &[rust]);
        let code = clash_starlark::codegen::serialize(&stmts);
        assert!(code.contains("rust.star"));
        assert!(code.contains("rust_full"));
    }

    #[test]
    fn standard_loads_deduplicates_sandbox_presets() {
        let git = crate::ecosystem::ECOSYSTEMS
            .iter()
            .find(|e| e.name == "git")
            .unwrap();
        // git lives in sandboxes.star — should merge with preset load
        let stmts = standard_loads(&["project"], &[git]);
        let code = clash_starlark::codegen::serialize(&stmts);
        // Should be one sandboxes.star load with both project and git sandboxes
        let sandboxes_count = code.matches("sandboxes.star").count();
        assert_eq!(sandboxes_count, 1, "should have single sandboxes.star load");
    }
}
