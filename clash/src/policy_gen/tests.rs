//! Integration tests verifying that shared definitions stay consistent
//! and that generated policies compile successfully.

#[cfg(test)]
mod test {
    use crate::policy_gen::sandboxes;
    use crate::policy_gen::tools::*;

    #[test]
    fn project_files_sandbox_evaluates_to_valid_policy() {
        use clash_starlark::codegen::ast::{Expr, Stmt};
        use clash_starlark::codegen::builder::*;

        let mut stmts = vec![
            load_builtin(),
            load_std(&[
                "settings", "policy", "sandbox", "allow", "ask", "deny", "glob", "subpath", "when",
            ]),
            Stmt::Blank,
        ];
        stmts.extend(sandboxes::project_files_sandbox());
        stmts.push(Stmt::Blank);
        stmts.push(Stmt::Expr(settings(
            ask(),
            Some(Expr::ident(sandboxes::PROJECT_FILES_SANDBOX)),
        )));
        stmts.push(Stmt::Blank);
        stmts.push(Stmt::Expr(policy(
            "test",
            ask(),
            vec![tool_match(
                FS_ALL_TOOLS,
                allow_with_sandbox(Expr::ident(sandboxes::PROJECT_FILES_SANDBOX)),
            )],
            None,
        )));

        let code = clash_starlark::codegen::serialize(&stmts);
        let result = clash_starlark::evaluate(&code, "test.star", &std::path::PathBuf::from("."));
        assert!(
            result.is_ok(),
            "generated policy should evaluate successfully: {:?}\n\nGenerated:\n{}",
            result.err(),
            code,
        );
    }

    #[test]
    fn ecosystem_rules_with_shared_sandbox_compile() {
        use clash_starlark::codegen::ast::Stmt;
        use clash_starlark::codegen::builder::*;
        use crate::policy_gen::ecosystems;
        use crate::policy_gen::loads;

        let rust = crate::ecosystem::ECOSYSTEMS
            .iter()
            .find(|e| e.name == "rust")
            .unwrap();

        let mut stmts = loads::standard_loads(&[], &[rust]);
        stmts.push(load_std(&[
            "settings", "policy", "sandbox", "allow", "ask", "deny",
            "glob", "subpath", "when",
        ]));
        stmts.push(Stmt::Blank);
        stmts.extend(sandboxes::project_files_sandbox());
        stmts.push(Stmt::Blank);
        stmts.push(Stmt::Expr(settings(ask(), None)));
        stmts.push(Stmt::Blank);

        let eco_rules = ecosystems::ecosystem_rules(
            &[rust],
            sandboxes::PROJECT_FILES_SANDBOX,
        );
        stmts.push(Stmt::Expr(policy("test", ask(), eco_rules, None)));

        let code = clash_starlark::codegen::serialize(&stmts);
        let result = clash_starlark::evaluate(&code, "test.star", &std::path::PathBuf::from("."));
        assert!(
            result.is_ok(),
            "policy with ecosystem rules should evaluate: {:?}\n\nGenerated:\n{}",
            result.err(),
            code,
        );
    }
}
