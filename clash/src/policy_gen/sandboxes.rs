//! Shared sandbox builders for policy generation.
//!
//! Provides canonical sandbox definitions as Starlark AST, ensuring all
//! generators produce identical sandbox shapes.

use clash_starlark::codegen::ast::{DictEntry, Expr, Stmt};
use clash_starlark::codegen::builder::*;

/// Build the `project_files` sandbox definition: `$PWD` (r/w/c, follow worktrees)
/// and `$HOME/.claude` (r/w/c). Returns a `(comment, assign)` pair of statements.
pub fn project_files_sandbox() -> Vec<Stmt> {
    let fs_dict = Expr::dict(vec![
        DictEntry::new(
            Expr::call_kwargs(
                "subpath",
                vec![Expr::string("$PWD")],
                vec![("follow_worktrees", Expr::ident("True"))],
            ),
            Expr::call("allow", vec![Expr::string("rwc")]),
        ),
        DictEntry::new(
            Expr::call("glob", vec![Expr::string("$HOME/.claude/**")]),
            Expr::call("allow", vec![Expr::string("rwc")]),
        ),
    ]);
    let sb = sandbox("project_files", vec![("default", ask()), ("fs", fs_dict)]);
    vec![
        Stmt::comment("Sandbox for file-access tools (scoped to project + ~/.claude)"),
        Stmt::assign("project_files", sb),
    ]
}

/// Name of the project_files sandbox, for use in `allow(sandbox=...)` references.
pub const PROJECT_FILES_SANDBOX: &str = "project_files";

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn project_files_sandbox_produces_statements() {
        let stmts = project_files_sandbox();
        assert_eq!(stmts.len(), 2, "expected comment + assign");
        assert!(matches!(&stmts[0], Stmt::Comment(_)));
        assert!(matches!(&stmts[1], Stmt::Assign { .. }));
    }

    #[test]
    fn project_files_sandbox_compiles() {
        let stmts = project_files_sandbox();
        let code = clash_starlark::codegen::serialize(&stmts);
        assert!(
            code.contains("project_files"),
            "should define project_files"
        );
        assert!(code.contains("$PWD"), "should reference $PWD");
        assert!(
            code.contains("$HOME/.claude"),
            "should reference $HOME/.claude"
        );
    }
}
