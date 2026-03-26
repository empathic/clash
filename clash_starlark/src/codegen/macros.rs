//! Convenience macros for building Starlark AST nodes.

/// Build a `match({...})` expression from a nested tree literal.
///
/// Eliminates the `MatchKey`/`MatchValue`/`.into()` ceremony.
///
/// ```ignore
/// match_tree! {
///     "Bash" => {
///         "git" => {
///             "push" => {
///                 "--force" => deny(),
///                 "--force-with-lease" => deny(),
///             },
///             "reset" => {
///                 "--hard" => deny(),
///             },
///         },
///     },
/// }
///
/// // Tuple keys:
/// match_tree! {
///     "Bash" => {
///         ("git", "cargo", "npm") => allow(),
///     },
/// }
/// ```
#[macro_export]
macro_rules! match_tree {
    ($($tt:tt)*) => {
        $crate::codegen::builder::match_rule($crate::__match_entries!($($tt)*))
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __match_entries {
    // Accumulator pattern: parse entries one at a time
    () => { vec![] };

    // Tuple key => nested dict (must come before single-key rules)
    (($($key:literal),+ $(,)?) => { $($inner:tt)* } $(, $($rest:tt)*)?) => {{
        let mut v = vec![(
            $crate::codegen::builder::MatchKey::Tuple(vec![$($key.to_owned()),+]),
            $crate::codegen::builder::MatchValue::Nested($crate::__match_entries!($($inner)*)),
        )];
        $(v.extend($crate::__match_entries!($($rest)*));)?
        v
    }};

    // Tuple key => effect expression
    (($($key:literal),+ $(,)?) => $effect:expr $(, $($rest:tt)*)?) => {{
        let mut v = vec![(
            $crate::codegen::builder::MatchKey::Tuple(vec![$($key.to_owned()),+]),
            $crate::codegen::builder::MatchValue::Effect($effect),
        )];
        $(v.extend($crate::__match_entries!($($rest)*));)?
        v
    }};

    // Single key => nested dict (key can be a literal or runtime variable)
    ($key:expr => { $($inner:tt)* } $(, $($rest:tt)*)?) => {{
        let mut v = vec![(
            $crate::codegen::builder::MatchKey::from($key),
            $crate::codegen::builder::MatchValue::Nested($crate::__match_entries!($($inner)*)),
        )];
        $(v.extend($crate::__match_entries!($($rest)*));)?
        v
    }};

    // Single key => effect expression
    ($key:expr => $effect:expr $(, $($rest:tt)*)?) => {{
        let mut v = vec![(
            $crate::codegen::builder::MatchKey::from($key),
            $crate::codegen::builder::MatchValue::Effect($effect),
        )];
        $(v.extend($crate::__match_entries!($($rest)*));)?
        v
    }};
}

/// Build a kwargs vec with automatic `Expr` wrapping via `Into<Expr>`.
///
/// ```ignore
/// kwargs!(read = true, write = true)
/// // → vec![("read", Expr::Bool(true)), ("write", Expr::Bool(true))]
///
/// kwargs!(name = "cwd")
/// // → vec![("name", Expr::String("cwd".into()))]
///
/// kwargs!(sandbox = some_expr)
/// // → vec![("sandbox", some_expr)]  (Expr passes through via From<Expr>)
/// ```
#[macro_export]
macro_rules! kwargs {
    ($($key:ident = $val:expr),* $(,)?) => {
        vec![$((stringify!($key), <$crate::codegen::ast::Expr as From<_>>::from($val))),*]
    };
}

#[cfg(test)]
mod tests {
    use crate::codegen::ast::{Expr, Stmt};
    use crate::codegen::builder::*;
    use crate::codegen::serialize::serialize;

    #[test]
    fn match_tree_simple() {
        let expr = match_tree! {
            "Bash" => allow(),
        };
        let src = serialize(&[Stmt::Expr(expr)]);
        assert_eq!(src, "match({\"Bash\": allow()})\n");
    }

    #[test]
    fn match_tree_nested() {
        let expr = match_tree! {
            "Bash" => {
                "git" => {
                    "push" => {
                        "--force" => deny(),
                    },
                },
            },
        };
        let src = serialize(&[Stmt::Expr(expr)]);
        assert!(src.contains("\"Bash\""));
        assert!(src.contains("\"git\""));
        assert!(src.contains("\"--force\": deny()"));
    }

    #[test]
    fn match_tree_multiple_entries() {
        let expr = match_tree! {
            "Bash" => {
                "push" => {
                    "--force" => deny(),
                    "--force-with-lease" => deny(),
                },
                "reset" => {
                    "--hard" => deny(),
                },
            },
        };
        let src = serialize(&[Stmt::Expr(expr)]);
        assert!(src.contains("\"--force\": deny()"));
        assert!(src.contains("\"--force-with-lease\": deny()"));
        assert!(src.contains("\"--hard\": deny()"));
    }

    #[test]
    fn match_tree_tuple_key() {
        let expr = match_tree! {
            "Bash" => {
                ("git", "cargo") => allow(),
            },
        };
        let src = serialize(&[Stmt::Expr(expr)]);
        assert!(src.contains("(\"git\", \"cargo\"): allow()"));
    }

    #[test]
    fn kwargs_bools() {
        let kw: Vec<(&str, Expr)> = kwargs!(read = true, write = false);
        assert_eq!(kw.len(), 2);
        assert_eq!(kw[0], ("read", Expr::Bool(true)));
        assert_eq!(kw[1], ("write", Expr::Bool(false)));
    }

    #[test]
    fn kwargs_strings() {
        let kw: Vec<(&str, Expr)> = kwargs!(name = "cwd");
        assert_eq!(kw[0], ("name", Expr::String("cwd".to_owned())));
    }

    #[test]
    fn kwargs_exprs() {
        let kw: Vec<(&str, Expr)> = kwargs!(default = deny(), sandbox = allow());
        assert_eq!(kw.len(), 2);
    }

    #[test]
    fn match_tree_runtime_key() {
        let bin_name = "git";
        let expr = match_tree! {
            "Bash" => {
                bin_name => allow(),
            },
        };
        let src = serialize(&[Stmt::Expr(expr)]);
        assert!(src.contains("\"git\": allow()"));
    }

    #[test]
    fn full_example_with_macros() {
        let stmts = vec![
            load_std(&["match", "tool", "policy", "allow", "deny", "ask"]),
            Stmt::Blank,
            Stmt::def("main", vec![Stmt::Return(policy(
                ask(),
                vec![
                    match_tree! {
                        "Bash" => {
                            ("git", "cargo") => allow(),
                        },
                    },
                    tool(&["Read"]).allow(),
                ],
                None,
            ))]),
        ];
        let src = serialize(&stmts);
        assert!(src.contains("(\"git\", \"cargo\"): allow()"));
        assert!(src.contains("tool([\"Read\"]).allow()"));
    }
}
