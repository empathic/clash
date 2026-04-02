use std::cmp::Ordering;

use anyhow::Result;
use std::collections::HashMap;

use crate::codegen::{
    DictEntry, Expr, Stmt,
    ast::{self, Transform, TransformOp, WalkCtx},
};

pub(crate) fn canonicalize(stmts: &mut Vec<Stmt>) -> Result<()> {
    let mut tmp = std::mem::take(stmts);
    tmp = SortLoads {}.apply(tmp);
    tmp = SeparateInternalExternalLoads::default().apply(tmp);
    tmp = CollapseDictSiblingsSameResult.apply(tmp);
    tmp = NoDoubleBlanks::default().apply(tmp);
    tmp = NoEndOnBlank {}.apply(tmp);
    *stmts = tmp;
    Ok(())
}

struct SortLoads;

impl ast::Transform for SortLoads {
    fn apply(&mut self, mut stmts: Vec<Stmt>) -> Vec<Stmt> {
        stmts.sort_by(|a, b| match (a, b) {
            (Stmt::Load { module: moda, .. }, Stmt::Load { module: modb, .. }) => {
                match (moda.split_once("//"), modb.split_once("//")) {
                    (None, None) => moda.cmp(modb),
                    (None, Some(_)) => Ordering::Greater,
                    (Some(_), None) => Ordering::Less,
                    (Some(a), Some(b)) => a.cmp(&b),
                }
            }
            // loads always go at the top
            (Stmt::Load { .. }, _) => Ordering::Less,
            _ => std::cmp::Ordering::Equal,
        });
        stmts
    }
}

#[derive(Default)]
struct SeparateInternalExternalLoads {
    last: Option<Stmt>,
}

impl ast::Transform for SeparateInternalExternalLoads {
    fn visit_stmt(&mut self, current: &Stmt, _ctx: &WalkCtx) -> TransformOp<Stmt> {
        fn is_internal_load(stmt: &Stmt) -> bool {
            match stmt {
                Stmt::Load { module, .. } => module.starts_with("@clash//"),
                _ => false,
            }
        }
        let out = match &self.last {
            Some(last) => match (is_internal_load(&last), is_internal_load(&current)) {
                (true, false) if current.is_load() => {
                    TransformOp::Expand(vec![Stmt::Blank, current.clone()])
                }
                _ => TransformOp::Keep,
            },
            _ => TransformOp::Keep,
        };
        self.last = Some(current.clone());
        out
    }
}

struct NoEndOnBlank;
impl Transform for NoEndOnBlank {
    fn apply(&mut self, mut stmts: Vec<Stmt>) -> Vec<Stmt> {
        if matches!(stmts.last(), Some(Stmt::Blank)) {
            stmts.pop();
        }
        stmts
    }
}

#[derive(Default)]
struct NoDoubleBlanks {
    last: Option<Stmt>,
}

impl ast::Transform for NoDoubleBlanks {
    fn visit_stmt(&mut self, current: &Stmt, _ctx: &WalkCtx) -> TransformOp<Stmt> {
        let out = match (current, &self.last) {
            (Stmt::Blank, Some(Stmt::Blank)) => TransformOp::Remove,
            _ => TransformOp::Keep,
        };
        self.last = Some(current.clone());
        out
    }
}

struct CollapseDictSiblingsSameResult;

impl Transform for CollapseDictSiblingsSameResult {
    fn visit_expr(&mut self, current: &Expr, ctx: &WalkCtx) -> TransformOp<Expr> {
        if !["when", "sandbox", "policy"]
            .iter()
            .any(|name| ctx.inside_call(name))
        {
            return TransformOp::Keep;
        }

        match current {
            Expr::Dict(items) => {
                let mut m: HashMap<Expr, Vec<Expr>> = HashMap::with_capacity(items.len());
                for i in items {
                    m.entry(i.value.clone()).or_default().push(i.key.clone());
                }
                TransformOp::Replace(Expr::Dict(
                    m.iter()
                        .map(|(value, keys)| {
                            let key = if keys.len() == 1 {
                                keys[0].clone()
                            } else {
                                Expr::Tuple(keys.clone())
                            };
                            DictEntry {
                                key,
                                value: value.clone(),
                            }
                        })
                        .collect(),
                ))
            }
            _ => TransformOp::Keep,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::codegen::StarDocument;
    use indoc::indoc;
    use pretty_assertions::assert_eq;

    /// Generate table-driven canonicalization tests.
    ///
    /// ```ignore
    /// canon_tests! {
    ///     test_name: "input starlark" => "expected output",
    ///     another:   "input"          => "expected",
    /// }
    /// ```
    macro_rules! canon_tests {
        ($($name:ident : $input:expr => $expected:expr),+ $(,)?) => {
            $(
                #[test]
                fn $name() -> anyhow::Result<()> {
                    let doc = StarDocument::from_source(
                        indoc!{$input}.into(),
                        "test.star".into(),
                    )?;
                    assert_eq!(&doc.to_source(), indoc!{$expected});
                    Ok(())
                }
            )+
        };
    }

    canon_tests! {
        imports_are_sorted:
            r#"
                    load("@clash//b.star", "x")
                    load("c.star", "z")
                    load("@clash//a.star", "y")




                    load("@clash//d.star", "o")
                    load("@clash//e.star", "w")


                    "# => r#"load("@clash//a.star", "y")
                    load("@clash//b.star", "x")
                    load("@clash//d.star", "o")
                    load("@clash//e.star", "w")

                    load("c.star", "z")
                    "#,
            dict_collaps_inside_policy:
            r#"
                    load("@clash//std.star", "policy", "allow")

                    policy("test", {
                        "a": allow(),
                        "b": allow(),
                    })"# => r#"
                    load("@clash//std.star", "policy", "allow")

                    policy("test", {("a", "b"): allow()})
                    "#,

        dict_outside_call_unchanged:
            r#"
                    load("@clash//std.star", "allow")

                    x = {
                        "a": allow(),
                        "b": allow(),
                    }"# => r#"
                    load("@clash//std.star", "allow")

                    x = {"a": allow(), "b": allow()}
                    "#,
    }
}
