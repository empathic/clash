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
    tmp = MergeConsecutiveWhens.apply(tmp);
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

/// Merge consecutive `when()` calls in a `policy()` rules list into a single
/// `when()` with a combined dict.
///
/// Before:
/// ```starlark
/// rules = [
///     when({"Bash": {("git", "cargo"): allow()}}),
///     when({"Read": allow()}),
///     when({"Write": allow()}),
/// ]
/// ```
///
/// After:
/// ```starlark
/// rules = [
///     when({
///         "Bash": {("git", "cargo"): allow()},
///         "Read": allow(),
///         "Write": allow(),
///     }),
/// ]
/// ```
///
/// `Commented` when-calls act as group separators — a comment breaks the run
/// and starts a new group.
struct MergeConsecutiveWhens;

impl MergeConsecutiveWhens {
    /// Extract the dict entries from a `when({...})` call expression.
    /// Returns `None` if the expression is not a simple `when(dict)`.
    fn when_dict_entries(expr: &Expr) -> Option<&Vec<DictEntry>> {
        match expr {
            Expr::Call { func, args, kwargs }
                if matches!(func.as_ref(), Expr::Ident(n) if n == "when")
                    && args.len() == 1
                    && kwargs.is_empty() =>
            {
                match &args[0] {
                    Expr::Dict(entries) => Some(entries),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Merge a run of when-dict expressions into a single when call.
    fn merge_when_entries(entries: Vec<DictEntry>) -> Expr {
        Expr::Call {
            func: Box::new(Expr::Ident("when".into())),
            args: vec![Expr::Dict(entries)],
            kwargs: vec![],
        }
    }
}

impl Transform for MergeConsecutiveWhens {
    fn visit_expr(&mut self, expr: &Expr, ctx: &WalkCtx) -> TransformOp<Expr> {
        // Only operate on lists inside a policy() call (the rules list).
        if !ctx.inside_call("policy") {
            return TransformOp::Keep;
        }

        let Expr::List(items) = expr else {
            return TransformOp::Keep;
        };

        // Scan for consecutive when() calls and merge them.
        let mut result: Vec<Expr> = Vec::with_capacity(items.len());
        let mut pending_entries: Vec<DictEntry> = Vec::new();

        for item in items {
            // Unwrap Commented nodes — a comment breaks the group.
            if let Expr::Commented { .. } = item {
                // Flush any pending when-merge
                if !pending_entries.is_empty() {
                    result.push(Self::merge_when_entries(std::mem::take(&mut pending_entries)));
                }
                result.push(item.clone());
                continue;
            }

            if let Some(entries) = Self::when_dict_entries(item) {
                pending_entries.extend(entries.iter().cloned());
            } else {
                // Non-when item: flush pending, then add the item
                if !pending_entries.is_empty() {
                    result.push(Self::merge_when_entries(std::mem::take(&mut pending_entries)));
                }
                result.push(item.clone());
            }
        }

        // Flush final group
        if !pending_entries.is_empty() {
            result.push(Self::merge_when_entries(pending_entries));
        }

        // Only replace if we actually merged something (fewer items)
        if result.len() < items.len() {
            TransformOp::Replace(Expr::List(result))
        } else {
            TransformOp::Keep
        }
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

        merge_consecutive_whens_single_key:
            r#"
                    load("@clash//std.star", "when", "policy", "settings", "allow", "ask")

                    settings(default = ask())

                    policy(
                        "test",
                        default = ask(),
                        rules = [
                            when({"Read": allow()}),
                            when({"Write": allow()}),
                        ],
                    )"# => r#"
                    load("@clash//std.star", "when", "policy", "settings", "allow", "ask")

                    settings(default = ask())

                    policy("test", default = ask(), rules = [when({("Read", "Write"): allow()})])
                    "#,

        merge_whens_preserves_comments_as_separators:
            r#"
                    load("@clash//std.star", "when", "policy", "settings", "allow", "deny", "ask")

                    settings(default = ask())

                    policy(
                        "test",
                        default = ask(),
                        rules = [
                            # denied
                            when({"Read": {".env": deny()}}),
                            # allowed
                            when({"Bash": {"git": allow()}}),
                            when({"Read": allow()}),
                            when({"Write": allow()}),
                        ],
                    )"# => r#"
                    load("@clash//std.star", "when", "policy", "settings", "allow", "deny", "ask")

                    settings(default = ask())

                    policy(
                        "test",
                        default = ask(),
                        rules = [
                            # denied
                            when({"Read": {".env": deny()}}),
                            # allowed
                            when({"Bash": {"git": allow()}}),
                            when({("Read", "Write"): allow()}),
                        ],
                    )
                    "#,
    }
}
