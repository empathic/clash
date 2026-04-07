use std::cmp::Ordering;

use anyhow::Result;
use std::collections::HashMap;

use crate::codegen::{
    DictEntry, Expr, Stmt,
    ast::{self, Transform, TransformOp, WalkCtx},
};

pub fn canonicalize(stmts: &mut Vec<Stmt>) -> Result<()> {
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
    /// Extract the dict entries from a plain dict or a legacy `when({...})` call.
    /// Returns `None` if the expression is neither.
    fn dict_entries(expr: &Expr) -> Option<&Vec<DictEntry>> {
        match expr {
            Expr::Dict(entries) => Some(entries),
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

    /// Flush the pending group into the result list.
    fn flush(
        result: &mut Vec<Expr>,
        pending_entries: &mut Vec<DictEntry>,
        pending_comment: &mut Option<String>,
    ) {
        if pending_entries.is_empty() {
            return;
        }
        let merged = Expr::Dict(std::mem::take(pending_entries));
        if let Some(comment) = pending_comment.take() {
            result.push(Expr::commented(comment, merged));
        } else {
            result.push(merged);
        }
    }
}

impl Transform for MergeConsecutiveWhens {
    fn visit_expr(&mut self, expr: &Expr, ctx: &WalkCtx) -> TransformOp<Expr> {
        // Only operate inside a policy() call.
        if !ctx.inside_call("policy") {
            return TransformOp::Keep;
        }

        // Handle merge(...) calls: collapse consecutive plain dicts.
        let items = match expr {
            Expr::Call { func, args, kwargs }
                if matches!(func.as_ref(), Expr::Ident(n) if n == "merge") && kwargs.is_empty() =>
            {
                args
            }
            // Legacy: also handle List form for backwards compat.
            Expr::List(items) => items,
            _ => return TransformOp::Keep,
        };

        // Scan for consecutive dict expressions and merge them.
        // A commented dict starts a new group (flushing any prior group)
        // and subsequent uncommented dicts merge into it.
        let mut result: Vec<Expr> = Vec::with_capacity(items.len());
        let mut pending_entries: Vec<DictEntry> = Vec::new();
        let mut pending_comment: Option<String> = None;

        for item in items {
            // Commented dict — starts a new group with this comment.
            if let Expr::Commented { comment, expr } = item {
                if let Some(entries) = Self::dict_entries(expr) {
                    // Flush any prior group.
                    Self::flush(&mut result, &mut pending_entries, &mut pending_comment);
                    // Start a new group with this comment.
                    pending_comment = Some(comment.clone());
                    pending_entries.extend(entries.iter().cloned());
                    continue;
                }
                // Non-dict commented item: flush and pass through.
                Self::flush(&mut result, &mut pending_entries, &mut pending_comment);
                result.push(item.clone());
                continue;
            }

            if let Some(entries) = Self::dict_entries(item) {
                pending_entries.extend(entries.iter().cloned());
            } else {
                // Non-dict item: flush pending, then add the item
                Self::flush(&mut result, &mut pending_entries, &mut pending_comment);
                result.push(item.clone());
            }
        }

        // Flush final group
        Self::flush(&mut result, &mut pending_entries, &mut pending_comment);

        // Only replace if we actually merged something (fewer items)
        if result.len() < items.len() {
            // Re-wrap: single dict can stand alone, multiple need merge()
            let replacement = if result.len() == 1 {
                result.into_iter().next().unwrap()
            } else {
                Expr::Call {
                    func: Box::new(Expr::Ident("merge".into())),
                    args: result,
                    kwargs: vec![],
                }
            };
            TransformOp::Replace(replacement)
        } else {
            TransformOp::Keep
        }
    }
}

struct CollapseDictSiblingsSameResult;

impl Transform for CollapseDictSiblingsSameResult {
    fn visit_expr(&mut self, current: &Expr, ctx: &WalkCtx) -> TransformOp<Expr> {
        // Only collapse inside merge(), policy() match dicts, not sandbox()
        // fs dicts where path matchers as keys must stay separate.
        if !["merge", "policy"].iter().any(|name| ctx.inside_call(name)) {
            return TransformOp::Keep;
        }

        match current {
            Expr::Dict(items) => {
                // Group entries with the same value, preserving insertion order
                // of the first occurrence of each value.
                let mut groups: Vec<(Expr, Vec<Expr>)> = Vec::new();
                let mut index: HashMap<Expr, usize> = HashMap::new();
                for i in items {
                    if let Some(&idx) = index.get(&i.value) {
                        groups[idx].1.push(i.key.clone());
                    } else {
                        index.insert(i.value.clone(), groups.len());
                        groups.push((i.value.clone(), vec![i.key.clone()]));
                    }
                }
                TransformOp::Replace(Expr::Dict(
                    groups
                        .into_iter()
                        .map(|(value, keys)| {
                            let key = if keys.len() == 1 {
                                keys[0].clone()
                            } else {
                                Expr::Tuple(keys)
                            };
                            DictEntry { key, value }
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

        merge_consecutive_dicts_single_key:
            r#"
                    load("@clash//std.star", "policy", "settings", "allow", "ask")

                    settings(default = ask())

                    policy(
                        "test",
                        merge(
                            {"Read": allow()},
                            {"Write": allow()},
                        ),
                        default = ask(),
                    )"# => r#"
                    load("@clash//std.star", "policy", "settings", "allow", "ask")

                    settings(default = ask())

                    policy("test", {("Read", "Write"): allow()}, default = ask())
                    "#,

        merge_dicts_preserves_comments_as_separators:
            r#"
                    load("@clash//std.star", "policy", "settings", "allow", "deny", "ask")

                    settings(default = ask())

                    policy(
                        "test",
                        merge(
                            # denied
                            {"Read": {".env": deny()}},
                            # allowed
                            {"Bash": {"git": allow()}},
                            {"Read": allow()},
                            {"Write": allow()},
                        ),
                        default = ask(),
                    )"# => r#"
                    load("@clash//std.star", "policy", "settings", "allow", "deny", "ask")

                    settings(default = ask())

                    policy(
                        "test",
                        merge(
                            # denied
                            {"Read": {".env": deny()}},
                            # allowed
                            {"Bash": {"git": allow()}, ("Read", "Write"): allow()},
                        ),
                        default = ask(),
                    )
                    "#,
    }
}
