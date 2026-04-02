use std::cmp::Ordering;

use anyhow::Result;
use itertools::Itertools;
use std::collections::HashMap;
use tree_sitter::PARSER_HEADER;

use crate::codegen::{
    DictEntry, Expr, Stmt,
    ast::{self, Transform, TransformOp},
};

pub(crate) fn canonicalize(stmts: &mut Vec<Stmt>) -> Result<()> {
    let mut tmp = std::mem::take(stmts);
    tmp = SortLoads {}.apply(tmp);
    tmp = SeparateInternalExternalLoads::default().apply(tmp);
    tmp = CollapseDictSiblingsSameResult {}.apply(tmp);
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
    fn visit_stmt(&mut self, current: &Stmt) -> TransformOp<Stmt> {
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
    fn visit_stmt(&mut self, current: &Stmt) -> TransformOp<Stmt> {
        let out = match (current, &self.last) {
            (Stmt::Blank, Some(Stmt::Blank)) => TransformOp::Remove,
            _ => TransformOp::Keep,
        };
        self.last = Some(current.clone());
        eprintln!("{current:?}{out:?}");
        out
    }
}

#[derive(Default)]
struct CollapseDictSiblingsSameResult {}

impl Transform for CollapseDictSiblingsSameResult {
    fn visit_expr(&mut self, current: &Expr) -> TransformOp<Expr> {
        match current {
            Expr::Dict(items) => {
                let mut m: HashMap<Expr, Vec<Expr>> = HashMap::with_capacity(items.len());
                for i in items {
                    m.entry(i.value.clone()).or_default().push(i.key.clone());
                }
                TransformOp::Replace(Expr::Dict(
                    m.iter()
                        .map(|(value, keys)| DictEntry {
                            key: Expr::Tuple(keys.clone()),
                            value: value.clone(),
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
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn imports_are_sorted() -> anyhow::Result<()> {
        let doc = StarDocument::from_source(
            r#"
load("@clash//b.star", "x")
load("c.star", "z")
load("@clash//a.star", "y")









load("@clash//d.star", "o")
load("@clash//e.star", "w")


"#
            .into(),
            "test.star".into(),
        )?;

        assert_eq!(
            &doc.to_source(),
            r#"load("@clash//a.star", "y")
load("@clash//b.star", "x")
load("@clash//d.star", "o")
load("@clash//e.star", "w")

load("c.star", "z")
"#
        );

        Ok(())
    }
    #[test]
    fn dict_collaps() -> anyhow::Result<()> {
        let doc = StarDocument::from_source(
            r#"
                {
                "a": allow(),
                "b": allow(),
                }
"#
            .into(),
            "test.star".into(),
        )?;

        assert_eq!(
            &doc.to_source(),
            r#"{("a", "b"): allow()}
"#
        );

        Ok(())
    }
}
