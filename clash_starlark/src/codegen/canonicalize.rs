use std::cmp::Ordering;

use anyhow::Result;

use crate::codegen::Stmt;

pub(crate) fn canonicalize(stmts: &mut Vec<Stmt>) -> Result<()> {
    sort_loads(stmts)?;
    Ok(())
}

fn is_internal_load(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Load { module, .. } => module.starts_with("@clash//"),
        _ => false,
    }
}

fn sort_loads(stmts: &mut Vec<Stmt>) -> Result<()> {
    stmts.sort_by(|a, b| match (a, b) {
        (Stmt::Load { module: moda, .. }, Stmt::Load { module: modb, .. }) => {
            match (moda.split_once("//"), modb.split_once("//")) {
                (None, None) => moda.cmp(modb),
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => a.cmp(&b),
            }
        }
        _ => std::cmp::Ordering::Equal,
    });

    // find the break
    if let Some(idx) = stmts.windows(2).enumerate().find_map(|(idx, pairs)| {
        match (is_internal_load(&pairs[0]), is_internal_load(&pairs[1])) {
            (true, true) => None,
            (true, false) => Some(idx + 1),
            (false, true) => {
                unreachable!("internal loads should have been sorted above at this point")
            }
            (false, false) => None,
        }
    }) {
        stmts.insert(idx, Stmt::Blank);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::codegen::StarDocument;
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn imports_are_sorted() -> anyhow::Result<()> {
        let mut doc = StarDocument::from_source(
            r#"
load("@clash//b.star", "x")
load("@clash//a.star", "y")
load("@clash//d.star", "o")
load("@clash//e.star", "w")
load("c.star", "z")
"#
            .into(),
            "test.star".into(),
        )?;
        doc.canonicalize()?;

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
}
