//! StarDocument — a parsed `.star` policy file holding the mutable AST.
//!
//! The AST (`Vec<Stmt>`) is the source of truth. A `PolicyManifest` can be
//! derived on demand by serializing the AST back to Starlark source, evaluating
//! it through the Starlark interpreter, and deserializing the resulting JSON.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::codegen::ast::Transform;

use super::ast::Stmt;
use super::parser;
use super::serialize::serialize;

/// A parsed `.star` policy file, holding the mutable AST.
#[derive(Debug, Clone)]
pub struct StarDocument {
    /// The mutable Starlark AST — source of truth.
    pub stmts: Vec<Stmt>,
    /// The original source text (for diffing on save).
    pub original_source: String,
    /// Path to the `.star` file on disk.
    pub path: PathBuf,
}

impl StarDocument {
    /// Parse a `.star` file from disk.
    pub fn open(path: &Path) -> Result<Self> {
        let source = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::from_source(source, path.to_path_buf())
    }

    /// Create from source text and path (for testing or in-memory construction).
    pub fn from_source(source: String, path: PathBuf) -> Result<Self> {
        let stmts = parser::parse(&source)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        Ok(StarDocument {
            stmts,
            original_source: source,
            path,
        })
    }

    /// Serialize the current AST to Starlark source text.
    pub fn to_source(&self) -> String {
        let mut cpy = self.stmts.clone();
        crate::codegen::canonicalize::canonicalize(&mut cpy)
            .expect("unable to canonicalize starlark code");

        serialize(&cpy)
    }

    /// Evaluate the current AST through the Starlark evaluator,
    /// returning the compiled JSON string.
    ///
    /// The pipeline is: serialize AST → evaluate Starlark → JSON output.
    pub fn evaluate_to_json(&self) -> Result<String> {
        let source = self.to_source();
        let base_dir = self.path.parent().unwrap_or(Path::new("."));
        let filename = self.path.display().to_string();
        let output = crate::evaluate(&source, &filename, base_dir)?;
        Ok(output.json)
    }

    /// Write the serialized AST back to disk.
    pub fn save(&mut self) -> Result<()> {
        let source = self.to_source();
        std::fs::write(&self.path, &source)
            .with_context(|| format!("failed to write {}", self.path.display()))?;
        self.original_source = source;
        Ok(())
    }

    /// Returns true if the AST has been modified since the last save/open.
    pub fn is_dirty(&self) -> bool {
        self.to_source() != self.original_source
    }

    pub fn transform(&self, mut t: impl Transform) -> Self {
        let mut x = self.clone();
        x.stmts = t.apply(x.stmts);
        x
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::path::PathBuf;

    fn doc_from_str(src: &str) -> StarDocument {
        StarDocument::from_source(src.to_string(), PathBuf::from("test.star")).unwrap()
    }

    #[test]
    fn open_and_serialize() {
        let src = r#"load("@clash//std.star", "tool", "policy", "settings", "allow", "ask")

settings(default = ask())

policy("test", default = ask(), rules = [tool(["Read"]).allow()])
"#;
        let doc = doc_from_str(src);
        let reserialized = doc.to_source();
        // Should parse back to the same AST
        let doc2 =
            StarDocument::from_source(reserialized.clone(), PathBuf::from("test.star")).unwrap();
        assert_eq!(doc.stmts, doc2.stmts);
    }

    #[test]
    fn evaluate_produces_json() {
        let src = r#"load("@clash//std.star", "policy", "settings", "allow", "ask")

settings(default = ask())

policy("test", {"Read": allow()}, default = ask())
"#;
        let doc = doc_from_str(src);
        let json = doc.evaluate_to_json().unwrap();
        // Should contain expected fields
        assert!(json.contains("\"tree\""), "expected tree in JSON: {json}");
        assert!(json.contains("Read"), "expected Read in JSON: {json}");
    }

    #[test]
    fn is_dirty_after_mutation() {
        let src = r#"x = 1
"#;
        let mut doc = doc_from_str(src);
        assert!(!doc.is_dirty());
        doc.stmts.push(Stmt::Assign {
            target: "y".to_string(),
            value: super::super::ast::Expr::Int(2),
        });
        assert!(doc.is_dirty());
    }

    #[test]
    fn save_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.star");
        let src = r#"load("@clash//std.star", "allow", "policy", "settings")

settings(default = allow())

policy("test", default = allow(), rules = [])
"#;
        std::fs::write(&path, src).unwrap();

        let mut doc = StarDocument::open(&path).unwrap();
        assert!(!doc.is_dirty());

        // Mutate and save
        doc.stmts.push(Stmt::Comment("added".to_string()));
        assert!(doc.is_dirty());
        doc.save().unwrap();
        assert!(!doc.is_dirty());

        // Re-open and verify
        let doc2 = StarDocument::open(&path).unwrap();
        assert!(doc2.to_source().contains("# added"));
    }
}
