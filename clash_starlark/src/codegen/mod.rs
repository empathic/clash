//! Starlark code generation and round-trip editing.
//!
//! Provides typed AST construction, parsing, mutation, and pretty-printing
//! for Starlark source, backed by tree-sitter-starlark for round-trip editing.

pub mod ast;
pub mod builder;
pub mod document;
pub mod from_manifest;
#[macro_use]
pub mod macros;
pub mod mutate;
pub mod parser;
pub mod serialize;

pub use ast::{DictEntry, Expr, Stmt};
pub use document::StarDocument;
pub use parser::parse;
pub use serialize::{expr_to_string, serialize};
