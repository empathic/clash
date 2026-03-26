//! Starlark code generation and (future) CST manipulation.
//!
//! Provides typed AST construction and pretty-printing for Starlark source,
//! backed by tree-sitter-starlark for future round-trip editing.

pub mod ast;
pub mod builder;
#[macro_use]
pub mod macros;
pub mod serialize;

pub use ast::{DictEntry, Expr, Stmt};
pub use serialize::{expr_to_string, serialize};
