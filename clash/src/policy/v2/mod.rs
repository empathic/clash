//! Policy language v2 — a functional s-expression policy language.
//!
//! This module provides a capability-based policy language where rules are
//! expressed as `(effect (capability ...))` forms. The compiler resolves
//! includes, sorts rules by specificity, detects conflicts, and produces
//! a decision tree for efficient evaluation.
//!
//! ## Example
//!
//! ```text
//! (default deny "main")
//!
//! (policy "main"
//!   (deny  (exec "git" "push" *))
//!   (allow (exec "git" *))
//!   (allow (fs read (subpath (env PWD))))
//!   (allow (net "github.com")))
//! ```

pub mod ast;
pub mod compile;
pub mod eval;
pub mod ir;
pub mod parse;
pub mod print;
pub mod specificity;

pub use compile::compile_policy;
pub use ir::DecisionTree;
pub use print::print_tree;
