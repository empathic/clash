//! Starlark AST node types for code generation.
//!
//! These types mirror tree-sitter-starlark's node kinds but are mutable and
//! constructable, enabling both programmatic generation and (future) round-trip
//! editing of `.star` files.
//!
//!

#[derive(Clone, Debug)]
pub enum TransformOp<T> {
    Keep,
    Replace(T),
    Expand(Vec<T>),
    Remove,
}

pub trait Transform {
    fn visit_stmt(&mut self, stmt: &Stmt) -> TransformOp<Stmt> {
        match stmt {
            Stmt::Return(expr) => match self.visit_expr(expr) {
                TransformOp::Keep => TransformOp::Keep,
                TransformOp::Replace(expr) => TransformOp::Replace(Stmt::Return(expr)),
                TransformOp::Expand(items) => {
                    unreachable!("replace not supported for returned expressions {:?}", items)
                }
                TransformOp::Remove => TransformOp::Remove,
            },
            Stmt::Expr(expr) => match self.visit_expr(expr) {
                TransformOp::Keep => TransformOp::Keep,
                TransformOp::Replace(expr) => TransformOp::Replace(Stmt::Expr(expr)),
                TransformOp::Expand(items) => {
                    TransformOp::Expand(items.into_iter().map(Stmt::Expr).collect())
                }
                TransformOp::Remove => TransformOp::Remove,
            },
            _ => TransformOp::Keep,
        }
    }

    fn visit_expr(&mut self, _: &Expr) -> TransformOp<Expr> {
        TransformOp::Keep
    }

    fn apply(&mut self, stmts: Vec<Stmt>) -> Vec<Stmt> {
        let mut out = Vec::with_capacity(stmts.len());
        for stmt in stmts {
            match self.visit_stmt(&stmt) {
                TransformOp::Keep => out.push(stmt),
                TransformOp::Replace(s) => out.push(s),
                TransformOp::Expand(items) => out.extend_from_slice(&items),
                TransformOp::Remove => {}
            }
        }
        out
    }
}

/// A top-level statement in a Starlark module.
#[derive(Debug, Clone, PartialEq, Default)]
pub enum Stmt {
    /// `load("module", "name1", "name2", ...)`
    Load { module: String, names: Vec<String> },
    /// `target = value`
    Assign { target: String, value: Expr },
    /// `def name(params): body`
    FuncDef {
        name: String,
        params: Vec<Param>,
        body: Vec<Stmt>,
    },
    /// `return value`
    Return(Expr),
    /// An expression used as a statement.
    Expr(Expr),
    /// `# text`
    Comment(String),
    /// A blank line.
    #[default]
    Blank,
}

/// A function parameter.
#[derive(Debug, Clone, PartialEq, Hash)]
pub struct Param {
    pub name: String,
    pub default: Option<Expr>,
}

/// A Starlark expression.
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum Expr {
    /// A string literal: `"foo"`
    String(String),
    /// A boolean literal: `True` / `False`
    Bool(bool),
    /// An integer literal: `42`
    Int(i64),
    /// `None`
    None,
    /// A bare identifier: `foo`
    Ident(String),
    /// A list literal: `[a, b, c]`
    List(Vec<Expr>),
    /// A tuple literal: `(a, b, c)`
    Tuple(Vec<Expr>),
    /// A dict literal: `{k1: v1, k2: v2}`
    Dict(Vec<DictEntry>),
    /// A function/method call: `func(args, k=v)`
    Call {
        func: Box<Expr>,
        args: Vec<Expr>,
        kwargs: Vec<(String, Expr)>,
    },
    /// Attribute access: `value.attr`
    Attr { value: Box<Expr>, attr: String },
    /// Escape hatch for pre-formatted expressions (e.g. user-entered rules).
    Raw(String),
    /// A comment placed before an expression in a list context.
    /// Serializes as `# text` on its own line followed by the expression.
    Commented { comment: String, expr: Box<Expr> },
}

/// A single key-value entry in a dict literal.
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub struct DictEntry {
    pub key: Expr,
    pub value: Expr,
}

// ---- Convenience constructors ------------------------------------------------

impl Expr {
    pub fn string(s: impl Into<String>) -> Self {
        Expr::String(s.into())
    }

    pub fn bool(b: bool) -> Self {
        Expr::Bool(b)
    }

    pub fn ident(s: impl Into<String>) -> Self {
        Expr::Ident(s.into())
    }

    pub fn call(func: impl Into<String>, args: Vec<Expr>) -> Self {
        Expr::Call {
            func: Box::new(Expr::Ident(func.into())),
            args,
            kwargs: vec![],
        }
    }

    pub fn call_kwargs(
        func: impl Into<String>,
        args: Vec<Expr>,
        kwargs: Vec<(impl Into<String>, Expr)>,
    ) -> Self {
        Expr::Call {
            func: Box::new(Expr::Ident(func.into())),
            args,
            kwargs: kwargs.into_iter().map(|(k, v)| (k.into(), v)).collect(),
        }
    }

    /// Chained method call: `self.method(args, kwargs)`
    pub fn method(
        self,
        method: impl Into<String>,
        args: Vec<Expr>,
        kwargs: Vec<(impl Into<String>, Expr)>,
    ) -> Self {
        Expr::Call {
            func: Box::new(Expr::Attr {
                value: Box::new(self),
                attr: method.into(),
            }),
            args,
            kwargs: kwargs.into_iter().map(|(k, v)| (k.into(), v)).collect(),
        }
    }

    /// Attribute access: `self.attr`
    pub fn attr(self, attr: impl Into<String>) -> Self {
        Expr::Attr {
            value: Box::new(self),
            attr: attr.into(),
        }
    }

    pub fn list(items: Vec<Expr>) -> Self {
        Expr::List(items)
    }

    pub fn tuple(items: Vec<Expr>) -> Self {
        Expr::Tuple(items)
    }

    pub fn dict(entries: Vec<DictEntry>) -> Self {
        Expr::Dict(entries)
    }

    pub fn raw(s: impl Into<String>) -> Self {
        Expr::Raw(s.into())
    }

    // ---- Chainable DSL methods (Clash policy shortcuts) ----------------------

    /// Chain `.allow()` — e.g. `cwd().allow()`
    pub fn allow(self) -> Self {
        self.method("allow", vec![], Vec::<(&str, Expr)>::new())
    }

    /// Chain `.deny()` — e.g. `cwd().deny()`
    pub fn deny(self) -> Self {
        self.method("deny", vec![], Vec::<(&str, Expr)>::new())
    }

    /// Chain `.ask()` — e.g. `cwd().ask()`
    pub fn ask(self) -> Self {
        self.method("ask", vec![], Vec::<(&str, Expr)>::new())
    }

    /// Chain `.sandbox(expr)` — e.g. `cwd().sandbox(_fs_box)`
    pub fn sandbox(self, sb: Expr) -> Self {
        self.method("sandbox", vec![sb], Vec::<(&str, Expr)>::new())
    }

    /// Chain `.recurse()` — e.g. `cwd().recurse()`
    pub fn recurse(self) -> Self {
        self.method("recurse", vec![], Vec::<(&str, Expr)>::new())
    }

    /// Chain `.child(name)` — e.g. `home().child(".claude")`
    pub fn child(self, name: impl Into<String>) -> Self {
        self.method(
            "child",
            vec![Expr::string(name)],
            Vec::<(&str, Expr)>::new(),
        )
    }

    /// Chain `.allow(read = True, write = True)` with keyword args.
    pub fn allow_kwargs(self, kwargs: Vec<(impl Into<String>, Expr)>) -> Self {
        self.method("allow", vec![], kwargs)
    }

    pub fn commented(comment: impl Into<String>, expr: Expr) -> Self {
        Expr::Commented {
            comment: comment.into(),
            expr: Box::new(expr),
        }
    }
}

impl DictEntry {
    pub fn new(key: Expr, value: Expr) -> Self {
        Self { key, value }
    }
}

impl Stmt {
    pub fn is_load(&self) -> bool {
        matches!(self, Self::Load { .. })
    }
    pub fn load(module: impl Into<String>, names: &[&str]) -> Self {
        Stmt::Load {
            module: module.into(),
            names: names.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    pub fn assign(target: impl Into<String>, value: Expr) -> Self {
        Stmt::Assign {
            target: target.into(),
            value,
        }
    }

    pub fn def(name: impl Into<String>, body: Vec<Stmt>) -> Self {
        Stmt::FuncDef {
            name: name.into(),
            params: vec![],
            body,
        }
    }

    pub fn comment(text: impl Into<String>) -> Self {
        Stmt::Comment(text.into())
    }
}

// ---- From impls (used by kwargs! macro) --------------------------------------

impl From<bool> for Expr {
    fn from(b: bool) -> Self {
        Expr::Bool(b)
    }
}

impl From<&str> for Expr {
    fn from(s: &str) -> Self {
        Expr::String(s.to_owned())
    }
}

impl From<i64> for Expr {
    fn from(n: i64) -> Self {
        Expr::Int(n)
    }
}
