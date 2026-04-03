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

/// Describes where an expression sits relative to its parent node.
#[derive(Clone, Debug)]
pub enum Ancestor {
    /// Inside a function/method call. `func_name` is best-effort
    /// (`Some` for `Ident` and `Attr` func exprs, `None` otherwise).
    Call {
        func_name: Option<String>,
    },
    List,
    Tuple,
    DictKey,
    DictValue,
    Attr {
        name: String,
    },
    Commented,
    Assign {
        target: String,
    },
    FuncDef {
        name: String,
    },
    FuncParam {
        name: String,
    },
    Return,
    ExprStmt,
}

/// Accumulated context passed through the tree walk.
/// Tracks the chain of ancestors so visitors can make decisions
/// based on where an expression sits in the tree.
#[derive(Default)]
pub struct WalkCtx {
    ancestors: Vec<Ancestor>,
}

impl WalkCtx {
    pub fn parent(&self) -> Option<&Ancestor> {
        self.ancestors.last()
    }

    pub fn ancestors(&self) -> &[Ancestor] {
        &self.ancestors
    }

    /// True if the immediate parent is a call to `name`.
    pub fn parent_is_call(&self, name: &str) -> bool {
        matches!(
            self.parent(),
            Some(Ancestor::Call { func_name: Some(n) }) if n == name
        )
    }

    /// True if any ancestor is a call to `name`.
    pub fn inside_call(&self, name: &str) -> bool {
        self.ancestors
            .iter()
            .any(|a| matches!(a, Ancestor::Call { func_name: Some(n) } if n == name))
    }

    fn push(&mut self, ancestor: Ancestor) {
        self.ancestors.push(ancestor);
    }

    fn pop(&mut self) {
        self.ancestors.pop();
    }
}

pub trait Transform {
    fn visit_stmt(&mut self, _stmt: &Stmt, _ctx: &WalkCtx) -> TransformOp<Stmt> {
        TransformOp::Keep
    }

    fn visit_expr(&mut self, _expr: &Expr, _ctx: &WalkCtx) -> TransformOp<Expr> {
        TransformOp::Keep
    }

    /// Visit an expression, then recurse into its children.
    fn walk_expr(&mut self, expr: &Expr, ctx: &mut WalkCtx) -> Expr {
        let expr = match self.visit_expr(expr, ctx) {
            TransformOp::Keep => expr.clone(),
            TransformOp::Replace(e) => e,
            _ => expr.clone(),
        };
        self.recurse_expr(expr, ctx)
    }

    /// Recurse into an expression's children, calling `walk_expr` on each.
    fn recurse_expr(&mut self, expr: Expr, ctx: &mut WalkCtx) -> Expr {
        match expr {
            Expr::List(items) => {
                ctx.push(Ancestor::List);
                let out = Expr::List(items.iter().map(|e| self.walk_expr(e, ctx)).collect());
                ctx.pop();
                out
            }
            Expr::Tuple(items) => {
                ctx.push(Ancestor::Tuple);
                let out = Expr::Tuple(items.iter().map(|e| self.walk_expr(e, ctx)).collect());
                ctx.pop();
                out
            }
            Expr::Dict(entries) => {
                let out = Expr::Dict(
                    entries
                        .iter()
                        .map(|e| {
                            ctx.push(Ancestor::DictKey);
                            let key = self.walk_expr(&e.key, ctx);
                            ctx.pop();
                            ctx.push(Ancestor::DictValue);
                            let value = self.walk_expr(&e.value, ctx);
                            ctx.pop();
                            DictEntry { key, value }
                        })
                        .collect(),
                );
                out
            }
            Expr::Call { func, args, kwargs } => {
                let func_name = match func.as_ref() {
                    Expr::Ident(name) => Some(name.clone()),
                    Expr::Attr { attr, .. } => Some(attr.clone()),
                    _ => None,
                };
                let new_func = Box::new(self.walk_expr(&func, ctx));
                ctx.push(Ancestor::Call { func_name });
                let new_args = args.iter().map(|e| self.walk_expr(e, ctx)).collect();
                let new_kwargs = kwargs
                    .iter()
                    .map(|(k, v)| (k.clone(), self.walk_expr(v, ctx)))
                    .collect();
                ctx.pop();
                Expr::Call {
                    func: new_func,
                    args: new_args,
                    kwargs: new_kwargs,
                }
            }
            Expr::Attr { value, attr } => {
                ctx.push(Ancestor::Attr { name: attr.clone() });
                let new_value = Box::new(self.walk_expr(&value, ctx));
                ctx.pop();
                Expr::Attr {
                    value: new_value,
                    attr,
                }
            }
            Expr::Commented { comment, expr } => {
                ctx.push(Ancestor::Commented);
                let new_expr = Box::new(self.walk_expr(&expr, ctx));
                ctx.pop();
                Expr::Commented {
                    comment,
                    expr: new_expr,
                }
            }
            other => other,
        }
    }

    /// Recurse into a statement's child expressions and sub-statements.
    fn recurse_stmt(&mut self, stmt: Stmt, ctx: &mut WalkCtx) -> Stmt {
        match stmt {
            Stmt::Assign { target, value } => {
                ctx.push(Ancestor::Assign {
                    target: target.clone(),
                });
                let value = self.walk_expr(&value, ctx);
                ctx.pop();
                Stmt::Assign { target, value }
            }
            Stmt::FuncDef { name, params, body } => {
                ctx.push(Ancestor::FuncDef { name: name.clone() });
                let params = params
                    .into_iter()
                    .map(|p| {
                        let default = p.default.map(|e| {
                            ctx.push(Ancestor::FuncParam {
                                name: p.name.clone(),
                            });
                            let out = self.walk_expr(&e, ctx);
                            ctx.pop();
                            out
                        });
                        Param {
                            name: p.name,
                            default,
                        }
                    })
                    .collect();
                let body = self.walk_stmts(body, ctx);
                ctx.pop();
                Stmt::FuncDef { name, params, body }
            }
            Stmt::Return(expr) => {
                ctx.push(Ancestor::Return);
                let expr = self.walk_expr(&expr, ctx);
                ctx.pop();
                Stmt::Return(expr)
            }
            Stmt::Expr(expr) => {
                ctx.push(Ancestor::ExprStmt);
                let expr = self.walk_expr(&expr, ctx);
                ctx.pop();
                Stmt::Expr(expr)
            }
            other => other,
        }
    }

    fn walk_stmts(&mut self, stmts: Vec<Stmt>, ctx: &mut WalkCtx) -> Vec<Stmt> {
        let mut out = Vec::with_capacity(stmts.len());
        for stmt in stmts {
            match self.visit_stmt(&stmt, ctx) {
                TransformOp::Keep => out.push(self.recurse_stmt(stmt, ctx)),
                TransformOp::Replace(s) => out.push(self.recurse_stmt(s, ctx)),
                TransformOp::Expand(items) => {
                    out.extend(items.into_iter().map(|s| self.recurse_stmt(s, ctx)));
                }
                TransformOp::Remove => {}
            }
        }
        out
    }

    fn apply(&mut self, stmts: Vec<Stmt>) -> Vec<Stmt> {
        self.walk_stmts(stmts, &mut WalkCtx::default())
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
