//! Path builders for filesystem permission entries.
//!
//! Each path builder (cwd, home, tempdir, path) produces a `PathValue` that
//! compiles to fs rule JSON fragments.

use std::fmt::{self, Display};

use allocative::Allocative;
use serde_json::{Value as JsonValue, json};
use starlark::starlark_simple_value;
use starlark::values::{NoSerialize, ProvidesStaticType, StarlarkValue, Trace, starlark_value};

use super::effect_str_valid;

/// A filesystem path permission entry.
///
/// Created by `cwd()`, `home()`, `tempdir()`, or `path()`.
/// Compiles to one or more fs rule JSON objects.
#[derive(Debug, Clone, ProvidesStaticType, NoSerialize, Allocative)]
pub struct PathValue {
    #[allocative(skip)]
    pub kind: PathKind,
    #[allocative(skip)]
    pub perms: Perms,
    #[allocative(skip)]
    pub children: Vec<PathChild>,
}

unsafe impl Trace<'_> for PathValue {
    fn trace(&mut self, _tracer: &starlark::values::Tracer<'_>) {}
}

#[derive(Debug, Clone)]
pub struct PathChild {
    pub name: String,
    pub perms: Perms,
}

#[derive(Debug, Clone)]
pub enum PathKind {
    Cwd { follow_worktrees: bool },
    Home,
    Tempdir,
    Static(String),
    Env(String),
}

#[derive(Debug, Clone, Default)]
pub struct Perms {
    pub read: Option<String>,
    pub write: Option<String>,
    pub execute: Option<String>,
    pub allow_all: bool,
}

impl Display for PathValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PathValue({:?})", self.kind)
    }
}

starlark_simple_value!(PathValue);

#[starlark_value(type = "PathValue")]
impl<'v> StarlarkValue<'v> for PathValue {
    fn get_methods() -> Option<&'static starlark::environment::Methods> {
        static RES: starlark::environment::MethodsStatic =
            starlark::environment::MethodsStatic::new();
        RES.methods(path_value_methods)
    }
}

#[starlark::starlark_module]
fn path_value_methods(builder: &mut starlark::environment::MethodsBuilder) {
    fn child(
        this: &PathValue,
        #[starlark(require = pos)] name: &str,
        #[starlark(require = named)] read: Option<&str>,
        #[starlark(require = named)] write: Option<&str>,
        #[starlark(require = named)] execute: Option<&str>,
        #[starlark(require = named, default = false)] allow_all: bool,
    ) -> anyhow::Result<PathValue> {
        let perms = Perms::from_opts(read, write, execute, allow_all)?;
        let mut result = this.clone();
        result.children.push(PathChild {
            name: name.to_string(),
            perms,
        });
        Ok(result)
    }
}

impl PathValue {
    pub fn cwd(
        follow_worktrees: bool,
        read: Option<&str>,
        write: Option<&str>,
        execute: Option<&str>,
        allow_all: bool,
    ) -> anyhow::Result<Self> {
        let perms = Perms::from_opts(read, write, execute, allow_all)?;
        Ok(PathValue {
            kind: PathKind::Cwd { follow_worktrees },
            perms,
            children: vec![],
        })
    }

    pub fn home() -> Self {
        PathValue {
            kind: PathKind::Home,
            perms: Perms::default(),
            children: vec![],
        }
    }

    pub fn tempdir(
        allow_all: bool,
        read: Option<&str>,
        write: Option<&str>,
        execute: Option<&str>,
    ) -> anyhow::Result<Self> {
        let perms = Perms::from_opts(read, write, execute, allow_all)?;
        Ok(PathValue {
            kind: PathKind::Tempdir,
            perms,
            children: vec![],
        })
    }

    pub fn arbitrary(
        path_str: Option<&str>,
        env: Option<&str>,
        read: Option<&str>,
        write: Option<&str>,
        execute: Option<&str>,
        allow_all: bool,
    ) -> anyhow::Result<Self> {
        let kind = match (path_str, env) {
            (Some(p), None) => PathKind::Static(p.to_string()),
            (None, Some(e)) => PathKind::Env(e.to_string()),
            (Some(_), Some(_)) => {
                anyhow::bail!("path() takes either a path string or env=, not both")
            }
            (None, None) => anyhow::bail!("path() requires either a path string or env= argument"),
        };
        let perms = Perms::from_opts(read, write, execute, allow_all)?;
        Ok(PathValue {
            kind,
            perms,
            children: vec![],
        })
    }

    /// Compile this path entry to a list of fs rule JSON objects.
    pub fn to_rules_json(&self) -> Vec<JsonValue> {
        let mut rules = Vec::new();

        let path_expr = self.path_expr_json();
        self.emit_rules(&path_expr, &self.perms, &mut rules);

        for child in &self.children {
            let child_path = json!({
                "join": [path_expr.clone(), {"static": child.name}]
            });
            self.emit_rules(&child_path, &child.perms, &mut rules);
        }

        rules
    }

    fn path_expr_json(&self) -> JsonValue {
        match &self.kind {
            PathKind::Cwd { .. } => json!({"env": "PWD"}),
            PathKind::Home => json!({"env": "HOME"}),
            PathKind::Tempdir => json!({"env": "TMPDIR"}),
            PathKind::Static(p) => json!({"static": p}),
            PathKind::Env(e) => json!({"env": e}),
        }
    }

    fn worktree(&self) -> bool {
        matches!(
            self.kind,
            PathKind::Cwd {
                follow_worktrees: true
            }
        )
    }

    fn emit_rules(&self, path_expr: &JsonValue, perms: &Perms, rules: &mut Vec<JsonValue>) {
        let ops = perms.to_ops();
        if ops.is_empty() {
            return;
        }

        let mut subpath = json!({
            "path": path_expr
        });
        if self.worktree() {
            subpath
                .as_object_mut()
                .unwrap()
                .insert("worktree".into(), json!(true));
        }

        let path_filter = json!({"subpath": subpath});

        // Group ops by effect
        let mut allow_ops = Vec::new();
        let mut deny_ops = Vec::new();
        let mut ask_ops = Vec::new();

        for (op, effect) in &ops {
            match effect.as_str() {
                "allow" => allow_ops.push(op.clone()),
                "deny" => deny_ops.push(op.clone()),
                "ask" => ask_ops.push(op.clone()),
                _ => {}
            }
        }

        for (effect, effect_ops) in [("allow", allow_ops), ("deny", deny_ops), ("ask", ask_ops)] {
            if effect_ops.is_empty() {
                continue;
            }
            let op_pattern = if effect_ops.len() == 1 {
                json!({"single": effect_ops[0]})
            } else {
                json!({"or": effect_ops})
            };
            rules.push(json!({
                "rule": {
                    "effect": effect,
                    "fs": {
                        "op": op_pattern,
                        "path": path_filter
                    }
                }
            }));
        }
    }
}

impl Perms {
    fn from_opts(
        read: Option<&str>,
        write: Option<&str>,
        execute: Option<&str>,
        allow_all: bool,
    ) -> anyhow::Result<Self> {
        if allow_all {
            return Ok(Perms {
                read: Some("allow".into()),
                write: Some("allow".into()),
                execute: Some("allow".into()),
                allow_all: true,
            });
        }
        if let Some(r) = read {
            effect_str_valid(r)?;
        }
        if let Some(w) = write {
            effect_str_valid(w)?;
        }
        if let Some(e) = execute {
            effect_str_valid(e)?;
        }
        Ok(Perms {
            read: read.map(String::from),
            write: write.map(String::from),
            execute: execute.map(String::from),
            allow_all: false,
        })
    }

    /// Return (op_name, effect) pairs for all set permissions.
    fn to_ops(&self) -> Vec<(String, String)> {
        let mut ops = Vec::new();
        if let Some(ref r) = self.read {
            ops.push(("read".into(), r.clone()));
        }
        if let Some(ref w) = self.write {
            ops.push(("write".into(), w.clone()));
            ops.push(("create".into(), w.clone()));
        }
        if let Some(ref e) = self.execute {
            // "execute" maps to delete op in fs terms (process execution control)
            ops.push(("delete".into(), e.clone()));
        }
        ops
    }
}
