//! Schema for the clash policy DSL surface.
//!
//! Provides a canonical list of top-level builtins, their signatures, and
//! docstrings. This is the single source of truth that drives completion,
//! hover, and other language features.
//!
//! The builtins here are sourced from `clash_starlark/stdlib/std.star` where
//! the full DSL is defined. See also `clash_starlark/src/globals.rs` for the
//! Rust-native registrations (_policy_impl, _register_settings, etc.).

pub mod types;
pub use types::{Builtin, Schema};

/// Load the built-in schema for the clash policy DSL.
pub fn load_builtin() -> Schema {
    Schema {
        builtins: vec![
            Builtin {
                name: "policy",
                signature: "policy(name: str, rules_or_dict: dict = None, default: str = \"deny\", default_sandbox: str = None)",
                doc: "Register a named clash policy with the given rules dict.",
            },
            Builtin {
                name: "sandbox",
                signature: "sandbox(name: str = None, default: str = \"deny\", fs = None, net = None, doc: str = None)",
                doc: "Register a named sandbox defining filesystem and network restrictions.",
            },
            Builtin {
                name: "settings",
                signature: "settings(default: str = \"deny\", default_sandbox: str = None, on_sandbox_violation: str = None, harness_defaults: bool = None)",
                doc: "Register settings to merge into the agent configuration.",
            },
            Builtin {
                name: "allow",
                signature: "allow(caps = None, sandbox: str = None, read = None, write = None, create = None, delete = None, execute = None)",
                doc: "Effect: allow the action. Optionally scoped to capability domains.",
            },
            Builtin {
                name: "deny",
                signature: "deny(caps = None, sandbox: str = None, read = None, write = None, create = None, delete = None, execute = None)",
                doc: "Effect: deny the action. Optionally scoped to capability domains.",
            },
            Builtin {
                name: "ask",
                signature: "ask(caps = None, sandbox: str = None, read = None, write = None, create = None, delete = None, execute = None)",
                doc: "Effect: prompt the user before allowing the action.",
            },
            Builtin {
                name: "mode",
                signature: "mode(name: str = None, doc: str = None)",
                doc: "Construct a mode matcher (e.g. mode(\"plan\")) for use as a policy dict key.",
            },
            Builtin {
                name: "merge",
                signature: "merge(*dicts)",
                doc: "Deep-merge two or more policy dicts. Rightmost value wins at leaf conflicts.",
            },
            Builtin {
                name: "glob",
                signature: "glob(pattern: str)",
                doc: "Construct a glob pattern matcher for paths or arguments.",
            },
            Builtin {
                name: "regex",
                signature: "regex(pattern: str)",
                doc: "Construct a regex pattern matcher for paths or arguments.",
            },
            Builtin {
                name: "literal",
                signature: "literal(path_str: str)",
                doc: "Construct a literal path matcher.",
            },
            Builtin {
                name: "subpath",
                signature: "subpath(path_str: str, follow_worktrees: bool = False)",
                doc: "Construct a subpath matcher (matches path and all descendants).",
            },
            Builtin {
                name: "cwd",
                signature: "cwd(follow_worktrees: bool = False)",
                doc: "Construct a matcher for the current working directory.",
            },
            Builtin {
                name: "home",
                signature: "home()",
                doc: "Construct a matcher for the user's home directory.",
            },
            Builtin {
                name: "tempdir",
                signature: "tempdir()",
                doc: "Construct a matcher for the system temporary directory.",
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_includes_core_builtins() {
        let s = load_builtin();
        assert!(s.lookup("policy").is_some());
        assert!(s.lookup("sandbox").is_some());
        assert!(s.lookup("settings").is_some());
        assert!(s.lookup("allow").is_some());
        assert!(s.lookup("deny").is_some());
        assert!(s.lookup("ask").is_some());
    }

    #[test]
    fn schema_lookup_unknown_returns_none() {
        let s = load_builtin();
        assert!(s.lookup("nonexistent_builtin").is_none());
    }
}
