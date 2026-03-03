//! Versioned schema registry for `ctx.*` observable paths.
//!
//! Each policy version defines a fixed set of valid `ctx` paths. The schema
//! drives parse-time validation: any `ctx` reference not in the schema for the
//! declared version is a parse error with a did-you-mean suggestion.

use super::ast::Observable;
use crate::policy::error::suggest_closest;

/// Describes how a `ctx` field behaves for sub-path access validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtxFieldKind {
    /// Scalar field — no sub-path access allowed.
    /// Used in when guards with `parse_pattern` → `ArmPattern::Single`.
    Scalar,
    /// Filesystem path field — no sub-path access allowed.
    /// Used in when guards with `parse_path_filter` → `ArmPattern::SinglePath`.
    Path,
    /// Dynamic subtree — sub-path access requires `?` suffix.
    /// e.g. `ctx.tool.args.file_path?`
    Dynamic,
}

/// One entry in the versioned ctx schema.
#[derive(Debug, Clone)]
pub struct CtxField {
    /// The full canonical path, e.g. `"ctx.http.domain"`.
    pub path: &'static str,
    /// The AST observable this path maps to.
    pub observable: Observable,
    /// Field kind for sub-path access validation.
    pub kind: CtxFieldKind,
}

/// Return the ctx schema for a given policy version.
///
/// Version 1 has no ctx namespace (observables were flat names), so returns
/// an empty slice. Version 2+ defines the full ctx tree from the spec.
pub fn ctx_schema(version: u32) -> &'static [CtxField] {
    match version {
        0 | 1 => &[],
        _ => &V2_SCHEMA,
    }
}

/// All valid `ctx.*` paths as strings for a given version.
pub fn ctx_paths(version: u32) -> Vec<&'static str> {
    ctx_schema(version).iter().map(|f| f.path).collect()
}

/// Look up a `ctx.*` path in the schema for the given version.
///
/// Returns the corresponding `Observable` on success, or a helpful error
/// with a did-you-mean suggestion when the path is invalid.
pub fn resolve_ctx_observable(path: &str, version: u32) -> anyhow::Result<Observable> {
    let schema = ctx_schema(version);

    // Exact match in schema.
    if let Some(entry) = schema.iter().find(|e| e.path == path) {
        return Ok(entry.observable.clone());
    }

    // Check for sub-path access on a known field (e.g. ctx.tool.args.file_path).
    let (base_path, has_nullable) = path
        .strip_suffix('?')
        .map(|stripped| (stripped, true))
        .unwrap_or((path, false));

    for entry in schema {
        let prefix_with_dot = format!("{}.", entry.path);
        if base_path.starts_with(&prefix_with_dot) {
            return match entry.kind {
                CtxFieldKind::Dynamic => {
                    if has_nullable {
                        // Valid dynamic field access with nullable suffix.
                        // Map to the parent observable (runtime will handle the sub-path).
                        Ok(entry.observable.clone())
                    } else {
                        anyhow::bail!(
                            "`{path}` accesses a dynamic subtree (`{}`). \
                             Use the `?` suffix for dynamic field access: `{path}?`",
                            entry.path,
                        )
                    }
                }
                CtxFieldKind::Scalar | CtxFieldKind::Path => {
                    anyhow::bail!(
                        "`{}` is a leaf field and does not have sub-paths",
                        entry.path,
                    )
                }
            };
        }
    }

    // No match — produce a did-you-mean suggestion.
    let candidates = ctx_paths(version);
    if let Some(suggestion) = suggest_closest(path, &candidates) {
        anyhow::bail!(
            "`{path}` is not a valid observable in version {version}. \
             Did you mean `{suggestion}`?"
        );
    }
    anyhow::bail!("`{path}` is not a valid observable in version {version}")
}

// ---------------------------------------------------------------------------
// Version 2 schema
// ---------------------------------------------------------------------------

static V2_SCHEMA: [CtxField; 15] = [
    // ctx.http namespace
    CtxField {
        path: "ctx.http.domain",
        observable: Observable::HttpDomain,
        kind: CtxFieldKind::Scalar,
    },
    CtxField {
        path: "ctx.http.method",
        observable: Observable::HttpMethod,
        kind: CtxFieldKind::Scalar,
    },
    CtxField {
        path: "ctx.http.port",
        observable: Observable::HttpPort,
        kind: CtxFieldKind::Scalar,
    },
    CtxField {
        path: "ctx.http.path",
        observable: Observable::HttpPath,
        kind: CtxFieldKind::Scalar,
    },
    // ctx.fs namespace
    CtxField {
        path: "ctx.fs.action",
        observable: Observable::FsAction,
        kind: CtxFieldKind::Scalar,
    },
    CtxField {
        path: "ctx.fs.path",
        observable: Observable::FsPath,
        kind: CtxFieldKind::Path,
    },
    CtxField {
        path: "ctx.fs.exists",
        observable: Observable::FsExists,
        kind: CtxFieldKind::Scalar,
    },
    // ctx.process namespace
    CtxField {
        path: "ctx.process.command",
        observable: Observable::ProcessCommand,
        kind: CtxFieldKind::Scalar,
    },
    CtxField {
        path: "ctx.process.args",
        observable: Observable::ProcessArgs,
        kind: CtxFieldKind::Dynamic,
    },
    // ctx.tool namespace
    CtxField {
        path: "ctx.tool.name",
        observable: Observable::ToolName,
        kind: CtxFieldKind::Scalar,
    },
    CtxField {
        path: "ctx.tool.args",
        observable: Observable::ToolArgs,
        kind: CtxFieldKind::Dynamic,
    },
    // ctx.mcp namespace
    CtxField {
        path: "ctx.mcp.server",
        observable: Observable::McpServer,
        kind: CtxFieldKind::Scalar,
    },
    CtxField {
        path: "ctx.mcp.tool",
        observable: Observable::McpTool,
        kind: CtxFieldKind::Scalar,
    },
    // ctx.agent namespace
    CtxField {
        path: "ctx.agent.name",
        observable: Observable::AgentName,
        kind: CtxFieldKind::Scalar,
    },
    // ctx.state
    CtxField {
        path: "ctx.state",
        observable: Observable::State,
        kind: CtxFieldKind::Scalar,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_schema_is_empty() {
        assert!(ctx_schema(1).is_empty());
    }

    #[test]
    fn v2_schema_has_all_paths() {
        let paths = ctx_paths(2);
        assert!(paths.contains(&"ctx.http.domain"));
        assert!(paths.contains(&"ctx.fs.path"));
        assert!(paths.contains(&"ctx.tool.args"));
        assert!(paths.contains(&"ctx.mcp.server"));
        assert!(paths.contains(&"ctx.agent.name"));
        assert!(paths.contains(&"ctx.state"));
    }

    #[test]
    fn resolve_exact_match() {
        let obs = resolve_ctx_observable("ctx.http.domain", 2).unwrap();
        assert_eq!(obs, Observable::HttpDomain);
    }

    #[test]
    fn resolve_typo_suggests_closest() {
        let err = resolve_ctx_observable("ctx.htttp.domain", 2).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Did you mean `ctx.http.domain`?"),
            "got: {msg}"
        );
    }

    #[test]
    fn resolve_unknown_namespace() {
        let err = resolve_ctx_observable("ctx.foo.bar", 2).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("is not a valid observable in version 2"),
            "got: {msg}"
        );
    }

    #[test]
    fn resolve_dynamic_subpath_without_nullable() {
        let err = resolve_ctx_observable("ctx.tool.args.file_path", 2).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("dynamic subtree"), "got: {msg}");
        assert!(msg.contains("?"), "should suggest ? suffix, got: {msg}");
    }

    #[test]
    fn resolve_dynamic_subpath_with_nullable() {
        let obs = resolve_ctx_observable("ctx.tool.args.file_path?", 2).unwrap();
        assert_eq!(obs, Observable::ToolArgs);
    }

    #[test]
    fn resolve_static_subpath_errors() {
        let err = resolve_ctx_observable("ctx.http.domain.something", 2).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("leaf field"), "got: {msg}");
    }

    #[test]
    fn v1_does_not_validate_ctx() {
        // v1 schema is empty, so resolve fails generically.
        let err = resolve_ctx_observable("ctx.http.domain", 1).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("is not a valid observable in version 1"),
            "got: {msg}"
        );
    }
}
