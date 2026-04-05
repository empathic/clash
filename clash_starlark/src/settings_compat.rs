//! Shared classification logic for converting Claude Code permission strings
//! into Clash match tree nodes.
//!
//! This is used by the `_from_claude_settings` native Starlark function to
//! dynamically import Claude Code permission settings at policy evaluation time.

use claude_settings::permission::{Permission, PermissionPattern, PermissionSet};
use claude_settings::{ClaudeSettings, PathResolver, SettingsLevel};
use serde_json::{Value as JsonValue, json};

use crate::builders::match_tree::MatchTreeNode;

/// Classification of a single Claude Code permission into Clash match tree form.
#[derive(Debug, Clone)]
struct ClassifiedRule {
    effect: String,
    node: JsonValue,
}

/// Convert a `PermissionSet` into a list of `MatchTreeNode` values suitable
/// for inclusion in a Clash policy `rules` list.
pub fn permission_set_to_nodes(perms: &PermissionSet) -> Vec<MatchTreeNode> {
    let mut nodes = Vec::new();

    for perm in perms.denied() {
        nodes.extend(classify_permission(perm, "deny"));
    }
    for perm in perms.asking() {
        nodes.extend(classify_permission(perm, "ask"));
    }
    for perm in perms.allowed() {
        nodes.extend(classify_permission(perm, "allow"));
    }

    nodes
}

/// Map a Claude Code tool name to the Clash capability domain observation.
///
/// Claude Code tools map to Clash's capability model:
/// - `Bash` -> exec domain (tool_name = "Bash", observes binary + args)
/// - `Read`, `Edit`, `Write`, `Glob`, `Grep`, `MultiEdit` -> fs domain
/// - `WebFetch` -> net domain
/// - MCP tools (`mcp__*`) -> skipped (Clash doesn't manage MCP)
fn classify_permission(perm: &Permission, effect: &str) -> Vec<MatchTreeNode> {
    let tool = perm.tool();

    // Skip MCP tools entirely
    if tool.starts_with("mcp__") {
        return vec![];
    }

    let effect_json = json!({ "effect": effect });

    match perm.pattern() {
        None => {
            // Tool-only permission: match all uses of this tool
            // e.g., "Read" -> when tool_name == "Read": effect
            vec![make_tool_match(tool, json!("wildcard"), effect_json)]
        }

        Some(PermissionPattern::Prefix(prefix)) if tool == "Bash" => {
            // Bash prefix: e.g., "Bash(git:*)" -> match exec bin="git", args=glob("**")
            // Multi-word: "Bash(cargo check:*)" -> bin="cargo", first arg starts with "check"
            let segments: Vec<&str> = prefix.split_whitespace().collect();
            let bin = segments[0];

            if segments.len() == 1 {
                // Simple: Bash(git:*) -> tool=Bash, bin=git, args=wildcard
                vec![make_bash_prefix_match(bin, None, effect_json)]
            } else {
                // Multi-word: Bash(cargo check:*) -> bin=cargo, first arg prefix="check ..."
                let sub = segments[1..].join(" ");
                vec![make_bash_prefix_match(bin, Some(&sub), effect_json)]
            }
        }

        Some(PermissionPattern::Prefix(prefix)) => {
            // Non-Bash prefix (unusual) -> treat as tool match with prefix on first arg
            let pattern = json!({"prefix": prefix});
            vec![make_tool_arg_match(tool, pattern, effect_json)]
        }

        Some(PermissionPattern::Exact(path)) => {
            // Exact file match: e.g., "Read(.env)" -> tool=Read, path=literal(".env")
            let pattern = json!({"literal": path});
            vec![make_tool_arg_match(tool, pattern, effect_json)]
        }

        Some(PermissionPattern::Glob(glob_pattern)) => {
            // Glob pattern: e.g., "Read(**/*.rs)" -> tool=Read, path=glob("**/*.rs")
            let pattern = json!({"glob": glob_pattern});
            vec![make_tool_arg_match(tool, pattern, effect_json)]
        }
    }
}

/// Build a match tree node that matches a tool by name with a wildcard or specific pattern.
fn make_tool_match(tool: &str, pattern: JsonValue, decision: JsonValue) -> MatchTreeNode {
    MatchTreeNode {
        json: json!({
            "condition": {
                "observe": "tool_name",
                "pattern": { "literal": tool }
            },
            "children": [{
                "condition": {
                    "observe": {"positional_arg": 0},
                    "pattern": pattern
                },
                "children": [decision]
            }]
        }),
    }
}

/// Build a match tree node for a Bash command with a known binary prefix.
fn make_bash_prefix_match(
    bin: &str,
    subcommand: Option<&str>,
    decision: JsonValue,
) -> MatchTreeNode {
    let args_node = match subcommand {
        Some(sub) => {
            // Match first positional arg with prefix
            json!({
                "condition": {
                    "observe": {"positional_arg": 0},
                    "pattern": {"prefix": sub}
                },
                "children": [decision]
            })
        }
        None => {
            // Wildcard on args
            json!({
                "condition": {
                    "observe": {"positional_arg": 0},
                    "pattern": "wildcard"
                },
                "children": [decision]
            })
        }
    };

    MatchTreeNode {
        json: json!({
            "condition": {
                "observe": "tool_name",
                "pattern": { "literal": "Bash" }
            },
            "children": [{
                "condition": {
                    "observe": "binary",
                    "pattern": { "literal": bin }
                },
                "children": [args_node]
            }]
        }),
    }
}

/// Build a match tree node for a tool with a pattern on its first argument.
fn make_tool_arg_match(tool: &str, pattern: JsonValue, decision: JsonValue) -> MatchTreeNode {
    MatchTreeNode {
        json: json!({
            "condition": {
                "observe": "tool_name",
                "pattern": { "literal": tool }
            },
            "children": [{
                "condition": {
                    "observe": {"positional_arg": 0},
                    "pattern": pattern
                },
                "children": [decision]
            }]
        }),
    }
}

/// Read Claude Code settings and convert permissions to match tree nodes.
///
/// `user`: include user-level (~/.claude/settings.json) permissions
/// `project`: include project-level (.claude/settings.json + .claude/settings.local.json) permissions
///
/// Returns an empty Vec if settings files don't exist or can't be read.
pub fn from_claude_settings(user: bool, project: bool) -> Vec<MatchTreeNode> {
    from_claude_settings_inner(user, project, None)
}

/// Inner implementation that accepts an optional custom resolver for testing.
pub(crate) fn from_claude_settings_inner(
    user: bool,
    project: bool,
    resolver: Option<PathResolver>,
) -> Vec<MatchTreeNode> {
    let manager = match resolver {
        Some(r) => ClaudeSettings::with_resolver(r),
        None => ClaudeSettings::new(),
    };

    let mut combined = PermissionSet::new();

    if user {
        if let Ok(Some(settings)) = manager.read(SettingsLevel::User) {
            combined = combined.merge(&settings.permissions);
        }
    }

    if project {
        if let Ok(Some(settings)) = manager.read(SettingsLevel::Project) {
            combined = combined.merge(&settings.permissions);
        }
        if let Ok(Some(settings)) = manager.read(SettingsLevel::ProjectLocal) {
            combined = combined.merge(&settings.permissions);
        }
    }

    permission_set_to_nodes(&combined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use claude_settings::permission::Permission;

    #[test]
    fn test_tool_only_allow() {
        let perms = PermissionSet::new().allow(Permission::for_tool("Read"));
        let nodes = permission_set_to_nodes(&perms);
        assert_eq!(nodes.len(), 1);
        let json = &nodes[0].json;
        assert_eq!(json["condition"]["observe"], "tool_name");
        assert_eq!(json["condition"]["pattern"]["literal"], "Read");
        let child = &json["children"][0];
        assert_eq!(child["children"][0]["effect"], "allow");
    }

    #[test]
    fn test_tool_only_deny() {
        let perms = PermissionSet::new().deny(Permission::for_tool("Write"));
        let nodes = permission_set_to_nodes(&perms);
        assert_eq!(nodes.len(), 1);
        let json = &nodes[0].json;
        assert_eq!(json["children"][0]["children"][0]["effect"], "deny");
    }

    #[test]
    fn test_bash_prefix() {
        let perms = PermissionSet::new().allow(Permission::prefix("Bash", "git"));
        let nodes = permission_set_to_nodes(&perms);
        assert_eq!(nodes.len(), 1);
        let json = &nodes[0].json;
        assert_eq!(json["condition"]["pattern"]["literal"], "Bash");
        let bin_node = &json["children"][0];
        assert_eq!(bin_node["condition"]["observe"], "binary");
        assert_eq!(bin_node["condition"]["pattern"]["literal"], "git");
    }

    #[test]
    fn test_bash_multi_word_prefix() {
        let perms = PermissionSet::new().allow(Permission::prefix("Bash", "cargo check"));
        let nodes = permission_set_to_nodes(&perms);
        assert_eq!(nodes.len(), 1);
        let json = &nodes[0].json;
        let bin_node = &json["children"][0];
        assert_eq!(bin_node["condition"]["pattern"]["literal"], "cargo");
        let args_node = &bin_node["children"][0];
        assert_eq!(args_node["condition"]["pattern"]["prefix"], "check");
    }

    #[test]
    fn test_exact_file_match() {
        let perms = PermissionSet::new().deny(Permission::exact("Read", ".env"));
        let nodes = permission_set_to_nodes(&perms);
        assert_eq!(nodes.len(), 1);
        let json = &nodes[0].json;
        assert_eq!(json["condition"]["pattern"]["literal"], "Read");
        let arg_node = &json["children"][0];
        assert_eq!(arg_node["condition"]["pattern"]["literal"], ".env");
        assert_eq!(arg_node["children"][0]["effect"], "deny");
    }

    #[test]
    fn test_glob_pattern() {
        let perms = PermissionSet::new().allow(Permission::glob("Read", "**/*.rs"));
        let nodes = permission_set_to_nodes(&perms);
        assert_eq!(nodes.len(), 1);
        let json = &nodes[0].json;
        assert_eq!(json["condition"]["pattern"]["literal"], "Read");
        let arg_node = &json["children"][0];
        assert_eq!(arg_node["condition"]["pattern"]["glob"], "**/*.rs");
        assert_eq!(arg_node["children"][0]["effect"], "allow");
    }

    #[test]
    fn test_mcp_tools_skipped() {
        let perms = PermissionSet::new()
            .allow(Permission::for_tool("mcp__server__tool"))
            .allow(Permission::for_tool("Read"));
        let nodes = permission_set_to_nodes(&perms);
        // Only Read should produce a node; MCP is skipped
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].json["condition"]["pattern"]["literal"], "Read");
    }

    #[test]
    fn test_deny_before_allow_ordering() {
        let perms = PermissionSet::new()
            .allow(Permission::for_tool("Read"))
            .deny(Permission::exact("Read", ".env"));
        let nodes = permission_set_to_nodes(&perms);
        // Deny should come first
        assert_eq!(nodes.len(), 2);
        assert_eq!(
            nodes[0].json["children"][0]["children"][0]["effect"],
            "deny"
        );
        assert_eq!(
            nodes[1].json["children"][0]["children"][0]["effect"],
            "allow"
        );
    }

    #[test]
    fn test_empty_permissions_returns_empty() {
        let perms = PermissionSet::new();
        let nodes = permission_set_to_nodes(&perms);
        assert!(nodes.is_empty());
    }

    #[test]
    fn test_mixed_effects() {
        let perms = PermissionSet::new()
            .allow(Permission::prefix("Bash", "git"))
            .deny(Permission::exact("Read", ".env"))
            .ask(Permission::for_tool("Write"));
        let nodes = permission_set_to_nodes(&perms);
        // deny first, then ask, then allow
        assert_eq!(nodes.len(), 3);
        assert_eq!(
            nodes[0].json["children"][0]["children"][0]["effect"],
            "deny"
        );
        assert_eq!(
            nodes[1].json["children"][0]["children"][0]["effect"],
            "ask"
        );
        // The bash allow has deeper nesting
        let bash_node = &nodes[2].json;
        let bin_node = &bash_node["children"][0];
        let args_node = &bin_node["children"][0];
        assert_eq!(args_node["children"][0]["effect"], "allow");
    }

    #[test]
    fn test_from_claude_settings_no_files() {
        // With a resolver pointing to a nonexistent directory, should return empty
        let resolver = PathResolver::new()
            .with_home("/nonexistent/path/for/test")
            .with_project("/nonexistent/path/for/test");
        let nodes = from_claude_settings_inner(true, true, Some(resolver));
        assert!(nodes.is_empty());
    }

    #[test]
    fn test_from_claude_settings_with_temp_dir() {
        use std::fs;
        let temp = tempfile::TempDir::new().unwrap();
        let home = temp.path().join("home");
        let project = temp.path().join("project");
        fs::create_dir_all(home.join(".claude")).unwrap();
        fs::create_dir_all(project.join(".claude")).unwrap();

        // Write user settings
        let user_settings = serde_json::json!({
            "permissions": {
                "allow": ["Bash(git:*)"],
                "deny": ["Read(.env)"]
            }
        });
        fs::write(
            home.join(".claude/settings.json"),
            serde_json::to_string_pretty(&user_settings).unwrap(),
        )
        .unwrap();

        // Write project settings
        let project_settings = serde_json::json!({
            "permissions": {
                "allow": ["Edit"]
            }
        });
        fs::write(
            project.join(".claude/settings.json"),
            serde_json::to_string_pretty(&project_settings).unwrap(),
        )
        .unwrap();

        let resolver = PathResolver::new()
            .with_home(&home)
            .with_project(&project);

        // User only
        let nodes = from_claude_settings_inner(true, false, Some(resolver.clone()));
        assert_eq!(nodes.len(), 2); // deny + allow

        // Project only
        let nodes = from_claude_settings_inner(false, true, Some(resolver.clone()));
        assert_eq!(nodes.len(), 1); // allow Edit

        // Both
        let nodes = from_claude_settings_inner(true, true, Some(resolver));
        assert_eq!(nodes.len(), 3); // deny + allow git + allow Edit
    }
}
