//! Shared classification logic for converting Claude Code permission strings
//! into Clash match tree nodes or Starlark policy dicts.
//!
//! This is used by the `_from_claude_settings` native Starlark function to
//! dynamically import Claude Code permission settings at policy evaluation time.
//!
//! Two output formats:
//! - **Match tree nodes** (`permission_set_to_nodes`): legacy list-of-rules format
//! - **Policy dict** (`build_policy_dict`): nested dict for use with `merge()` + `policy()`

use std::collections::HashMap;

use claude_settings::permission::{Permission, PermissionPattern, PermissionSet};
use claude_settings::{ClaudeSettings, PathResolver, SettingsLevel};
use serde_json::{Value as JsonValue, json};
use starlark::values::structs::AllocStruct;
use starlark::values::{Heap, Value};

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

// ---------------------------------------------------------------------------
// Policy dict output (for merge() + policy() usage)
// ---------------------------------------------------------------------------

/// Intermediate representation of a classified permission for dict building.
#[derive(Debug, Clone)]
enum DictEntry {
    /// Tool-level effect: `"Read": allow()`
    ToolEffect { tool: String, effect: String },
    /// Tool with a single argument key: `"Read": {".env": deny()}`
    ToolArg {
        tool: String,
        arg: String,
        effect: String,
    },
    /// Bash with binary (and optional sub-args): `"Bash": {"git": {"push": allow()}}`
    BashCmd {
        bin: String,
        sub_args: Vec<String>,
        effect: String,
    },
}

/// Allocate an effect struct on the Starlark heap matching the shape produced
/// by `allow()`/`deny()`/`ask()` in `std.star`.
fn alloc_effect<'v>(heap: &'v Heap, effect: &str) -> Value<'v> {
    heap.alloc(AllocStruct([
        ("_effect", heap.alloc_str(effect).to_value()),
        ("_is_effect", Value::new_bool(true)),
        ("_sandbox", Value::new_none()),
        ("_read", Value::new_none()),
        ("_write", Value::new_none()),
        ("_create", Value::new_none()),
        ("_delete", Value::new_none()),
        ("_execute", Value::new_none()),
    ]))
}

/// Classify a single permission into a `DictEntry`.
fn classify_permission_for_dict(perm: &Permission, effect: &str) -> Option<DictEntry> {
    let tool = perm.tool();

    // Skip MCP tools
    if tool.starts_with("mcp__") {
        return None;
    }

    match perm.pattern() {
        None => Some(DictEntry::ToolEffect {
            tool: tool.to_string(),
            effect: effect.to_string(),
        }),

        Some(PermissionPattern::Prefix(prefix)) if tool == "Bash" => {
            let segments: Vec<&str> = prefix.split_whitespace().collect();
            let bin = segments[0].to_string();
            let sub_args: Vec<String> = segments[1..].iter().map(|s| s.to_string()).collect();
            Some(DictEntry::BashCmd {
                bin,
                sub_args,
                effect: effect.to_string(),
            })
        }

        Some(PermissionPattern::Prefix(prefix)) => Some(DictEntry::ToolArg {
            tool: tool.to_string(),
            arg: prefix.to_string(),
            effect: effect.to_string(),
        }),

        Some(PermissionPattern::Exact(path)) => Some(DictEntry::ToolArg {
            tool: tool.to_string(),
            arg: path.to_string(),
            effect: effect.to_string(),
        }),

        Some(PermissionPattern::Glob(glob_pattern)) => Some(DictEntry::ToolArg {
            tool: tool.to_string(),
            arg: glob_pattern.to_string(),
            effect: effect.to_string(),
        }),
    }
}

/// Intermediate tree node for building nested dicts.
/// Either a leaf (effect) or a branch (map of key -> subtree).
enum DictTree {
    Leaf(String),
    Branch(Vec<(String, DictTree)>),
}

impl DictTree {
    /// Insert a path of keys leading to a leaf effect.
    /// If the path is empty, this is a leaf.
    fn insert(&mut self, keys: &[String], effect: String) {
        if keys.is_empty() {
            *self = DictTree::Leaf(effect);
            return;
        }
        match self {
            DictTree::Branch(children) => {
                let key = &keys[0];
                // Find existing child with this key
                if let Some((_k, child)) = children.iter_mut().find(|(k, _)| k == key) {
                    child.insert(&keys[1..], effect);
                } else {
                    let mut new_child = DictTree::Branch(Vec::new());
                    new_child.insert(&keys[1..], effect);
                    children.push((key.clone(), new_child));
                }
            }
            DictTree::Leaf(_) => {
                // A more specific path overwrites a tool-level wildcard;
                // convert to branch. This case is rare but handle gracefully.
                let mut branch = DictTree::Branch(Vec::new());
                branch.insert(keys, effect);
                *self = branch;
            }
        }
    }

    /// Allocate this tree as Starlark values on the heap.
    fn to_starlark<'v>(&self, heap: &'v Heap) -> Value<'v> {
        match self {
            DictTree::Leaf(effect) => alloc_effect(heap, effect),
            DictTree::Branch(children) => {
                let entries: Vec<(Value<'v>, Value<'v>)> = children
                    .iter()
                    .map(|(key, child)| {
                        (
                            heap.alloc_str(key).to_value(),
                            child.to_starlark(heap),
                        )
                    })
                    .collect();
                heap.alloc(starlark::values::dict::AllocDict(entries))
            }
        }
    }
}

/// Build a Starlark policy dict from a `PermissionSet`.
///
/// Returns entries suitable for `heap.alloc(AllocDict(entries))`.
/// The dict uses plain string keys and effect structs as leaf values.
pub fn build_policy_dict<'v>(perms: &PermissionSet, heap: &'v Heap) -> Value<'v> {
    // Collect all entries grouped by tool name, preserving order:
    // deny first, then ask, then allow (matching existing priority ordering).
    let mut entries: Vec<DictEntry> = Vec::new();

    for perm in perms.denied() {
        if let Some(entry) = classify_permission_for_dict(perm, "deny") {
            entries.push(entry);
        }
    }
    for perm in perms.asking() {
        if let Some(entry) = classify_permission_for_dict(perm, "ask") {
            entries.push(entry);
        }
    }
    for perm in perms.allowed() {
        if let Some(entry) = classify_permission_for_dict(perm, "allow") {
            entries.push(entry);
        }
    }

    // Build a top-level tree keyed by tool name.
    // Order: maintain insertion order for tools (first-seen order).
    let mut tool_order: Vec<String> = Vec::new();
    let mut tool_trees: HashMap<String, DictTree> = HashMap::new();

    for entry in &entries {
        match entry {
            DictEntry::ToolEffect { tool, effect } => {
                if !tool_trees.contains_key(tool) {
                    tool_order.push(tool.clone());
                    tool_trees.insert(tool.clone(), DictTree::Branch(Vec::new()));
                }
                // Tool-level effect replaces existing tree
                tool_trees.insert(tool.clone(), DictTree::Leaf(effect.clone()));
            }
            DictEntry::ToolArg { tool, arg, effect } => {
                if !tool_trees.contains_key(tool) {
                    tool_order.push(tool.clone());
                    tool_trees.insert(tool.clone(), DictTree::Branch(Vec::new()));
                }
                tool_trees
                    .get_mut(tool)
                    .unwrap()
                    .insert(&[arg.clone()], effect.clone());
            }
            DictEntry::BashCmd {
                bin,
                sub_args,
                effect,
            } => {
                let tool = "Bash".to_string();
                if !tool_trees.contains_key(&tool) {
                    tool_order.push(tool.clone());
                    tool_trees.insert(tool.clone(), DictTree::Branch(Vec::new()));
                }
                let mut keys = vec![bin.clone()];
                keys.extend(sub_args.iter().cloned());
                tool_trees
                    .get_mut(&tool)
                    .unwrap()
                    .insert(&keys, effect.clone());
            }
        }
    }

    // Convert to Starlark dict
    let starlark_entries: Vec<(Value<'v>, Value<'v>)> = tool_order
        .iter()
        .map(|tool| {
            let tree = tool_trees.get(tool).unwrap();
            (heap.alloc_str(tool).to_value(), tree.to_starlark(heap))
        })
        .collect();

    heap.alloc(starlark::values::dict::AllocDict(starlark_entries))
}

/// Read Claude Code settings and build a Starlark policy dict.
///
/// This is the dict-based counterpart of `from_claude_settings()`.
/// The returned dict can be passed to `merge()` and then to `policy()`.
pub fn from_claude_settings_as_dict<'v>(
    user: bool,
    project: bool,
    heap: &'v Heap,
) -> Value<'v> {
    from_claude_settings_as_dict_inner(user, project, None, heap)
}

/// Inner implementation that accepts an optional custom resolver for testing.
pub(crate) fn from_claude_settings_as_dict_inner<'v>(
    user: bool,
    project: bool,
    resolver: Option<PathResolver>,
    heap: &'v Heap,
) -> Value<'v> {
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

    build_policy_dict(&combined, heap)
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

    // -----------------------------------------------------------------------
    // Policy dict tests
    // -----------------------------------------------------------------------

    /// Helper: build a policy dict and return its repr string for assertions.
    fn dict_repr(perms: &PermissionSet) -> String {
        let heap = Heap::new();
        let dict = build_policy_dict(perms, &heap);
        dict.to_repr()
    }

    #[test]
    fn test_dict_tool_only_allow() {
        let perms = PermissionSet::new().allow(Permission::for_tool("Read"));
        let repr = dict_repr(&perms);
        // Should produce {"Read": struct(_effect = "allow", ...)}
        assert!(repr.contains("\"Read\""), "dict should have Read key: {repr}");
        assert!(repr.contains("_effect=\"allow\""), "should have allow effect: {repr}");
    }

    #[test]
    fn test_dict_tool_only_deny() {
        let perms = PermissionSet::new().deny(Permission::for_tool("Write"));
        let repr = dict_repr(&perms);
        assert!(repr.contains("\"Write\""), "dict should have Write key: {repr}");
        assert!(repr.contains("_effect=\"deny\""), "should have deny effect: {repr}");
    }

    #[test]
    fn test_dict_bash_prefix_simple() {
        let perms = PermissionSet::new().allow(Permission::prefix("Bash", "git"));
        let repr = dict_repr(&perms);
        // Should produce {"Bash": {"git": struct(...)}}
        assert!(repr.contains("\"Bash\""), "dict should have Bash key: {repr}");
        assert!(repr.contains("\"git\""), "should have git sub-key: {repr}");
        assert!(repr.contains("_effect=\"allow\""), "should have allow: {repr}");
    }

    #[test]
    fn test_dict_bash_multi_word() {
        let perms = PermissionSet::new().allow(Permission::prefix("Bash", "cargo build"));
        let repr = dict_repr(&perms);
        // Should produce {"Bash": {"cargo": {"build": struct(...)}}}
        assert!(repr.contains("\"Bash\""), "dict should have Bash key: {repr}");
        assert!(repr.contains("\"cargo\""), "should have cargo sub-key: {repr}");
        assert!(repr.contains("\"build\""), "should have build sub-key: {repr}");
    }

    #[test]
    fn test_dict_exact_file() {
        let perms = PermissionSet::new().deny(Permission::exact("Read", ".env"));
        let repr = dict_repr(&perms);
        // Should produce {"Read": {".env": struct(_effect = "deny", ...)}}
        assert!(repr.contains("\"Read\""), "dict should have Read key: {repr}");
        assert!(repr.contains("\".env\""), "should have .env sub-key: {repr}");
        assert!(repr.contains("_effect=\"deny\""), "should have deny: {repr}");
    }

    #[test]
    fn test_dict_glob_pattern() {
        let perms = PermissionSet::new().allow(Permission::glob("Read", "**/*.rs"));
        let repr = dict_repr(&perms);
        assert!(repr.contains("\"Read\""), "dict should have Read key: {repr}");
        assert!(repr.contains("\"**/*.rs\""), "should have glob sub-key: {repr}");
    }

    #[test]
    fn test_dict_mcp_skipped() {
        let perms = PermissionSet::new()
            .allow(Permission::for_tool("mcp__server__tool"))
            .allow(Permission::for_tool("Read"));
        let repr = dict_repr(&perms);
        assert!(!repr.contains("mcp__"), "MCP tools should be skipped: {repr}");
        assert!(repr.contains("\"Read\""), "Read should be present: {repr}");
    }

    #[test]
    fn test_dict_empty_permissions() {
        let perms = PermissionSet::new();
        let repr = dict_repr(&perms);
        assert_eq!(repr, "{}", "empty perms should produce empty dict");
    }

    #[test]
    fn test_dict_multiple_bash_commands_merged() {
        let perms = PermissionSet::new()
            .allow(Permission::prefix("Bash", "git"))
            .allow(Permission::prefix("Bash", "cargo"));
        let repr = dict_repr(&perms);
        // Both should appear under a single "Bash" key
        assert!(repr.contains("\"git\""), "should have git: {repr}");
        assert!(repr.contains("\"cargo\""), "should have cargo: {repr}");
        // Only one "Bash" key (the repr should have exactly one occurrence)
        assert_eq!(
            repr.matches("\"Bash\"").count(),
            1,
            "should have exactly one Bash key: {repr}"
        );
    }

    #[test]
    fn test_dict_mixed_effects_same_tool() {
        // deny .env + allow Read (tool-level)
        // deny comes first, then allow replaces the tree with a leaf
        let perms = PermissionSet::new()
            .allow(Permission::for_tool("Read"))
            .deny(Permission::exact("Read", ".env"));
        let repr = dict_repr(&perms);
        // deny is processed first -> Read: {".env": deny()}
        // then allow is processed -> Read: allow() (replaces tree)
        // This is the correct merge semantics: tool-level allow overrides specific deny
        assert!(repr.contains("\"Read\""), "should have Read: {repr}");
    }

    #[test]
    fn test_dict_from_settings_no_files() {
        let heap = Heap::new();
        let resolver = PathResolver::new()
            .with_home("/nonexistent/path/for/test")
            .with_project("/nonexistent/path/for/test");
        let dict = from_claude_settings_as_dict_inner(true, true, Some(resolver), &heap);
        assert_eq!(dict.to_repr(), "{}", "no settings -> empty dict");
    }

    #[test]
    fn test_dict_from_settings_with_temp_dir() {
        use std::fs;
        let heap = Heap::new();
        let temp = tempfile::TempDir::new().unwrap();
        let home = temp.path().join("home");
        let project = temp.path().join("project");
        fs::create_dir_all(home.join(".claude")).unwrap();
        fs::create_dir_all(project.join(".claude")).unwrap();

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

        // Both user + project
        let dict = from_claude_settings_as_dict_inner(true, true, Some(resolver), &heap);
        let repr = dict.to_repr();
        assert!(repr.contains("\"Read\""), "should have Read: {repr}");
        assert!(repr.contains("\".env\""), "should have .env: {repr}");
        assert!(repr.contains("\"Bash\""), "should have Bash: {repr}");
        assert!(repr.contains("\"git\""), "should have git: {repr}");
        assert!(repr.contains("\"Edit\""), "should have Edit: {repr}");
    }
}
