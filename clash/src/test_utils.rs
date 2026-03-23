//! Shared test fixtures and helpers for the clash crate.
//!
//! Provides reusable builders for policies, hook events, and tool inputs
//! so that test files do not need to reinvent boilerplate.

use crate::hooks::{HookOutput, HookSpecificOutput, ToolUseHookInput};
use crate::policy::Effect;
use crate::settings::ClashSettings;

// ---------------------------------------------------------------------------
// Tool input builders
// ---------------------------------------------------------------------------

/// Build a `serde_json::Value` representing a Bash tool input.
pub fn bash_command(command: &str) -> serde_json::Value {
    serde_json::json!({"command": command})
}

/// Build a `serde_json::Value` representing a Read tool input.
pub fn read_file(path: &str) -> serde_json::Value {
    serde_json::json!({"file_path": path})
}

/// Build a `serde_json::Value` representing a Write tool input.
pub fn write_file(path: &str) -> serde_json::Value {
    serde_json::json!({"file_path": path, "content": ""})
}

/// Build a `serde_json::Value` representing an Edit tool input.
pub fn edit_file(path: &str) -> serde_json::Value {
    serde_json::json!({"file_path": path, "old_string": "", "new_string": ""})
}

/// Build a `serde_json::Value` representing a Glob tool input.
pub fn glob_pattern(pattern: &str) -> serde_json::Value {
    serde_json::json!({"pattern": pattern})
}

/// Build a `serde_json::Value` representing a Grep tool input.
pub fn grep_pattern(pattern: &str) -> serde_json::Value {
    serde_json::json!({"pattern": pattern})
}

// ---------------------------------------------------------------------------
// Hook event builders
// ---------------------------------------------------------------------------

/// Build a [`ToolUseHookInput`] for a PreToolUse event.
pub fn pre_tool_use(tool_name: &str, tool_input: serde_json::Value) -> ToolUseHookInput {
    ToolUseHookInput {
        session_id: "test-session".into(),
        transcript_path: "/tmp/transcript.jsonl".into(),
        cwd: "/tmp".into(),
        permission_mode: "default".into(),
        hook_event_name: "PreToolUse".into(),
        tool_name: tool_name.into(),
        tool_input,
        tool_use_id: Some("toolu_test".into()),
        tool_response: None,
    }
}

/// Build a [`ToolUseHookInput`] for a PostToolUse event.
pub fn post_tool_use(
    tool_name: &str,
    tool_input: serde_json::Value,
    tool_response: serde_json::Value,
) -> ToolUseHookInput {
    ToolUseHookInput {
        hook_event_name: "PostToolUse".into(),
        tool_response: Some(tool_response),
        ..pre_tool_use(tool_name, tool_input)
    }
}

// ---------------------------------------------------------------------------
// TestPolicy builder
// ---------------------------------------------------------------------------

/// Builder for constructing [`ClashSettings`] with an inline JSON policy.
///
/// # Example
///
/// ```ignore
/// let settings = TestPolicy::deny_all()
///     .allow_exec("git")
///     .build();
/// ```
pub struct TestPolicy {
    default_effect: &'static str,
    tree: Vec<String>,
}

impl TestPolicy {
    /// Start with a policy that denies everything by default.
    pub fn deny_all() -> Self {
        Self {
            default_effect: "deny",
            tree: Vec::new(),
        }
    }

    /// Start with a policy that asks for everything by default.
    pub fn ask_all() -> Self {
        Self {
            default_effect: "ask",
            tree: Vec::new(),
        }
    }

    /// Start with a policy that allows everything by default.
    pub fn allow_all() -> Self {
        Self {
            default_effect: "allow",
            tree: Vec::new(),
        }
    }

    /// Add a rule that allows executing a specific binary.
    pub fn allow_exec(mut self, bin: &str) -> Self {
        self.tree.push(format!(
            r#"{{"condition":{{"observe":"tool_name","pattern":{{"literal":{{"literal":"Bash"}}}},"children":[
                {{"condition":{{"observe":{{"positional_arg":0}},"pattern":{{"literal":{{"literal":"{bin}"}}}},"children":[
                    {{"decision":{{"allow":null}}}}
                ]}}}}
            ]}}}}"#
        ));
        self
    }

    /// Add a rule that denies executing a specific binary.
    pub fn deny_exec(mut self, bin: &str) -> Self {
        self.tree.push(format!(
            r#"{{"condition":{{"observe":"tool_name","pattern":{{"literal":{{"literal":"Bash"}}}},"children":[
                {{"condition":{{"observe":{{"positional_arg":0}},"pattern":{{"literal":{{"literal":"{bin}"}}}},"children":[
                    {{"decision":"deny"}}
                ]}}}}
            ]}}}}"#
        ));
        self
    }

    /// Add a rule that allows reading files under a path prefix.
    pub fn allow_read(mut self, path_prefix: &str) -> Self {
        self.tree.push(format!(
            r#"{{"condition":{{"observe":"fs_op","pattern":{{"literal":{{"literal":"read"}}}},"children":[
                {{"condition":{{"observe":"fs_path","pattern":{{"prefix":{{"literal":"{path_prefix}"}}}},"children":[
                    {{"decision":{{"allow":null}}}}
                ]}}}}
            ]}}}}"#
        ));
        self
    }

    /// Add a rule that allows writing files under a path prefix.
    pub fn allow_write(mut self, path_prefix: &str) -> Self {
        self.tree.push(format!(
            r#"{{"condition":{{"observe":"fs_op","pattern":{{"literal":{{"literal":"write"}}}},"children":[
                {{"condition":{{"observe":"fs_path","pattern":{{"prefix":{{"literal":"{path_prefix}"}}}},"children":[
                    {{"decision":{{"allow":null}}}}
                ]}}}}
            ]}}}}"#
        ));
        self
    }

    /// Add a rule that allows all tools (wildcard on tool_name).
    pub fn allow_all_tools(mut self) -> Self {
        self.tree.push(
            r#"{"condition":{"observe":"tool_name","pattern":"wildcard","children":[
                {"decision":{"allow":null}}
            ]}}"#
                .into(),
        );
        self
    }

    /// Add a raw JSON tree node string.
    pub fn raw_node(mut self, json: &str) -> Self {
        self.tree.push(json.to_string());
        self
    }

    /// Build the policy into a [`ClashSettings`] ready for permission checks.
    pub fn build(&self) -> ClashSettings {
        let tree_json = self.tree.join(",");
        let source = format!(
            r#"{{"schema_version":5,"default_effect":"{}","sandboxes":{{}},"tree":[{}]}}"#,
            self.default_effect, tree_json
        );
        let mut settings = ClashSettings::default();
        settings.set_policy_source(&source);
        settings
    }
}

// ---------------------------------------------------------------------------
// TestEnvironment
// ---------------------------------------------------------------------------

/// A temporary environment with a directory for policy files.
///
/// Useful for tests that need to write policy files to disk.
pub struct TestEnvironment {
    pub dir: tempfile::TempDir,
}

impl Default for TestEnvironment {
    fn default() -> Self {
        Self::new()
    }
}

impl TestEnvironment {
    /// Create a new test environment with a temporary directory.
    pub fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("failed to create temp dir"),
        }
    }

    /// Write a policy JSON string to a file in the temp directory and return its path.
    pub fn write_policy(&self, filename: &str, content: &str) -> std::path::PathBuf {
        let path = self.dir.path().join(filename);
        std::fs::write(&path, content).expect("failed to write policy file");
        path
    }

    /// Return the path of the temp directory.
    pub fn path(&self) -> &std::path::Path {
        self.dir.path()
    }
}

// ---------------------------------------------------------------------------
// Decision extraction helpers
// ---------------------------------------------------------------------------

/// Extract the permission decision [`Effect`] from a [`HookOutput`].
pub fn get_effect(output: &HookOutput) -> Option<Effect> {
    match &output.hook_specific_output {
        Some(HookSpecificOutput::PreToolUse(pre)) => {
            pre.permission_decision
                .as_ref()
                .and_then(|rule| match rule {
                    claude_settings::PermissionRule::Allow => Some(Effect::Allow),
                    claude_settings::PermissionRule::Deny => Some(Effect::Deny),
                    claude_settings::PermissionRule::Ask => Some(Effect::Ask),
                    _ => None,
                })
        }
        _ => None,
    }
}

/// Extract the additional_context from a PreToolUse [`HookOutput`].
pub fn get_context(output: &HookOutput) -> Option<String> {
    match &output.hook_specific_output {
        Some(HookSpecificOutput::PreToolUse(pre)) => pre.additional_context.clone(),
        _ => None,
    }
}

/// Extract the permission_decision_reason from a PreToolUse [`HookOutput`].
pub fn get_reason(output: &HookOutput) -> Option<String> {
    match &output.hook_specific_output {
        Some(HookSpecificOutput::PreToolUse(pre)) => pre.permission_decision_reason.clone(),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// assert_decision! macro
// ---------------------------------------------------------------------------

/// Assert that evaluating a policy against a hook event produces the expected effect.
///
/// # Usage
///
/// ```ignore
/// let settings = TestPolicy::deny_all().allow_exec("git").build();
/// let input = pre_tool_use("Bash", bash_command("git status"));
/// assert_decision!(settings, input, Effect::Allow);
/// ```
///
/// With optional reason substring check:
///
/// ```ignore
/// assert_decision!(settings, input, Effect::Allow, reason_contains: "allow");
/// ```
#[macro_export]
macro_rules! assert_decision {
    ($settings:expr, $input:expr, $expected_effect:expr) => {{
        let result =
            $crate::permissions::check_permission(&$input, &$settings).expect("check_permission");
        let effect = $crate::test_utils::get_effect(&result);
        assert_eq!(
            effect,
            Some($expected_effect),
            "expected {:?}, got {:?}",
            $expected_effect,
            effect
        );
        result
    }};
    ($settings:expr, $input:expr, $expected_effect:expr, reason_contains: $substr:expr) => {{
        let result = $crate::assert_decision!($settings, $input, $expected_effect);
        let reason = $crate::test_utils::get_reason(&result);
        let reason_str = reason.as_deref().unwrap_or("");
        assert!(
            reason_str.contains($substr),
            "expected reason to contain {:?}, got {:?}",
            $substr,
            reason_str
        );
        result
    }};
}

// ---------------------------------------------------------------------------
// Tests for test_utils
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Effect;

    #[test]
    fn test_policy_builder_deny_all() {
        let settings = TestPolicy::deny_all().build();
        let input = pre_tool_use("Bash", bash_command("ls"));
        let result =
            crate::permissions::check_permission(&input, &settings).expect("check_permission");
        assert_eq!(get_effect(&result), Some(Effect::Deny));
    }

    #[test]
    fn test_policy_builder_allow_exec() {
        let settings = TestPolicy::deny_all().allow_exec("git").build();
        let input = pre_tool_use("Bash", bash_command("git status"));
        assert_decision!(settings, input, Effect::Allow);
    }

    #[test]
    fn test_policy_builder_deny_exec() {
        let settings = TestPolicy::deny_all()
            .deny_exec("rm")
            .allow_all_tools()
            .build();
        let input = pre_tool_use("Bash", bash_command("rm -rf /"));
        assert_decision!(settings, input, Effect::Deny);
    }

    #[test]
    fn test_policy_builder_allow_read() {
        let settings = TestPolicy::deny_all()
            .allow_read("/home/user/project")
            .build();
        let input = pre_tool_use("Read", read_file("/home/user/project/src/main.rs"));
        assert_decision!(settings, input, Effect::Allow);
    }

    #[test]
    fn test_policy_builder_deny_read_outside_prefix() {
        let settings = TestPolicy::deny_all()
            .allow_read("/home/user/project")
            .build();
        let input = pre_tool_use("Read", read_file("/etc/passwd"));
        assert_decision!(settings, input, Effect::Deny);
    }

    #[test]
    fn test_policy_builder_allow_write() {
        let settings = TestPolicy::deny_all().allow_write("/tmp").build();
        let input = pre_tool_use("Write", write_file("/tmp/test.txt"));
        assert_decision!(settings, input, Effect::Allow);
    }

    #[test]
    fn test_policy_builder_ask_all() {
        let settings = TestPolicy::ask_all().build();
        let input = pre_tool_use("Bash", bash_command("ls"));
        assert_decision!(settings, input, Effect::Ask);
    }

    #[test]
    fn test_assert_decision_macro_with_reason() {
        let settings = TestPolicy::deny_all().allow_exec("git").build();
        let input = pre_tool_use("Bash", bash_command("git status"));
        assert_decision!(settings, input, Effect::Allow, reason_contains: "allow");
    }

    #[test]
    fn test_pre_tool_use_builder() {
        let input = pre_tool_use("Bash", bash_command("ls"));
        assert_eq!(input.tool_name, "Bash");
        assert_eq!(input.hook_event_name, "PreToolUse");
        assert_eq!(input.tool_input["command"], "ls");
    }

    #[test]
    fn test_post_tool_use_builder() {
        let response = serde_json::json!({"output": "file contents"});
        let input = post_tool_use("Read", read_file("/tmp/foo"), response.clone());
        assert_eq!(input.hook_event_name, "PostToolUse");
        assert_eq!(input.tool_response, Some(response));
    }

    #[test]
    fn test_environment_write_policy() {
        let env = TestEnvironment::new();
        let path = env.write_policy("test.json", r#"{"hello": "world"}"#);
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, r#"{"hello": "world"}"#);
    }

    #[test]
    fn test_tool_input_builders() {
        assert_eq!(bash_command("ls")["command"], "ls");
        assert_eq!(read_file("/tmp/foo")["file_path"], "/tmp/foo");
        assert_eq!(write_file("/tmp/bar")["file_path"], "/tmp/bar");
        assert_eq!(edit_file("/tmp/baz")["file_path"], "/tmp/baz");
        assert_eq!(glob_pattern("**/*.rs")["pattern"], "**/*.rs");
        assert_eq!(grep_pattern("fn main")["pattern"], "fn main");
    }
}
