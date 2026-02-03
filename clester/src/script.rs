//! Test script parsing for clester.
//!
//! Parses YAML test scripts that define settings configurations,
//! hook invocation steps, and expected outcomes.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

/// A complete test script defining an end-to-end test scenario.
#[derive(Debug, Clone, Deserialize)]
pub struct TestScript {
    /// Metadata about the test.
    pub meta: Meta,

    /// Settings to configure at various levels before running steps.
    #[serde(default)]
    pub settings: SettingsConfig,

    /// Clash-specific configuration (policy document).
    #[serde(default)]
    pub clash: Option<ClashConfig>,

    /// Ordered sequence of hook invocations to execute.
    pub steps: Vec<Step>,
}

/// Clash-specific settings: policy document for the test environment.
#[derive(Debug, Clone, Deserialize)]
pub struct ClashConfig {
    /// Raw YAML string written directly to ~/.clash/policy.yaml.
    #[serde(default)]
    pub policy_raw: Option<String>,
}

/// Test metadata.
#[derive(Debug, Clone, Deserialize)]
pub struct Meta {
    /// Human-readable name of the test.
    pub name: String,

    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
}

/// Settings configuration at multiple levels.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SettingsConfig {
    /// User-level settings (~/.claude/settings.json).
    #[serde(default)]
    pub user: Option<SettingsSpec>,

    /// Project-level settings (.claude/settings.json).
    #[serde(default)]
    pub project: Option<SettingsSpec>,

    /// Project-local settings (.claude/settings.local.json).
    #[serde(default)]
    pub project_local: Option<SettingsSpec>,
}

/// Specification for settings at a single level.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SettingsSpec {
    /// Permission rules.
    #[serde(default)]
    pub permissions: Option<PermissionsSpec>,

    /// Model override.
    #[serde(default)]
    pub model: Option<String>,

    /// Environment variables.
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,
}

/// Permission rules specification.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PermissionsSpec {
    #[serde(default)]
    pub allow: Vec<String>,

    #[serde(default)]
    pub deny: Vec<String>,

    #[serde(default)]
    pub ask: Vec<String>,
}

/// A single test step: invoke a hook and check the result.
#[derive(Debug, Clone, Deserialize)]
pub struct Step {
    /// Human-readable name for this step.
    pub name: String,

    /// Which hook to invoke: "pre-tool-use", "post-tool-use", "permission-request", "notification".
    pub hook: String,

    /// Tool name (for tool-related hooks): "Bash", "Read", "Write", "Edit".
    #[serde(default)]
    pub tool_name: Option<String>,

    /// Tool input as a free-form map (e.g., {"command": "git status"}).
    #[serde(default)]
    pub tool_input: Option<serde_json::Value>,

    /// For notification hooks: the notification message.
    #[serde(default)]
    pub message: Option<String>,

    /// For notification hooks: the notification type.
    #[serde(default)]
    pub notification_type: Option<String>,

    /// Expected outcome assertions.
    pub expect: Expectation,
}

/// Expected outcome of a step.
#[derive(Debug, Clone, Deserialize)]
pub struct Expectation {
    /// Expected permission decision: "allow", "deny", "ask".
    #[serde(default)]
    pub decision: Option<String>,

    /// Expected exit code (default: 0).
    #[serde(default)]
    pub exit_code: Option<i32>,

    /// If true, expect the output to have no hook_specific_output (e.g., continue_execution).
    #[serde(default)]
    pub no_decision: Option<bool>,

    /// Expected substring in the decision reason.
    #[serde(default)]
    pub reason_contains: Option<String>,
}

impl TestScript {
    /// Parse a test script from a YAML file.
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::from_str(&content)
    }

    /// Parse a test script from a YAML string.
    pub fn from_str(content: &str) -> anyhow::Result<Self> {
        Ok(serde_yaml::from_str(content)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_script() {
        let yaml = r#"
meta:
  name: basic permissions
  description: Test allow/deny/ask

settings:
  user:
    permissions:
      allow:
        - "Bash(git:*)"
      deny:
        - "Read(.env)"

steps:
  - name: git status allowed
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: git status
    expect:
      decision: allow

  - name: read .env denied
    hook: pre-tool-use
    tool_name: Read
    tool_input:
      file_path: ".env"
    expect:
      decision: deny
"#;

        let script = TestScript::from_str(yaml).unwrap();
        assert_eq!(script.meta.name, "basic permissions");
        assert_eq!(script.steps.len(), 2);
        assert_eq!(script.steps[0].expect.decision.as_deref(), Some("allow"));
        assert_eq!(script.steps[1].expect.decision.as_deref(), Some("deny"));
    }

    #[test]
    fn test_parse_notification_step() {
        let yaml = r#"
meta:
  name: notification test

steps:
  - name: handle notification
    hook: notification
    message: Claude needs your permission
    notification_type: permission_prompt
    expect:
      no_decision: true
      exit_code: 0
"#;

        let script = TestScript::from_str(yaml).unwrap();
        assert_eq!(script.steps[0].hook, "notification");
        assert_eq!(script.steps[0].expect.no_decision, Some(true));
    }

    #[test]
    fn test_parse_clash_config() {
        let yaml = r#"
meta:
  name: clash config test

clash:
  policy_raw: |
    default: ask
    rules:
      allow bash git *:
      deny read .env:

steps:
  - name: test
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: git status
    expect:
      decision: allow
"#;

        let script = TestScript::from_str(yaml).unwrap();
        let clash = script.clash.expect("clash config should be present");
        let raw = clash.policy_raw.expect("policy_raw should be present");
        assert!(raw.contains("default: ask"));
        assert!(raw.contains("allow bash git *"));
    }

    #[test]
    fn test_parse_clash_config_omitted() {
        let yaml = r#"
meta:
  name: no clash config

steps:
  - name: test
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: git status
    expect:
      decision: ask
"#;

        let script = TestScript::from_str(yaml).unwrap();
        assert!(script.clash.is_none());
    }

    #[test]
    fn test_parse_multi_level_settings() {
        let yaml = r#"
meta:
  name: multi-level settings

settings:
  user:
    permissions:
      allow:
        - "Bash(git:*)"
  project:
    permissions:
      deny:
        - "Read(.env)"
  project_local:
    permissions:
      allow:
        - "Bash(npm run test)"

steps:
  - name: test
    hook: pre-tool-use
    tool_name: Bash
    tool_input:
      command: git status
    expect:
      decision: allow
"#;

        let script = TestScript::from_str(yaml).unwrap();
        assert!(script.settings.user.is_some());
        assert!(script.settings.project.is_some());
        assert!(script.settings.project_local.is_some());
    }
}
