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

    /// Clash-specific configuration (policy).
    #[serde(default)]
    pub clash: Option<ClashConfig>,

    /// Ordered sequence of hook invocations to execute.
    pub steps: Vec<Step>,
}

/// Clash-specific settings: policy document.
#[derive(Debug, Clone, Deserialize)]
pub struct ClashConfig {
    /// Policy document to write to ~/.clash/policy.yaml (old format).
    #[serde(default)]
    pub policy: Option<PolicySpec>,

    /// Raw YAML string written directly to ~/.clash/policy.yaml (new format).
    /// When present, takes precedence over `policy`.
    #[serde(default)]
    pub policy_raw: Option<String>,
}

/// Policy document specification for ~/.clash/policy.yaml.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicySpec {
    /// Default effect when no rule matches: "allow", "deny", "ask", "delegate".
    #[serde(default = "PolicySpec::default_effect")]
    pub default: String,

    /// Policy rules — supports both YAML list and mapping formats.
    #[serde(default, deserialize_with = "deserialize_rules")]
    pub rules: Vec<String>,
}

impl PolicySpec {
    fn default_effect() -> String {
        "ask".into()
    }
}

/// Deserialize rules from either a YAML sequence or mapping.
fn deserialize_rules<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let value = serde_yaml::Value::deserialize(deserializer)?;
    match value {
        serde_yaml::Value::Sequence(seq) => seq
            .into_iter()
            .map(|v| match v {
                serde_yaml::Value::String(s) => Ok(s),
                _ => Err(Error::custom("rule must be a string")),
            })
            .collect(),
        serde_yaml::Value::Mapping(map) => {
            let mut rules = Vec::new();
            for (key, value) in map {
                let rule_key = match key {
                    serde_yaml::Value::String(s) => s,
                    _ => return Err(Error::custom("rule key must be a string")),
                };
                let constraint = match &value {
                    serde_yaml::Value::String(s) => Some(s.clone()),
                    serde_yaml::Value::Null => None,
                    serde_yaml::Value::Sequence(seq) if seq.is_empty() => None,
                    _ => {
                        return Err(Error::custom(format!(
                            "constraint for '{}' must be a string, null, or []",
                            rule_key
                        )));
                    }
                };
                if let Some(constraint) = constraint {
                    rules.push(format!("{} : {}", rule_key, constraint));
                } else {
                    rules.push(rule_key);
                }
            }
            Ok(rules)
        }
        serde_yaml::Value::Null => Ok(Vec::new()),
        _ => Err(Error::custom("rules must be a sequence or mapping")),
    }
}

/// Test metadata.
#[derive(Debug, Clone, Deserialize)]
pub struct Meta {
    /// Human-readable name of the test.
    pub name: String,

    /// Optional description.
    #[serde(default)]
    #[allow(dead_code)]
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
  policy:
    default: ask
    rules:
      - "allow * bash git *"
      - "deny * read .env"

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
        let policy = clash.policy.expect("policy should be present");
        assert_eq!(policy.default, "ask");
        assert_eq!(policy.rules.len(), 2);
        assert_eq!(policy.rules[0], "allow * bash git *");
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
