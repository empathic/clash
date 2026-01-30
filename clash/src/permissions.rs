use claude_settings::PermissionRule;
use claude_settings::policy::{Effect, Verb};
use tracing::{Level, info, instrument, warn};

use crate::hooks::{HookOutput, ToolInput, ToolUseHookInput};
use crate::settings::{ClashSettings, EngineMode};

/// Check if a tool invocation should be allowed, denied, or require user confirmation.
#[instrument(level=Level::INFO)]
pub fn check_permission(
    input: &ToolUseHookInput,
    settings: &ClashSettings,
) -> anyhow::Result<HookOutput> {
    // TODO(eliot): re-enable mac notifications
    match settings.engine_mode {
        EngineMode::Policy => check_permission_policy(input, settings),
        EngineMode::Legacy => check_permission_legacy(input, settings),
        EngineMode::Auto => {
            // If a policy document is loaded, use the policy engine.
            // Otherwise, fall back to legacy.
            if settings.policy.is_some() {
                check_permission_policy(input, settings)
            } else {
                check_permission_legacy(input, settings)
            }
        }
    }
}

/// Check permission using the new policy engine (entity, verb, noun triples).
fn check_permission_policy(
    input: &ToolUseHookInput,
    settings: &ClashSettings,
) -> anyhow::Result<HookOutput> {
    let compiled = match settings.compiled_policy() {
        Some(c) => c,
        None => {
            warn!("Policy engine selected but no policy could be compiled; falling back to ask");
            return Ok(HookOutput::ask(Some(
                "policy engine: no compiled policy available".into(),
            )));
        }
    };

    // Map tool_name → Verb
    let verb = match Verb::from_tool_name(&input.tool_name) {
        Some(v) => v,
        None => {
            info!(tool = %input.tool_name, "Unknown tool name for policy evaluation");
            return Ok(HookOutput::ask(Some(format!(
                "unknown tool '{}' for policy evaluation",
                input.tool_name
            ))));
        }
    };

    // Extract the noun (the resource being acted on) from the tool input.
    let noun = extract_noun(input);

    // Default entity — the hook input doesn't carry entity info yet,
    // so we treat all invocations as coming from "agent".
    let entity = "agent";

    let decision = compiled.evaluate(entity, &verb, &noun);
    info!(
        entity,
        verb = %verb,
        noun = %noun,
        effect = %decision.effect,
        reason = ?decision.reason,
        "Policy decision"
    );

    Ok(match decision.effect {
        Effect::Permit => HookOutput::allow(decision.reason.or(Some("policy: permitted".into()))),
        Effect::Forbid => HookOutput::deny(
            decision
                .reason
                .unwrap_or_else(|| "policy: forbidden".into()),
        ),
        Effect::Ask => HookOutput::ask(decision.reason.or(Some("policy: ask".into()))),
        Effect::Delegate => {
            // Delegation is not yet implemented; fall back to ask.
            warn!("Delegate effect not yet implemented; falling back to ask");
            HookOutput::ask(Some("policy: delegation not yet implemented".into()))
        }
    })
}

/// Extract the noun (resource identifier) from a tool input.
///
/// For Bash: the command string.
/// For Read/Write/Edit: the file path.
/// For unknown tools: the JSON-serialized tool input.
fn extract_noun(input: &ToolUseHookInput) -> String {
    match input.typed_tool_input() {
        ToolInput::Bash(bash) => bash.command,
        ToolInput::Write(write) => write.file_path,
        ToolInput::Edit(edit) => edit.file_path,
        ToolInput::Read(read) => read.file_path,
        ToolInput::Unknown(value) => value.to_string(),
    }
}

/// Check permission using the legacy Claude Code PermissionSet.
fn check_permission_legacy(
    input: &ToolUseHookInput,
    settings: &ClashSettings,
) -> anyhow::Result<HookOutput> {
    match &settings.from_claude {
        Some(claude) => Ok(check_permission_claude(input, claude)),
        None => Ok(HookOutput::ask(Some(
            "clash currently not configured".into(),
        ))),
    }
}

#[instrument(level=Level::INFO)]
pub fn check_permission_claude(
    input: &ToolUseHookInput,
    settings: &claude_settings::Settings,
) -> HookOutput {
    let perms = &settings.permissions;
    fn decide(tool: &str, arg: Option<&str>, perms: &claude_settings::PermissionSet) -> HookOutput {
        match perms.check(tool, arg) {
            PermissionRule::Allow => HookOutput::allow(Some("explicitly allowed".into())),
            PermissionRule::Deny => HookOutput::deny("explicitly denied".into()),
            _ => HookOutput::ask(Some("no applicable setting".into())),
        }
    }

    match input.typed_tool_input() {
        ToolInput::Bash(bash_input) => decide("Bash", Some(&bash_input.command), perms),
        ToolInput::Write(write_input) => decide("Write", Some(&write_input.file_path), perms),
        ToolInput::Edit(edit_input) => decide("Edit", Some(&edit_input.file_path), perms),
        ToolInput::Read(read_input) => decide("Read", Some(&read_input.file_path), perms),
        ToolInput::Unknown(value) => {
            warn!("value" = ?value, "Unknown tool type");
            HookOutput::ask(Some("Unknown tool type".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::ToolUseHookInput;
    use anyhow::Result;
    use serde_json::json;

    fn bash_input(command: &str) -> ToolUseHookInput {
        ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_input: json!({"command": command}),
            ..Default::default()
        }
    }
    fn read_input(file_path: &str) -> ToolUseHookInput {
        ToolUseHookInput {
            tool_name: "Read".into(),
            tool_input: json!({"file_path": file_path}),
            ..Default::default()
        }
    }

    #[test]
    fn test_allow_npm_exact() -> Result<()> {
        let settings: ClashSettings = serde_json::from_value(json!({"from_claude": {
            "permissions": {
                "allow": ["Bash(npm run test)"],
            }
        }}))
        .unwrap();
        assert_eq!(
            check_permission(&bash_input("npm run test"), &settings)?,
            HookOutput::allow(Some("explicitly allowed".into())),
        );
        Ok(())
    }
    #[test]
    fn test_allow_npm_glob() -> Result<()> {
        let settings: ClashSettings = serde_json::from_value(json!({"from_claude": {
            "permissions": {
                "allow": ["Bash(npm run test *)"],
            }
        }}))
        .unwrap();
        assert_eq!(
            check_permission(&bash_input("npm run test any"), &settings)?,
            HookOutput::allow(Some("explicitly allowed".into())),
        );
        Ok(())
    }
    #[test]
    fn test_allow_empty() -> Result<()> {
        let settings: ClashSettings = serde_json::from_value(json!({"from_claude": {
            "permissions": {
                "allow": [],
            }
        }}))
        .unwrap();
        assert_eq!(
            check_permission(&bash_input("npm run test any"), &settings)?,
            HookOutput::ask(Some("no applicable setting".into())),
        );
        Ok(())
    }
    #[test]
    fn test_deny_glob() -> Result<()> {
        let settings: ClashSettings = serde_json::from_value(json!({"from_claude": {
            "permissions": {
                "allow": [],
                "deny": ["Bash(*)"],
            }
        }}))
        .unwrap();
        assert_eq!(
            check_permission(&bash_input("npm run test any"), &settings)?,
            HookOutput::deny("explicitly denied".into()),
        );
        Ok(())
    }

    // --- Policy engine tests ---

    fn settings_with_policy(toml_str: &str) -> ClashSettings {
        use claude_settings::policy::parse::parse_toml;
        let doc = parse_toml(toml_str).expect("valid TOML");
        ClashSettings {
            engine_mode: crate::settings::EngineMode::Policy,
            from_claude: None,
            policy: Some(doc),
        }
    }

    #[test]
    fn test_policy_permit_bash() -> Result<()> {
        let settings = settings_with_policy(
            r#"
[[statements]]
effect = "permit"
entity = "*"
verb = "execute"
noun = "git *"
"#,
        );
        let result = check_permission(&bash_input("git status"), &settings)?;
        assert_eq!(result, HookOutput::allow(Some("policy: permitted".into())),);
        Ok(())
    }

    #[test]
    fn test_policy_forbid_bash() -> Result<()> {
        let settings = settings_with_policy(
            r#"
[[statements]]
effect = "forbid"
entity = "*"
verb = "execute"
noun = "rm *"
reason = "Destructive command"
"#,
        );
        let result = check_permission(&bash_input("rm -rf /"), &settings)?;
        assert_eq!(result, HookOutput::deny("Destructive command".into()),);
        Ok(())
    }

    #[test]
    fn test_policy_ask_default() -> Result<()> {
        let settings = settings_with_policy(
            r#"
[[statements]]
effect = "permit"
entity = "user"
verb = "execute"
noun = "*"
"#,
        );
        // entity is "agent" by default, so this permit for "user" won't match
        let result = check_permission(&bash_input("ls"), &settings)?;
        assert_eq!(result, HookOutput::ask(Some("policy: ask".into())),);
        Ok(())
    }

    #[test]
    fn test_policy_read_file() -> Result<()> {
        let settings = settings_with_policy(
            r#"
[[statements]]
effect = "permit"
entity = "*"
verb = "read"
noun = "*.rs"
"#,
        );
        let result = check_permission(&read_input("src/main.rs"), &settings)?;
        assert_eq!(result, HookOutput::allow(Some("policy: permitted".into())),);
        Ok(())
    }

    #[test]
    fn test_policy_forbid_overrides_permit() -> Result<()> {
        let settings = settings_with_policy(
            r#"
[[statements]]
effect = "permit"
entity = "*"
verb = "read"
noun = "*"

[[statements]]
effect = "forbid"
entity = "*"
verb = "read"
noun = ".env"
reason = "Never read .env"
"#,
        );
        let result = check_permission(&read_input(".env"), &settings)?;
        assert_eq!(result, HookOutput::deny("Never read .env".into()),);
        Ok(())
    }

    #[test]
    fn test_auto_mode_uses_policy_when_available() -> Result<()> {
        use claude_settings::policy::parse::parse_toml;
        let doc = parse_toml(
            r#"
[[statements]]
effect = "permit"
entity = "*"
verb = "execute"
noun = "echo *"
"#,
        )
        .unwrap();
        let settings = ClashSettings {
            engine_mode: crate::settings::EngineMode::Auto,
            from_claude: None,
            policy: Some(doc),
        };
        let result = check_permission(&bash_input("echo hello"), &settings)?;
        assert_eq!(result, HookOutput::allow(Some("policy: permitted".into())),);
        Ok(())
    }

    #[test]
    fn test_auto_mode_falls_back_to_legacy() -> Result<()> {
        let settings: ClashSettings = serde_json::from_value(json!({
            "engine_mode": "auto",
            "from_claude": {
                "permissions": {
                    "allow": ["Bash(npm run test)"],
                }
            }
        }))
        .unwrap();
        // No policy loaded → should fall back to legacy
        assert_eq!(
            check_permission(&bash_input("npm run test"), &settings)?,
            HookOutput::allow(Some("explicitly allowed".into())),
        );
        Ok(())
    }
}
