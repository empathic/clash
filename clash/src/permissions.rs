use claude_settings::policy::{Effect, EvalContext, Verb};
use claude_settings::sandbox::SandboxPolicy;
use tracing::{Level, info, instrument, warn};

use crate::hooks::{HookOutput, ToolInput, ToolUseHookInput};
use crate::settings::ClashSettings;

/// Check if a tool invocation should be allowed, denied, or require user confirmation.
#[instrument(level = Level::TRACE, ret)]
pub fn check_permission(
    input: &ToolUseHookInput,
    settings: &ClashSettings,
) -> anyhow::Result<HookOutput> {
    // TODO(eliot): re-enable mac notifications
    check_permission_policy(input, settings)
}

/// Check permission using the policy engine (entity, verb, noun triples).
#[instrument(level = Level::TRACE, ret, skip(settings))]
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

    // Map tool_name → Verb. For known tools, use the canonical verb.
    // For unknown tools with old-format policies, fall back to ask.
    // For new-format policies, the raw tool name is matched via verb_str.
    let verb = Verb::from_tool_name(&input.tool_name);
    let fallback_verb = Verb::Execute; // used when verb is None for new-format
    let verb_ref = verb.as_ref().unwrap_or(&fallback_verb);

    // Extract the noun (the resource being acted on) from the tool input.
    let noun = extract_noun(input);

    // Default entity — the hook input doesn't carry entity info yet,
    // so we treat all invocations as coming from "agent".
    let entity = "agent";

    // Build evaluation context with cwd and tool_input for constraint evaluation.
    // verb_str uses the tool_name lowercased for new-format matching.
    let verb_str_owned = if let Some(ref v) = verb {
        v.rule_name().to_string()
    } else {
        input.tool_name.to_lowercase()
    };
    let ctx = EvalContext {
        entity,
        verb: verb_ref,
        noun: &noun,
        cwd: &input.cwd,
        tool_input: &input.tool_input,
        verb_str: &verb_str_owned,
    };

    let decision = compiled.evaluate_with_context(&ctx);
    info!(
        entity,
        verb = %verb_str_owned,
        noun = %noun,
        effect = %decision.effect,
        reason = ?decision.reason,
        "Policy decision"
    );

    // Write audit log entry if enabled.
    crate::audit::log_decision(
        &settings.audit,
        &input.tool_name,
        &input.tool_input,
        decision.effect,
        decision.reason.as_deref(),
        &decision.trace,
    );

    let explanation = decision.explanation();
    let additional_context = if explanation.is_empty() {
        None
    } else {
        Some(explanation.join("\n"))
    };

    Ok(match decision.effect {
        Effect::Allow => {
            let mut output = HookOutput::allow_with_context(
                decision.reason.or(Some("policy: allowed".into())),
                additional_context,
            );
            // If the policy decision includes a per-command sandbox, rewrite the
            // command to run through `clash sandbox exec`.
            if let Some(ref sandbox_policy) = decision.sandbox
                && let Some(updated) = wrap_bash_with_sandbox(input, sandbox_policy)
            {
                output.set_updated_input(updated);
                info!("Rewrote Bash command to run under sandbox");
            }
            output
        }
        Effect::Deny => HookOutput::deny_with_context(
            decision.reason.unwrap_or_else(|| "policy: denied".into()),
            additional_context,
        ),
        Effect::Ask => HookOutput::ask_with_context(
            decision.reason.or(Some("policy: ask".into())),
            additional_context,
        ),
        Effect::Delegate => {
            // Delegation is not yet implemented; fall back to ask.
            warn!("Delegate effect not yet implemented; falling back to ask");
            HookOutput::ask_with_context(
                Some("policy: delegation not yet implemented".into()),
                additional_context,
            )
        }
    })
}

/// If the tool input is a Bash command and a sandbox policy exists,
/// rewrite the command to run through `clash sandbox exec`.
///
/// Returns the updated `tool_input` JSON if rewriting is applicable, or None.
#[instrument(level = Level::TRACE, skip(input, sandbox_policy))]
fn wrap_bash_with_sandbox(
    input: &ToolUseHookInput,
    sandbox_policy: &SandboxPolicy,
) -> Option<serde_json::Value> {
    let bash_input = match input.typed_tool_input() {
        ToolInput::Bash(b) => b,
        _ => return None,
    };

    let clash_bin = std::env::current_exe().ok()?;
    let policy_json = serde_json::to_string(sandbox_policy).ok()?;

    // Build: clash sandbox exec --policy <json> --cwd <cwd> -- bash -c "<original command>"
    let sandboxed_command = format!(
        "{} sandbox exec --policy {} --cwd {} -- bash -c {}",
        shell_escape(&clash_bin.to_string_lossy()),
        shell_escape(&policy_json),
        shell_escape(&input.cwd),
        shell_escape(&bash_input.command),
    );

    let mut updated = input.tool_input.clone();
    if let Some(obj) = updated.as_object_mut() {
        obj.insert(
            "command".into(),
            serde_json::Value::String(sandboxed_command),
        );
    }

    Some(updated)
}

/// Simple shell escaping: wrap in single quotes, escaping embedded single quotes.
#[instrument(level = Level::TRACE)]
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Extract the noun (resource identifier) from a tool input.
///
/// Checks common field names in priority order to extract a meaningful
/// noun from any tool's input JSON. This handles both known tools
/// (Bash, Read, Write, Edit) and arbitrary tools (Glob, Grep, WebSearch, etc.).
#[instrument(level = Level::TRACE, skip(input))]
fn extract_noun(input: &ToolUseHookInput) -> String {
    // Try common noun fields in priority order
    let fields = [
        "command",   // Bash
        "file_path", // Read, Write, Edit, NotebookEdit
        "pattern",   // Glob, Grep
        "query",     // WebSearch
        "url",       // WebFetch
        "path",      // Glob, Grep (secondary field)
        "prompt",    // Task
    ];
    for field in &fields {
        if let Some(val) = input.tool_input.get(*field).and_then(|v| v.as_str()) {
            return val.to_string();
        }
    }
    // Fallback: use the tool name as noun (better than serializing entire JSON)
    input.tool_name.to_lowercase()
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
            notifications: Default::default(),
            notification_warning: None,
            audit: Default::default(),
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
            constraints: Default::default(),
            profiles: Default::default(),
            statements,
            default_config: None,
            profile_defs: Default::default(),
        };
        ClashSettings {
            engine_mode: crate::settings::EngineMode::Auto,
            policy: Some(doc),
            notifications: Default::default(),
            notification_warning: None,
            audit: Default::default(),
        }
    }

    // --- Legacy permissions compiled to policy ---

    #[test]
    fn test_allow_npm_exact() -> Result<()> {
        let settings = settings_with_legacy_perms(vec!["Bash(npm run test)"], vec![], vec![]);
        let result = check_permission(&bash_input("npm run test"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Allow,
            Some("policy: allowed"),
        );
        Ok(())
    }
    #[test]
    fn test_allow_npm_glob() -> Result<()> {
        let settings = settings_with_legacy_perms(vec!["Bash(npm run test *)"], vec![], vec![]);
        let result = check_permission(&bash_input("npm run test any"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Allow,
            Some("policy: allowed"),
        );
        Ok(())
    }
    #[test]
    fn test_allow_empty() -> Result<()> {
        let settings = settings_with_legacy_perms(vec![], vec![], vec![]);
        let result = check_permission(&bash_input("npm run test any"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Ask,
            Some("policy: ask"),
        );
        Ok(())
    }
    #[test]
    fn test_deny_glob() -> Result<()> {
        let settings = settings_with_legacy_perms(vec![], vec!["Bash(*)"], vec![]);
        let result = check_permission(&bash_input("npm run test any"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Deny,
            Some("policy: denied"),
        );
        Ok(())
    }

    // --- Policy engine tests ---

    #[test]
    fn test_policy_allow_bash() -> Result<()> {
        let settings = settings_with_policy("rules:\n  - allow * bash git *\n");
        let result = check_permission(&bash_input("git status"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Allow,
            Some("policy: allowed"),
        );
        Ok(())
    }

    #[test]
    fn test_policy_deny_bash() -> Result<()> {
        let settings = settings_with_policy("rules:\n  - deny * bash rm *\n");
        let result = check_permission(&bash_input("rm -rf /"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Deny,
            Some("policy: denied"),
        );
        Ok(())
    }

    #[test]
    fn test_policy_ask_default() -> Result<()> {
        let settings = settings_with_policy("rules:\n  - allow user bash *\n");
        // entity is "agent" by default, so this allow for "user" won't match
        let result = check_permission(&bash_input("ls"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Ask,
            Some("policy: ask"),
        );
        Ok(())
    }

    #[test]
    fn test_policy_read_file() -> Result<()> {
        let settings = settings_with_policy("rules:\n  - allow * read *.rs\n");
        let result = check_permission(&read_input("src/main.rs"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Allow,
            Some("policy: allowed"),
        );
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
        assert_decision(
            &result,
            claude_settings::PermissionRule::Deny,
            Some("policy: denied"),
        );
        Ok(())
    }

    #[test]
    fn test_auto_mode_uses_policy_when_available() -> Result<()> {
        let doc = parse_yaml("rules:\n  - allow * bash echo *\n").unwrap();
        let settings = ClashSettings {
            engine_mode: crate::settings::EngineMode::Auto,
            policy: Some(doc),
            notifications: Default::default(),
            notification_warning: None,
            audit: Default::default(),
        };
        let result = check_permission(&bash_input("echo hello"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Allow,
            Some("policy: allowed"),
        );
        Ok(())
    }

    #[test]
    fn test_auto_mode_legacy_compiled_to_policy() -> Result<()> {
        // Legacy permissions compiled into a policy document
        let settings = settings_with_legacy_perms(vec!["Bash(npm run test)"], vec![], vec![]);
        let result = check_permission(&bash_input("npm run test"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Allow,
            Some("policy: allowed"),
        );
        Ok(())
    }

    // --- Constraint integration tests ---

    fn bash_input_with_cwd(command: &str, cwd: &str) -> ToolUseHookInput {
        ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_input: json!({"command": command}),
            cwd: cwd.into(),
            ..Default::default()
        }
    }

    fn read_input_with_cwd(file_path: &str, cwd: &str) -> ToolUseHookInput {
        ToolUseHookInput {
            tool_name: "Read".into(),
            tool_input: json!({"file_path": file_path}),
            cwd: cwd.into(),
            ..Default::default()
        }
    }

    #[test]
    fn test_constraint_pipe_blocks_piped_command() -> Result<()> {
        let settings = settings_with_policy(
            "\
constraints:
  safe-io:
    pipe: false
rules:
  - \"allow * bash * : safe-io\"
",
        );
        // Command without pipe → allowed
        let result = check_permission(&bash_input("ls -la"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Allow,
            Some("policy: allowed"),
        );

        // Command with pipe → constraint fails → falls through to default (ask)
        let result = check_permission(&bash_input("cat foo | grep bar"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Ask,
            Some("policy: ask"),
        );
        Ok(())
    }

    #[test]
    fn test_constraint_forbid_args_blocks_force_push() -> Result<()> {
        let settings = settings_with_policy(
            "\
constraints:
  git-safe:
    forbid-args:
      - --force
      - --force-with-lease
rules:
  - \"allow * bash git * : git-safe\"
",
        );
        // git push without --force → allowed
        let result = check_permission(&bash_input("git push origin main"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Allow,
            Some("policy: allowed"),
        );

        // git push --force → constraint fails
        let result = check_permission(&bash_input("git push --force origin main"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Ask,
            Some("policy: ask"),
        );
        Ok(())
    }

    #[test]
    fn test_constraint_fs_subpath_with_cwd() -> Result<()> {
        let settings = settings_with_policy(
            "\
constraints:
  local:
    fs: subpath(.)
rules:
  - \"allow * read * : local\"
",
        );
        // File under cwd → allowed
        let result = check_permission(
            &read_input_with_cwd("/home/user/project/src/main.rs", "/home/user/project"),
            &settings,
        )?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Allow,
            Some("policy: allowed"),
        );

        // File outside cwd → constraint fails
        let result = check_permission(
            &read_input_with_cwd("/etc/passwd", "/home/user/project"),
            &settings,
        )?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Ask,
            Some("policy: ask"),
        );
        Ok(())
    }

    /// Extract the permission decision from a HookOutput.
    fn get_decision(output: &HookOutput) -> Option<claude_settings::PermissionRule> {
        match &output.hook_specific_output {
            Some(crate::hooks::HookSpecificOutput::PreToolUse(pre)) => {
                pre.permission_decision.clone()
            }
            _ => None,
        }
    }

    /// Check if the HookOutput has an updated_input (sandbox rewrite).
    fn has_updated_input(output: &HookOutput) -> bool {
        match &output.hook_specific_output {
            Some(crate::hooks::HookSpecificOutput::PreToolUse(pre)) => pre.updated_input.is_some(),
            _ => false,
        }
    }

    /// Get the additional context from a HookOutput (for explanation testing).
    fn get_additional_context(output: &HookOutput) -> Option<String> {
        match &output.hook_specific_output {
            Some(crate::hooks::HookSpecificOutput::PreToolUse(pre)) => {
                pre.additional_context.clone()
            }
            _ => None,
        }
    }

    /// Assert that a HookOutput has the expected decision and reason, ignoring additional_context.
    fn assert_decision(
        output: &HookOutput,
        expected_decision: claude_settings::PermissionRule,
        expected_reason: Option<&str>,
    ) {
        let decision = get_decision(output);
        assert_eq!(decision, Some(expected_decision), "unexpected decision");
        let reason = match &output.hook_specific_output {
            Some(crate::hooks::HookSpecificOutput::PreToolUse(pre)) => {
                pre.permission_decision_reason.as_deref()
            }
            _ => None,
        };
        assert_eq!(reason, expected_reason, "unexpected reason");
    }

    #[test]
    fn test_profile_composition_integration() -> Result<()> {
        let settings = settings_with_policy(
            "\
constraints:
  local:
    fs: subpath(.)
  safe-io:
    pipe: false
    redirect: false
  git-safe:
    forbid-args:
      - --force
      - --hard
profiles:
  sandboxed: local & safe-io
  strict-git: sandboxed & git-safe
rules:
  - \"allow * bash git * : strict-git\"
  - \"allow * bash cargo * : sandboxed\"
  - \"allow * read * : local\"
  - deny * bash rm *
",
        );

        // git status (no pipe, no force, within cwd) → allowed with sandbox
        let result = check_permission(
            &bash_input_with_cwd("git status", "/home/user/project"),
            &settings,
        )?;
        assert_eq!(
            get_decision(&result),
            Some(claude_settings::PermissionRule::Allow)
        );
        // Bash command with fs constraint should have sandbox-rewritten input
        assert!(has_updated_input(&result));

        // git push --force → git-safe constraint fails → default
        let result = check_permission(
            &bash_input_with_cwd("git push --force origin main", "/home/user/project"),
            &settings,
        )?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Ask,
            Some("policy: ask"),
        );

        // rm -rf / → unconditional deny
        let result = check_permission(&bash_input("rm -rf /"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Deny,
            Some("policy: denied"),
        );

        // read file under cwd → allowed (fs acts as permission guard, no sandbox)
        let result = check_permission(
            &read_input_with_cwd("/home/user/project/Cargo.toml", "/home/user/project"),
            &settings,
        )?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Allow,
            Some("policy: allowed"),
        );

        // read file outside cwd → default
        let result = check_permission(
            &read_input_with_cwd("/etc/passwd", "/home/user/project"),
            &settings,
        )?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Ask,
            Some("policy: ask"),
        );

        Ok(())
    }

    // --- Explanation content tests ---

    #[test]
    fn test_explanation_contains_matched_rule() -> Result<()> {
        let settings = settings_with_policy("rules:\n  - allow * bash git *\n");
        let result = check_permission(&bash_input("git status"), &settings)?;
        let ctx = get_additional_context(&result).expect("should have additional_context");
        assert!(
            ctx.contains("matched:"),
            "explanation should contain 'matched:' but got: {ctx}"
        );
        assert!(
            ctx.contains("allow"),
            "explanation should mention allow but got: {ctx}"
        );
        Ok(())
    }

    #[test]
    fn test_explanation_deny_overrides_allow_detail() -> Result<()> {
        let settings = settings_with_policy(
            "\
rules:
  - allow * read *
  - deny * read .env
",
        );
        let result = check_permission(&read_input(".env"), &settings)?;
        let ctx = get_additional_context(&result).expect("should have additional_context");
        assert!(
            ctx.contains("deny"),
            "explanation should mention deny but got: {ctx}"
        );
        Ok(())
    }

    #[test]
    fn test_explanation_constraint_failure() -> Result<()> {
        let settings = settings_with_policy(
            "\
constraints:
  safe-io:
    pipe: false
rules:
  - \"allow * bash * : safe-io\"
",
        );
        // Command with pipe → constraint fails
        let result = check_permission(&bash_input("cat foo | grep bar"), &settings)?;
        let ctx = get_additional_context(&result).expect("should have additional_context");
        assert!(
            ctx.contains("pipe"),
            "explanation should mention pipe constraint but got: {ctx}"
        );
        Ok(())
    }

    #[test]
    fn test_explanation_no_rules_matched() -> Result<()> {
        let settings = settings_with_policy("rules:\n  - allow user bash *\n");
        let result = check_permission(&bash_input("ls"), &settings)?;
        let ctx = get_additional_context(&result).expect("should have additional_context");
        assert!(
            ctx.contains("no rules matched"),
            "explanation should say 'no rules matched' but got: {ctx}"
        );
        Ok(())
    }
}
