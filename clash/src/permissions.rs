use claude_settings::policy::{Effect, EvalContext, Verb};
use claude_settings::sandbox::SandboxPolicy;
use tracing::{Level, info, instrument, warn};

use crate::hooks::{HookOutput, ToolInput, ToolUseHookInput};
use crate::settings::ClashSettings;

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

    // Extract the noun (the resource being acted on) from the tool input.
    let noun = extract_noun(input);

    // Default entity — the hook input doesn't carry entity info yet,
    // so we treat all invocations as coming from "agent".
    let entity = "agent";

    // Build evaluation context with cwd and tool_input for constraint evaluation.
    let ctx = EvalContext {
        entity,
        verb: &verb,
        noun: &noun,
        cwd: &input.cwd,
        tool_input: &input.tool_input,
    };

    let decision = compiled.evaluate_with_context(&ctx);
    info!(
        entity,
        verb = %verb,
        noun = %noun,
        effect = %decision.effect,
        reason = ?decision.reason,
        "Policy decision"
    );

    Ok(match decision.effect {
        Effect::Allow => {
            let mut output = HookOutput::allow(decision.reason.or(Some("policy: allowed".into())));
            // If there's a sandbox policy and this is a Bash tool, rewrite the
            // command to run through `clash sandbox exec`.
            if let Some(sandbox_policy) = settings.sandbox_policy() {
                if let Some(updated) = wrap_bash_with_sandbox(input, sandbox_policy) {
                    output.set_updated_input(updated);
                    info!("Rewrote Bash command to run under sandbox");
                }
            }
            output
        }
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

/// If the tool input is a Bash command and a sandbox policy exists,
/// rewrite the command to run through `clash sandbox exec`.
///
/// Returns the updated `tool_input` JSON if rewriting is applicable, or None.
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
        obj.insert("command".into(), serde_json::Value::String(sandboxed_command));
    }

    Some(updated)
}

/// Simple shell escaping: wrap in single quotes, escaping embedded single quotes.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
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
            sandbox: None,
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
        };
        ClashSettings {
            engine_mode: crate::settings::EngineMode::Auto,
            policy: Some(doc),
            sandbox: None,
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
            sandbox: None,
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
        assert_eq!(result, HookOutput::allow(Some("policy: allowed".into())));

        // Command with pipe → constraint fails → falls through to default (ask)
        let result = check_permission(&bash_input("cat foo | grep bar"), &settings)?;
        assert_eq!(result, HookOutput::ask(Some("policy: ask".into())));
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
        assert_eq!(result, HookOutput::allow(Some("policy: allowed".into())));

        // git push --force → constraint fails
        let result = check_permission(&bash_input("git push --force origin main"), &settings)?;
        assert_eq!(result, HookOutput::ask(Some("policy: ask".into())));
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
        assert_eq!(result, HookOutput::allow(Some("policy: allowed".into())));

        // File outside cwd → constraint fails
        let result = check_permission(
            &read_input_with_cwd("/etc/passwd", "/home/user/project"),
            &settings,
        )?;
        assert_eq!(result, HookOutput::ask(Some("policy: ask".into())));
        Ok(())
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

        // git status (no pipe, no force, within cwd) → allowed
        let result = check_permission(
            &bash_input_with_cwd("git status", "/home/user/project"),
            &settings,
        )?;
        assert_eq!(result, HookOutput::allow(Some("policy: allowed".into())));

        // git push --force → git-safe constraint fails → default
        let result = check_permission(
            &bash_input_with_cwd("git push --force origin main", "/home/user/project"),
            &settings,
        )?;
        assert_eq!(result, HookOutput::ask(Some("policy: ask".into())));

        // rm -rf / → unconditional deny
        let result = check_permission(&bash_input("rm -rf /"), &settings)?;
        assert_eq!(result, HookOutput::deny("policy: denied".into()));

        // read file under cwd → allowed
        let result = check_permission(
            &read_input_with_cwd("/home/user/project/Cargo.toml", "/home/user/project"),
            &settings,
        )?;
        assert_eq!(result, HookOutput::allow(Some("policy: allowed".into())));

        // read file outside cwd → default
        let result = check_permission(
            &read_input_with_cwd("/etc/passwd", "/home/user/project"),
            &settings,
        )?;
        assert_eq!(result, HookOutput::ask(Some("policy: ask".into())));

        Ok(())
    }
}
