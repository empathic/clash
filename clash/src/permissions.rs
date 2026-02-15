use crate::policy::Effect;
use tracing::{Level, info, instrument, warn};

use crate::hooks::{HookOutput, ToolInput, ToolUseHookInput};
use crate::settings::ClashSettings;

/// Check if a tool invocation should be allowed, denied, or require user confirmation.
#[instrument(level = Level::TRACE, ret)]
pub fn check_permission(
    input: &ToolUseHookInput,
    settings: &ClashSettings,
) -> anyhow::Result<HookOutput> {
    let tree = match settings.decision_tree() {
        Some(t) => t,
        None => {
            let reason = match settings.policy_error() {
                Some(err) => format!("{}. All tool uses will require approval.", err),
                None => "policy engine: no compiled policy available".into(),
            };
            warn!("{}", reason);
            return Ok(HookOutput::ask(Some(reason), None));
        }
    };

    let decision = tree.evaluate(&input.tool_name, &input.tool_input, &input.cwd);
    let noun = extract_noun(&input.tool_name, &input.tool_input);

    info!(
        tool = %input.tool_name,
        noun = %noun,
        effect = %decision.effect,
        reason = ?decision.reason,
        trace = ?decision.trace,
        "Policy decision"
    );

    // Write audit log entry (global + session).
    crate::audit::log_decision(
        &settings.audit,
        &input.session_id,
        &input.tool_name,
        &input.tool_input,
        decision.effect,
        decision.reason.as_deref(),
        &decision.trace,
    );

    let explanation = decision.human_explanation();
    let additional_context = if explanation.is_empty() {
        None
    } else {
        Some(explanation.join("\n"))
    };

    // Print a concise denial message to stderr so the user sees it in the terminal.
    if decision.effect == Effect::Deny {
        let denial_count = count_session_denials(&input.session_id);
        let verb_str = tool_to_verb_str(&input.tool_name);
        let noun_summary = truncate_noun(&noun, 60);

        eprintln!("clash: blocked {} on {}", verb_str, noun_summary);

        let is_explicit_deny = decision
            .reason
            .as_deref()
            .is_some_and(|r| r.contains("denied") || r.contains("deny"));

        if is_explicit_deny {
            eprintln!("  This action is explicitly denied by your policy.");
            if denial_count <= 3 {
                eprintln!("  Run \"clash policy list\" to see your rules.");
            }
        } else {
            if denial_count <= 1 {
                let explanation = denial_explanation(&verb_str);
                eprintln!("  {}", explanation);
            }

            let suggested = suggest_allow_command(&verb_str, &noun_summary);
            eprintln!("  To allow: {}", suggested);

            if denial_count <= 3 {
                eprintln!("  Or run \"clash policy setup\" for interactive configuration.");
            }
        }
    }

    let verb_str = tool_to_verb_str(&input.tool_name);

    Ok(match decision.effect {
        Effect::Allow => {
            let mut output = HookOutput::allow(
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
        Effect::Deny => {
            let denial_count = count_session_denials(&input.session_id);
            let deny_context = build_deny_context(
                &input.tool_name,
                &verb_str,
                &noun,
                decision.reason.as_deref(),
                denial_count,
            );
            HookOutput::deny(
                decision.reason.unwrap_or_else(|| "policy: denied".into()),
                Some(deny_context),
            )
        }
        Effect::Ask => HookOutput::ask(
            decision.reason.or(Some("policy: ask".into())),
            additional_context,
        ),
    })
}

/// Map a tool name to a short verb string for user-facing messages.
fn tool_to_verb_str(tool_name: &str) -> String {
    match tool_name {
        "Bash" => "bash".into(),
        "Read" => "read".into(),
        "Write" => "write".into(),
        "Edit" => "edit".into(),
        "WebFetch" => "webfetch".into(),
        "WebSearch" => "websearch".into(),
        "Glob" | "Grep" => "read".into(),
        _ => tool_name.to_lowercase(),
    }
}

/// If the tool input is a Bash command and a sandbox policy exists,
/// rewrite the command to run through `clash sandbox exec`.
///
/// Returns the updated `tool_input` JSON if rewriting is applicable, or None.
#[instrument(level = Level::TRACE, skip(input, sandbox_policy))]
fn wrap_bash_with_sandbox(
    input: &ToolUseHookInput,
    sandbox_policy: &crate::policy::sandbox_types::SandboxPolicy,
) -> Option<serde_json::Value> {
    let bash_input = match input.typed_tool_input() {
        ToolInput::Bash(b) => b,
        _ => return None,
    };

    let clash_bin = std::env::current_exe().ok()?;
    let policy_json = serde_json::to_string(sandbox_policy).ok()?;

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

/// Count the number of deny decisions in the current session's audit log.
fn count_session_denials(session_id: &str) -> usize {
    let log_path = crate::audit::session_dir(session_id).join("audit.jsonl");
    let content = match std::fs::read_to_string(&log_path) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    content
        .lines()
        .filter(|line| line.contains("\"decision\":\"deny\""))
        .count()
}

/// Suggest a `clash policy allow` command for a denied verb.
fn suggest_allow_command(verb_str: &str, noun_summary: &str) -> String {
    match verb_str {
        "edit" | "write" => "clash policy allow edit".into(),
        "bash" => "clash policy allow bash".into(),
        "webfetch" | "websearch" => "clash policy allow web".into(),
        "read" => "clash policy allow read".into(),
        _ => format!("clash policy allow \"{} {}\"", verb_str, noun_summary),
    }
}

/// Return a plain-English explanation for why a verb was denied.
fn denial_explanation(verb_str: &str) -> &'static str {
    match verb_str {
        "edit" | "write" => "Claude can't edit files yet.",
        "bash" => "Claude can't run commands yet.",
        "webfetch" | "websearch" => "Claude can't access the web yet.",
        "read" => "Claude can't read files outside the project.",
        _ => "This action isn't allowed yet.",
    }
}

/// Truncate a noun string to approximately `max_len` characters, appending "..." if truncated.
fn truncate_noun(noun: &str, max_len: usize) -> String {
    if noun.len() <= max_len {
        noun.to_string()
    } else {
        format!("{}...", &noun[..max_len])
    }
}

/// Build structured agent context for a Deny decision.
fn build_deny_context(
    tool_name: &str,
    verb_str: &str,
    noun: &str,
    reason: Option<&str>,
    denial_count: usize,
) -> String {
    let truncated_noun = truncate_noun(noun, 80);

    let reason_code = match reason {
        Some(r) if r.contains("denied") || r.contains("deny") => "explicit-deny",
        _ => "default-deny",
    };

    let description = denial_explanation(verb_str);

    let suggested_action = suggest_allow_command(verb_str, &truncated_noun);

    if reason_code == "explicit-deny" {
        format!(
            "clash: denied tool={} input={}\n\
             reason: {}\n\
             \n\
             This action is explicitly denied by the user's policy.\n\
             \n\
             Agent instructions:\n\
             - Tell the user this action is blocked by their clash policy\n\
             - Suggest running \"clash policy list\" to review rules\n\
             - Do NOT retry the tool call\n\
             - Do NOT suggest workarounds",
            tool_name, truncated_noun, reason_code,
        )
    } else if denial_count >= 4 {
        format!(
            "clash: denied tool={} input={}\n\
             reason: {}\n\
             Suggested action: {}\n\
             Agent instructions:\n\
             - Suggest the command above",
            tool_name, truncated_noun, reason_code, suggested_action,
        )
    } else if denial_count <= 1 {
        format!(
            "clash: denied tool={} input={}\n\
             reason: {}\n\
             \n\
             {}\n\
             \n\
             Suggested action: {}\n\
             Agent instructions:\n\
             - Explain briefly that clash blocked this to protect the project\n\
             - Suggest the user run the command above\n\
             - Mention \"clash policy setup\" for broader configuration\n\
             - Do NOT retry the tool call\n\
             - Do NOT suggest workarounds or alternative approaches",
            tool_name, truncated_noun, reason_code, description, suggested_action,
        )
    } else {
        format!(
            "clash: denied tool={} input={}\n\
             reason: {}\n\
             \n\
             {}\n\
             \n\
             Suggested action: {}\n\
             Agent instructions:\n\
             - Suggest the user run the command above\n\
             - Do NOT retry the tool call\n\
             - Do NOT suggest workarounds or alternative approaches",
            tool_name, truncated_noun, reason_code, description, suggested_action,
        )
    }
}

/// Extract the noun (resource identifier) from tool input JSON.
pub fn extract_noun(tool_name: &str, tool_input: &serde_json::Value) -> String {
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
        if let Some(val) = tool_input.get(*field).and_then(|v| v.as_str()) {
            return val.to_string();
        }
    }
    tool_name.to_lowercase()
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
    fn settings_with_v2(source: &str) -> ClashSettings {
        let mut settings = ClashSettings::default();
        settings.set_v2_source(source);
        settings
    }

    // --- v2 policy engine tests ---

    #[test]
    fn test_policy_allow_git_status() -> Result<()> {
        let settings = settings_with_v2(
            r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *)))
"#,
        );
        let result = check_permission(&bash_input("git status"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Allow,
            Some("policy: allowed"),
        );
        Ok(())
    }

    #[test]
    fn test_policy_deny_git_push() -> Result<()> {
        let settings = settings_with_v2(
            r#"
(default deny "main")
(policy "main"
  (deny  (exec "git" "push" *))
  (allow (exec "git" *)))
"#,
        );
        let result = check_permission(&bash_input("git push origin main"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Deny,
            None, // v2 uses rule description as reason, not "policy: denied"
        );
        Ok(())
    }

    #[test]
    fn test_policy_default_deny() -> Result<()> {
        let settings = settings_with_v2(
            r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *)))
"#,
        );
        // ls doesn't match any rule
        let result = check_permission(&bash_input("ls"), &settings)?;
        assert_eq!(
            get_decision(&result),
            Some(claude_settings::PermissionRule::Deny),
        );
        Ok(())
    }

    #[test]
    fn test_policy_read_under_cwd() -> Result<()> {
        let settings = settings_with_v2(
            r#"
(default deny "main")
(policy "main"
  (allow (fs read (subpath "/home/user/project"))))
"#,
        );
        let input = ToolUseHookInput {
            tool_name: "Read".into(),
            tool_input: json!({"file_path": "/home/user/project/src/main.rs"}),
            cwd: "/home/user/project".into(),
            ..Default::default()
        };
        let result = check_permission(&input, &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Allow,
            Some("policy: allowed"),
        );
        Ok(())
    }

    #[test]
    fn test_policy_read_outside_cwd_denied() -> Result<()> {
        let settings = settings_with_v2(
            r#"
(default deny "main")
(policy "main"
  (allow (fs read (subpath "/home/user/project"))))
"#,
        );
        let input = ToolUseHookInput {
            tool_name: "Read".into(),
            tool_input: json!({"file_path": "/etc/passwd"}),
            cwd: "/home/user/project".into(),
            ..Default::default()
        };
        let result = check_permission(&input, &settings)?;
        assert_eq!(
            get_decision(&result),
            Some(claude_settings::PermissionRule::Deny),
        );
        Ok(())
    }

    #[test]
    fn test_no_compiled_policy_asks() -> Result<()> {
        let settings = ClashSettings::default();
        let result = check_permission(&bash_input("ls"), &settings)?;
        assert_eq!(
            get_decision(&result),
            Some(claude_settings::PermissionRule::Ask),
        );
        Ok(())
    }

    // --- Explanation tests ---

    #[test]
    fn test_explanation_contains_matched_rule() -> Result<()> {
        let settings = settings_with_v2(
            r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *)))
"#,
        );
        let result = check_permission(&bash_input("git status"), &settings)?;
        let ctx = get_additional_context(&result).expect("should have additional_context");
        assert!(
            ctx.contains("matched"),
            "explanation should contain 'matched' but got: {ctx}"
        );
        Ok(())
    }

    #[test]
    fn test_explanation_no_rules_matched() -> Result<()> {
        let settings = settings_with_v2(
            r#"
(default ask "main")
(policy "main"
  (allow (exec "git" *)))
"#,
        );
        let result = check_permission(&bash_input("ls"), &settings)?;
        let ctx = get_additional_context(&result).expect("should have additional_context");
        assert!(
            ctx.contains("No rules matched"),
            "explanation should say 'No rules matched' but got: {ctx}"
        );
        Ok(())
    }

    // --- Helper functions ---

    fn get_decision(output: &HookOutput) -> Option<claude_settings::PermissionRule> {
        match &output.hook_specific_output {
            Some(crate::hooks::HookSpecificOutput::PreToolUse(pre)) => {
                pre.permission_decision.clone()
            }
            _ => None,
        }
    }

    fn get_additional_context(output: &HookOutput) -> Option<String> {
        match &output.hook_specific_output {
            Some(crate::hooks::HookSpecificOutput::PreToolUse(pre)) => {
                pre.additional_context.clone()
            }
            _ => None,
        }
    }

    fn assert_decision(
        output: &HookOutput,
        expected_decision: claude_settings::PermissionRule,
        expected_reason: Option<&str>,
    ) {
        let decision = get_decision(output);
        assert_eq!(decision, Some(expected_decision), "unexpected decision");
        if let Some(expected) = expected_reason {
            let reason = match &output.hook_specific_output {
                Some(crate::hooks::HookSpecificOutput::PreToolUse(pre)) => {
                    pre.permission_decision_reason.as_deref()
                }
                _ => None,
            };
            assert_eq!(reason, Some(expected), "unexpected reason");
        }
    }

    // --- shell_escape tests ---

    #[test]
    fn test_shell_escape_simple_string() {
        assert_eq!(shell_escape("hello"), "'hello'");
    }

    #[test]
    fn test_shell_escape_string_with_spaces() {
        assert_eq!(shell_escape("hello world"), "'hello world'");
    }

    #[test]
    fn test_shell_escape_empty_string() {
        assert_eq!(shell_escape(""), "''");
    }

    #[test]
    fn test_shell_escape_embedded_single_quotes() {
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_shell_escape_multiple_single_quotes() {
        assert_eq!(shell_escape("a'b'c"), "'a'\\''b'\\''c'");
    }

    #[test]
    fn test_shell_escape_special_characters() {
        assert_eq!(shell_escape("$HOME"), "'$HOME'");
        assert_eq!(shell_escape("`whoami`"), "'`whoami`'");
        assert_eq!(shell_escape("a\\b"), "'a\\b'");
    }

    #[test]
    fn test_shell_escape_double_quotes() {
        assert_eq!(shell_escape("say \"hi\""), "'say \"hi\"'");
    }

    // --- wrap_bash_with_sandbox tests ---

    fn test_sandbox_policy() -> crate::policy::sandbox_types::SandboxPolicy {
        use crate::policy::sandbox_types::{Cap, NetworkPolicy};
        crate::policy::sandbox_types::SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![],
            network: NetworkPolicy::Deny,
        }
    }

    fn bash_input_for_sandbox(command: &str, cwd: &str) -> ToolUseHookInput {
        ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_input: json!({"command": command}),
            cwd: cwd.into(),
            ..Default::default()
        }
    }

    fn extract_wrapped_command(result: &serde_json::Value) -> &str {
        result
            .get("command")
            .and_then(|v| v.as_str())
            .expect("wrapped result should have a 'command' string field")
    }

    #[test]
    fn test_wrap_bash_basic_command() {
        let input = bash_input_for_sandbox("ls -la", "/home/user/project");
        let policy = test_sandbox_policy();
        let result = wrap_bash_with_sandbox(&input, &policy);
        assert!(result.is_some());
        let wrapped = result.unwrap();
        let cmd = extract_wrapped_command(&wrapped);
        assert!(cmd.contains("sandbox exec"));
        assert!(cmd.contains("--policy"));
        assert!(cmd.contains("--cwd"));
        assert!(cmd.contains("-- bash -c 'ls -la'"));
    }

    #[test]
    fn test_wrap_bash_returns_none_for_read_tool() {
        let input = ToolUseHookInput {
            tool_name: "Read".into(),
            tool_input: json!({"file_path": "/tmp/test.txt"}),
            ..Default::default()
        };
        let policy = test_sandbox_policy();
        let result = wrap_bash_with_sandbox(&input, &policy);
        assert!(result.is_none());
    }

    // --- suggest/deny tests ---

    #[test]
    fn test_suggest_allow_command_edit() {
        assert_eq!(
            suggest_allow_command("edit", "main.rs"),
            "clash policy allow edit"
        );
    }

    #[test]
    fn test_suggest_allow_command_bash() {
        assert_eq!(
            suggest_allow_command("bash", "ls -la"),
            "clash policy allow bash"
        );
    }

    #[test]
    fn test_suggest_allow_command_web() {
        assert_eq!(
            suggest_allow_command("webfetch", "https://example.com"),
            "clash policy allow web"
        );
    }

    #[test]
    fn test_truncate_noun_short() {
        assert_eq!(truncate_noun("hello", 60), "hello");
    }

    #[test]
    fn test_truncate_noun_long() {
        let s = "a".repeat(100);
        let result = truncate_noun(&s, 60);
        assert_eq!(result.len(), 63);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_build_deny_context_contains_tool_name() {
        let ctx = build_deny_context("Bash", "bash", "ls -la", None, 1);
        assert!(ctx.contains("Bash"));
        assert!(ctx.contains("clash: denied"));
        assert!(ctx.contains("Agent instructions"));
    }

    #[test]
    fn test_deny_decision_includes_agent_context() -> Result<()> {
        let settings = settings_with_v2(
            r#"
(default deny "main")
(policy "main"
  (deny (exec *)))
"#,
        );
        let result = check_permission(&bash_input("ls -la"), &settings)?;
        assert_eq!(
            get_decision(&result),
            Some(claude_settings::PermissionRule::Deny),
        );
        let ctx = get_additional_context(&result).expect("deny should have additional_context");
        assert!(ctx.contains("clash: denied"), "got: {ctx}");
        Ok(())
    }
}
