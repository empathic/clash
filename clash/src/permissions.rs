use crate::policy::sandbox_types::SandboxPolicy;
use crate::policy::{Effect, EvalContext, Verb};
use tracing::{Level, info, instrument, warn};

use crate::hooks::{HookOutput, ToolInput, ToolUseHookInput};
use crate::settings::ClashSettings;

/// Check if a tool invocation should be allowed, denied, or require user confirmation.
#[instrument(level = Level::TRACE, ret)]
pub fn check_permission(
    input: &ToolUseHookInput,
    settings: &ClashSettings,
) -> anyhow::Result<HookOutput> {
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
            let reason = match settings.policy_error() {
                Some(err) => format!("{}. All tool uses will require approval.", err),
                None => "policy engine: no compiled policy available".into(),
            };
            warn!("{}", reason);
            return Ok(HookOutput::ask(Some(reason), None));
        }
    };

    let (verb, verb_str_owned) = resolve_verb(&input.tool_name);
    let noun = extract_noun(&input.tool_name, &input.tool_input);
    let entity = "agent";
    let ctx = EvalContext {
        entity,
        verb: &verb,
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
    // Adapt verbosity based on how many denials have occurred this session.
    if decision.effect == Effect::Deny {
        let denial_count = count_session_denials(&input.session_id);
        let noun_summary = truncate_noun(&noun, 60);

        eprintln!("clash: blocked {} on {}", verb_str_owned, noun_summary);

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
            // Default-deny: suggest the quick fix
            if denial_count <= 1 {
                let explanation = denial_explanation(&verb_str_owned);
                eprintln!("  {}", explanation);
            }

            let suggested = suggest_allow_command(&verb_str_owned, &noun_summary);
            eprintln!("  To allow: {}", suggested);

            if denial_count <= 3 {
                eprintln!("  Or run \"clash policy setup\" for interactive configuration.");
            }
        }
    }

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
                &verb_str_owned,
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

/// Count the number of deny decisions in the current session's audit log.
///
/// Returns 0 if the log file doesn't exist or can't be read.
/// The count includes the current denial (which has already been logged
/// by `log_decision` before this function is called).
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
///
/// Returns a bare-verb shorthand when possible (e.g. `clash policy allow edit`),
/// or a full rule command for unknown verbs.
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
///
/// This produces directive content that tells the AI agent how to respond
/// to the user when a tool invocation is denied, including a suggested
/// command to unblock the action.
///
/// The output adapts based on how many denials have occurred this session:
/// - 1st denial: full instructions with a note that this is the first encounter
/// - 2nd-3rd denial: standard instructions
/// - 4th+ denial: abbreviated instructions (the agent has seen the full version)
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
        // User intentionally blocked this — don't suggest allowing it.
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
        // Abbreviated context for repeat denials.
        format!(
            "clash: denied tool={} input={}\n\
             reason: {}\n\
             Suggested action: {}\n\
             Agent instructions:\n\
             - Suggest the command above",
            tool_name, truncated_noun, reason_code, suggested_action,
        )
    } else if denial_count <= 1 {
        // First denial: include extra context for the agent.
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
        // 2nd-3rd denial: standard instructions.
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
///
/// Checks common field names in priority order to extract a meaningful
/// noun from any tool's input JSON. This handles both known tools
/// (Bash, Read, Write, Edit) and arbitrary tools (Glob, Grep, WebSearch, etc.).
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
    // Fallback: use the tool name as noun (better than serializing entire JSON)
    tool_name.to_lowercase()
}

/// Resolve the verb and verb string for a tool name.
///
/// Returns the canonical `Verb` (or `Execute` as fallback) and the string
/// representation used for policy matching.
pub fn resolve_verb(tool_name: &str) -> (Verb, String) {
    match Verb::from_tool_name(tool_name) {
        Some(v) => {
            let s = v.rule_name().to_string();
            (v, s)
        }
        None => (Verb::Execute, tool_name.to_lowercase()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::ToolUseHookInput;
    use crate::policy::parse::desugar_claude_permissions;
    use crate::policy::parse::parse_policy;
    use crate::policy::{ClaudePermissions, PolicyConfig, PolicyDocument};
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

    fn settings_with_policy(sexpr: &str) -> ClashSettings {
        let doc = parse_policy(sexpr).expect("valid s-expr policy");
        let mut settings = ClashSettings::default();
        settings.set_policy(doc);
        settings
    }

    /// Build ClashSettings from Claude Code permission strings, compiled into a PolicyDocument.
    fn settings_with_claude_perms(
        allow: Vec<&str>,
        deny: Vec<&str>,
        ask: Vec<&str>,
    ) -> ClashSettings {
        let claude_perms = ClaudePermissions {
            allow: allow.into_iter().map(String::from).collect(),
            deny: deny.into_iter().map(String::from).collect(),
            ask: ask.into_iter().map(String::from).collect(),
        };
        let statements = desugar_claude_permissions(&claude_perms);
        let doc = PolicyDocument {
            policy: PolicyConfig::default(),
            permissions: None,
            constraints: Default::default(),
            profiles: Default::default(),
            statements,
            default_config: None,
            profile_defs: Default::default(),
        };
        let mut settings = ClashSettings::default();
        settings.set_policy(doc);
        settings
    }

    // --- Legacy permissions compiled to policy ---

    #[test]
    fn test_allow_npm_exact() -> Result<()> {
        let settings = settings_with_claude_perms(vec!["Bash(npm run test)"], vec![], vec![]);
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
        let settings = settings_with_claude_perms(vec!["Bash(npm run test *)"], vec![], vec![]);
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
        let settings = settings_with_claude_perms(vec![], vec![], vec![]);
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
        let settings = settings_with_claude_perms(vec![], vec!["Bash(*)"], vec![]);
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
        let settings =
            settings_with_policy("(default ask main)\n(profile main\n  (allow bash \"git *\"))\n");
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
        let settings =
            settings_with_policy("(default ask main)\n(profile main\n  (deny bash \"rm *\"))\n");
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
        // No rules match the command, so the default (ask) is applied
        let settings = settings_with_policy(
            "(default ask main)\n(profile main\n  (allow bash \"only-this-command\"))\n",
        );
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
        let settings =
            settings_with_policy("(default ask main)\n(profile main\n  (allow read *.rs))\n");
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
            "(default ask main)\n(profile main\n  (allow read *)\n  (deny read .env))\n",
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
        let doc = parse_policy("(default ask main)\n(profile main\n  (allow bash \"echo *\"))\n")
            .unwrap();
        let mut settings = ClashSettings::default();
        settings.set_policy(doc);
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
        let settings = settings_with_claude_perms(vec!["Bash(npm run test)"], vec![], vec![]);
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
            "(default ask main)\n\
             (profile main\n\
               (allow bash *\n\
                 (pipe deny)))\n",
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
            "(default ask main)\n\
             (profile main\n\
               (allow bash \"git *\"\n\
                 (args (not \"--force\") (not \"--force-with-lease\"))))\n",
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
            "(default ask main)\n\
             (profile main\n\
               (allow read *\n\
                 (fs (read (subpath .)))))\n",
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
            "(default ask main)\n\
             (profile main\n\
               (allow bash \"git *\"\n\
                 (fs (full (subpath .)))\n\
                 (pipe deny)\n\
                 (redirect deny)\n\
                 (args (not \"--force\") (not \"--hard\")))\n\
               (allow bash \"cargo *\"\n\
                 (fs (full (subpath .)))\n\
                 (pipe deny)\n\
                 (redirect deny))\n\
               (allow read *\n\
                 (fs (read (subpath .))))\n\
               (deny bash \"rm *\"))\n",
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
        let settings =
            settings_with_policy("(default ask main)\n(profile main\n  (allow bash \"git *\"))\n");
        let result = check_permission(&bash_input("git status"), &settings)?;
        let ctx = get_additional_context(&result).expect("should have additional_context");
        assert!(
            ctx.contains("matched"),
            "explanation should contain 'matched' but got: {ctx}"
        );
        assert!(
            ctx.contains("allowed"),
            "explanation should mention allowed but got: {ctx}"
        );
        Ok(())
    }

    #[test]
    fn test_explanation_deny_overrides_allow_detail() -> Result<()> {
        let settings = settings_with_policy(
            "(default ask main)\n(profile main\n  (allow read *)\n  (deny read .env))\n",
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
            "(default ask main)\n\
             (profile main\n\
               (allow bash *\n\
                 (pipe deny)))\n",
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
        let settings = settings_with_policy(
            "(default ask main)\n(profile main\n  (allow bash \"only-this-command\"))\n",
        );
        let result = check_permission(&bash_input("ls"), &settings)?;
        let ctx = get_additional_context(&result).expect("should have additional_context");
        assert!(
            ctx.contains("No rules matched"),
            "explanation should say 'No rules matched' but got: {ctx}"
        );
        Ok(())
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
        // A single quote inside the string must be escaped as: end quote, backslash-quote, re-open quote
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn test_shell_escape_multiple_single_quotes() {
        assert_eq!(shell_escape("a'b'c"), "'a'\\''b'\\''c'");
    }

    #[test]
    fn test_shell_escape_special_characters() {
        // Dollar signs, backticks, backslashes should all be preserved literally inside single quotes
        assert_eq!(shell_escape("$HOME"), "'$HOME'");
        assert_eq!(shell_escape("`whoami`"), "'`whoami`'");
        assert_eq!(shell_escape("a\\b"), "'a\\b'");
    }

    #[test]
    fn test_shell_escape_double_quotes() {
        assert_eq!(shell_escape("say \"hi\""), "'say \"hi\"'");
    }

    // --- wrap_bash_with_sandbox tests ---

    /// Helper: create a minimal SandboxPolicy for testing.
    fn test_sandbox_policy() -> SandboxPolicy {
        use crate::policy::sandbox_types::{Cap, NetworkPolicy};
        SandboxPolicy {
            default: Cap::READ | Cap::EXECUTE,
            rules: vec![],
            network: NetworkPolicy::Deny,
        }
    }

    /// Helper: create a ToolUseHookInput for a Bash command with a specified cwd.
    fn bash_input_for_sandbox(command: &str, cwd: &str) -> ToolUseHookInput {
        ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_input: json!({"command": command}),
            cwd: cwd.into(),
            ..Default::default()
        }
    }

    /// Helper: extract the rewritten command string from wrap_bash_with_sandbox output.
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
        assert!(
            result.is_some(),
            "wrap_bash_with_sandbox should return Some for Bash input"
        );

        let wrapped = result.unwrap();
        let cmd = extract_wrapped_command(&wrapped);

        // The wrapped command should contain the sandbox exec invocation
        assert!(
            cmd.contains("sandbox exec"),
            "should contain 'sandbox exec'"
        );
        // Should contain --policy with the serialized policy
        assert!(cmd.contains("--policy"), "should contain '--policy'");
        // Should contain --cwd with the working directory
        assert!(cmd.contains("--cwd"), "should contain '--cwd'");
        // Should end with: -- bash -c '<original command>'
        assert!(
            cmd.contains("-- bash -c 'ls -la'"),
            "should wrap the original command with bash -c, got: {cmd}"
        );
        // The cwd should be shell-escaped
        assert!(
            cmd.contains("--cwd '/home/user/project'"),
            "cwd should be shell-escaped, got: {cmd}"
        );
    }

    #[test]
    fn test_wrap_bash_command_with_single_quotes() {
        let input = bash_input_for_sandbox("echo 'hello world'", "/tmp");
        let policy = test_sandbox_policy();

        let result = wrap_bash_with_sandbox(&input, &policy).unwrap();
        let cmd = extract_wrapped_command(&result);

        // Single quotes inside the command must be escaped properly.
        // The original command echo 'hello world' should become:
        //   bash -c 'echo '\''hello world'\'''
        assert!(
            cmd.contains("bash -c 'echo '\\''hello world'\\'''"),
            "single quotes in command must be escaped, got: {cmd}"
        );
    }

    #[test]
    fn test_wrap_bash_command_with_double_quotes() {
        let input = bash_input_for_sandbox("echo \"hello world\"", "/tmp");
        let policy = test_sandbox_policy();

        let result = wrap_bash_with_sandbox(&input, &policy).unwrap();
        let cmd = extract_wrapped_command(&result);

        // Double quotes are safe inside single quotes, should be passed through literally
        assert!(
            cmd.contains("bash -c 'echo \"hello world\"'"),
            "double quotes in command should be preserved, got: {cmd}"
        );
    }

    #[test]
    fn test_wrap_bash_command_with_dollar_sign() {
        let input = bash_input_for_sandbox("echo $HOME", "/tmp");
        let policy = test_sandbox_policy();

        let result = wrap_bash_with_sandbox(&input, &policy).unwrap();
        let cmd = extract_wrapped_command(&result);

        // Dollar signs inside single quotes are literal, not expanded
        assert!(
            cmd.contains("bash -c 'echo $HOME'"),
            "dollar sign should be preserved literally, got: {cmd}"
        );
    }

    #[test]
    fn test_wrap_bash_command_with_backticks() {
        let input = bash_input_for_sandbox("echo `whoami`", "/tmp");
        let policy = test_sandbox_policy();

        let result = wrap_bash_with_sandbox(&input, &policy).unwrap();
        let cmd = extract_wrapped_command(&result);

        assert!(
            cmd.contains("bash -c 'echo `whoami`'"),
            "backticks should be preserved literally, got: {cmd}"
        );
    }

    #[test]
    fn test_wrap_bash_command_with_backslashes() {
        let input = bash_input_for_sandbox("echo a\\nb", "/tmp");
        let policy = test_sandbox_policy();

        let result = wrap_bash_with_sandbox(&input, &policy).unwrap();
        let cmd = extract_wrapped_command(&result);

        assert!(
            cmd.contains("bash -c 'echo a\\nb'"),
            "backslashes should be preserved literally, got: {cmd}"
        );
    }

    #[test]
    fn test_wrap_bash_policy_json_is_escaped() {
        let input = bash_input_for_sandbox("ls", "/tmp");
        let policy = test_sandbox_policy();

        let result = wrap_bash_with_sandbox(&input, &policy).unwrap();
        let cmd = extract_wrapped_command(&result);

        // The policy JSON is serialized and shell-escaped. It should be wrapped
        // in single quotes after --policy.
        let policy_json = serde_json::to_string(&policy).unwrap();
        let escaped_policy = shell_escape(&policy_json);
        assert!(
            cmd.contains(&format!("--policy {escaped_policy}")),
            "policy JSON should be shell-escaped, got: {cmd}"
        );
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
        assert!(
            result.is_none(),
            "wrap_bash_with_sandbox should return None for Read tool"
        );
    }

    #[test]
    fn test_wrap_bash_returns_none_for_write_tool() {
        let input = ToolUseHookInput {
            tool_name: "Write".into(),
            tool_input: json!({"file_path": "/tmp/test.txt", "content": "data"}),
            ..Default::default()
        };
        let policy = test_sandbox_policy();

        let result = wrap_bash_with_sandbox(&input, &policy);
        assert!(
            result.is_none(),
            "wrap_bash_with_sandbox should return None for Write tool"
        );
    }

    #[test]
    fn test_wrap_bash_returns_none_for_edit_tool() {
        let input = ToolUseHookInput {
            tool_name: "Edit".into(),
            tool_input: json!({"file_path": "/tmp/test.txt", "old_string": "a", "new_string": "b"}),
            ..Default::default()
        };
        let policy = test_sandbox_policy();

        let result = wrap_bash_with_sandbox(&input, &policy);
        assert!(
            result.is_none(),
            "wrap_bash_with_sandbox should return None for Edit tool"
        );
    }

    #[test]
    fn test_wrap_bash_returns_none_for_unknown_tool() {
        let input = ToolUseHookInput {
            tool_name: "WebSearch".into(),
            tool_input: json!({"query": "test"}),
            ..Default::default()
        };
        let policy = test_sandbox_policy();

        let result = wrap_bash_with_sandbox(&input, &policy);
        assert!(
            result.is_none(),
            "wrap_bash_with_sandbox should return None for unknown tools"
        );
    }

    #[test]
    fn test_wrap_bash_preserves_original_structure() {
        // Verify the returned JSON preserves non-command fields from the original tool_input
        let input = ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_input: json!({"command": "ls", "timeout": 5000}),
            cwd: "/tmp".into(),
            ..Default::default()
        };
        let policy = test_sandbox_policy();

        let result = wrap_bash_with_sandbox(&input, &policy).unwrap();

        // The timeout field from the original input should still be present
        assert_eq!(
            result.get("timeout").and_then(|v| v.as_u64()),
            Some(5000),
            "non-command fields should be preserved in the output"
        );

        // The command field should be the rewritten sandbox command
        let cmd = extract_wrapped_command(&result);
        assert!(cmd.contains("sandbox exec"), "command should be rewritten");
    }

    // --- WebFetch URL constraint integration tests ---

    fn webfetch_input(url: &str) -> ToolUseHookInput {
        ToolUseHookInput {
            tool_name: "WebFetch".into(),
            tool_input: json!({"url": url, "prompt": "test"}),
            ..Default::default()
        }
    }

    #[test]
    fn test_webfetch_url_constraint_allows_matching_domain() -> Result<()> {
        let settings = settings_with_policy(
            "(default ask test)\n\
             (profile test\n\
               (allow webfetch *\n\
                 (url \"github.com\")))\n",
        );
        let result = check_permission(&webfetch_input("https://github.com/foo"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Allow,
            Some("policy: allowed"),
        );
        Ok(())
    }

    #[test]
    fn test_webfetch_url_constraint_falls_to_default_for_non_matching() -> Result<()> {
        let settings = settings_with_policy(
            "(default ask test)\n\
             (profile test\n\
               (allow webfetch *\n\
                 (url \"github.com\")))\n",
        );
        let result = check_permission(&webfetch_input("https://evil.com/malware"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Ask,
            Some("policy: ask"),
        );
        Ok(())
    }

    #[test]
    fn test_webfetch_url_forbid_denies_matching() -> Result<()> {
        let settings = settings_with_policy(
            "(default allow test)\n\
             (profile test\n\
               (deny webfetch *\n\
                 (url \"evil.com\")))\n",
        );
        // Forbidden domain → denied
        let result = check_permission(&webfetch_input("https://evil.com/malware"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Deny,
            Some("policy: denied"),
        );

        // Non-forbidden domain → falls through to default (allow)
        let result = check_permission(&webfetch_input("https://github.com/foo"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Allow,
            Some("policy: allowed"),
        );
        Ok(())
    }

    // --- suggest_allow_command tests ---

    #[test]
    fn test_suggest_allow_command_edit() {
        assert_eq!(
            suggest_allow_command("edit", "main.rs"),
            "clash policy allow edit"
        );
    }

    #[test]
    fn test_suggest_allow_command_write() {
        assert_eq!(
            suggest_allow_command("write", "main.rs"),
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
    fn test_suggest_allow_command_webfetch() {
        assert_eq!(
            suggest_allow_command("webfetch", "https://example.com"),
            "clash policy allow web"
        );
    }

    #[test]
    fn test_suggest_allow_command_websearch() {
        assert_eq!(
            suggest_allow_command("websearch", "test query"),
            "clash policy allow web"
        );
    }

    #[test]
    fn test_suggest_allow_command_read() {
        assert_eq!(
            suggest_allow_command("read", "/etc/passwd"),
            "clash policy allow read"
        );
    }

    #[test]
    fn test_suggest_allow_command_unknown_verb() {
        let cmd = suggest_allow_command("unknownverb", "some-noun");
        assert!(
            cmd.contains("clash policy allow"),
            "should suggest clash policy allow, got: {cmd}"
        );
        assert!(
            cmd.contains("unknownverb"),
            "should contain the verb, got: {cmd}"
        );
    }

    // --- denial_explanation tests ---

    #[test]
    fn test_denial_explanation_edit() {
        let msg = denial_explanation("edit");
        assert!(!msg.is_empty());
        assert!(
            msg.to_lowercase().contains("edit"),
            "edit explanation should contain 'edit', got: {msg}"
        );
    }

    #[test]
    fn test_denial_explanation_write() {
        let msg = denial_explanation("write");
        assert!(!msg.is_empty());
        assert!(
            msg.to_lowercase().contains("edit"),
            "write explanation should contain 'edit', got: {msg}"
        );
    }

    #[test]
    fn test_denial_explanation_bash() {
        let msg = denial_explanation("bash");
        assert!(!msg.is_empty());
        assert!(
            msg.to_lowercase().contains("command"),
            "bash explanation should contain 'command', got: {msg}"
        );
    }

    #[test]
    fn test_denial_explanation_webfetch() {
        let msg = denial_explanation("webfetch");
        assert!(!msg.is_empty());
        assert!(
            msg.to_lowercase().contains("web"),
            "webfetch explanation should contain 'web', got: {msg}"
        );
    }

    #[test]
    fn test_denial_explanation_websearch() {
        let msg = denial_explanation("websearch");
        assert!(!msg.is_empty());
        assert!(
            msg.to_lowercase().contains("web"),
            "websearch explanation should contain 'web', got: {msg}"
        );
    }

    #[test]
    fn test_denial_explanation_read() {
        let msg = denial_explanation("read");
        assert!(!msg.is_empty());
        let lower = msg.to_lowercase();
        assert!(
            lower.contains("outside") || lower.contains("read"),
            "read explanation should contain 'outside' or 'read', got: {msg}"
        );
    }

    #[test]
    fn test_denial_explanation_unknown() {
        let msg = denial_explanation("unknown");
        assert!(
            !msg.is_empty(),
            "unknown verb should return non-empty explanation"
        );
    }

    // --- truncate_noun tests ---

    #[test]
    fn test_truncate_noun_short_string() {
        assert_eq!(truncate_noun("hello", 60), "hello");
    }

    #[test]
    fn test_truncate_noun_exact_length() {
        let s = "a".repeat(60);
        assert_eq!(truncate_noun(&s, 60), s);
    }

    #[test]
    fn test_truncate_noun_long_string() {
        let s = "a".repeat(100);
        let result = truncate_noun(&s, 60);
        assert_eq!(result.len(), 63); // 60 + "..."
        assert!(result.ends_with("..."));
        assert!(result.starts_with(&"a".repeat(60)));
    }

    #[test]
    fn test_truncate_noun_empty_string() {
        assert_eq!(truncate_noun("", 60), "");
    }

    // --- build_deny_context tests ---

    #[test]
    fn test_build_deny_context_contains_tool_name() {
        let ctx = build_deny_context("Bash", "bash", "ls -la", None, 1);
        assert!(
            ctx.contains("Bash"),
            "deny context should contain tool name, got: {ctx}"
        );
    }

    #[test]
    fn test_build_deny_context_contains_verb_info() {
        let ctx = build_deny_context("Bash", "bash", "ls -la", None, 1);
        assert!(
            ctx.contains("command"),
            "deny context should contain verb info (explanation), got: {ctx}"
        );
    }

    #[test]
    fn test_build_deny_context_has_clash_denied_prefix() {
        let ctx = build_deny_context("Bash", "bash", "ls -la", None, 1);
        assert!(
            ctx.contains("clash: denied"),
            "deny context should contain 'clash: denied' prefix, got: {ctx}"
        );
    }

    #[test]
    fn test_build_deny_context_contains_agent_instructions() {
        let ctx = build_deny_context("Bash", "bash", "ls -la", None, 1);
        assert!(
            ctx.contains("Agent instructions"),
            "deny context should contain 'Agent instructions', got: {ctx}"
        );
    }

    #[test]
    fn test_build_deny_context_bash_suggests_policy_allow() {
        let ctx = build_deny_context("Bash", "bash", "ls -la", None, 1);
        assert!(
            ctx.contains("clash policy allow bash"),
            "deny context for bash should suggest 'clash policy allow bash', got: {ctx}"
        );
    }

    #[test]
    fn test_build_deny_context_edit_suggests_policy_allow() {
        let ctx = build_deny_context("Edit", "edit", "main.rs", None, 1);
        assert!(
            ctx.contains("clash policy allow edit"),
            "deny context for edit should suggest 'clash policy allow edit', got: {ctx}"
        );
    }

    #[test]
    fn test_build_deny_context_web_suggests_policy_allow() {
        let ctx = build_deny_context("WebFetch", "webfetch", "https://example.com", None, 1);
        assert!(
            ctx.contains("clash policy allow web"),
            "deny context for webfetch should suggest 'clash policy allow web', got: {ctx}"
        );
    }

    #[test]
    fn test_build_deny_context_unknown_verb_suggests_policy_allow() {
        let ctx = build_deny_context("CustomTool", "customtool", "some-noun", None, 1);
        assert!(
            ctx.contains("clash policy allow"),
            "deny context for unknown verb should suggest 'clash policy allow', got: {ctx}"
        );
    }

    #[test]
    fn test_build_deny_context_explicit_deny_reason_code() {
        let ctx = build_deny_context("Bash", "bash", "rm -rf /", Some("policy: denied"), 1);
        assert!(
            ctx.contains("explicit-deny"),
            "deny context with 'denied' reason should use 'explicit-deny', got: {ctx}"
        );
    }

    #[test]
    fn test_build_deny_context_default_deny_reason_code() {
        let ctx = build_deny_context("Bash", "bash", "ls", None, 1);
        assert!(
            ctx.contains("default-deny"),
            "deny context without matching reason should use 'default-deny', got: {ctx}"
        );
    }

    #[test]
    fn test_build_deny_context_deny_in_reason() {
        let ctx = build_deny_context("Bash", "bash", "ls", Some("explicit deny rule matched"), 1);
        assert!(
            ctx.contains("explicit-deny"),
            "deny context with 'deny' in reason should use 'explicit-deny', got: {ctx}"
        );
    }

    // --- Integration test: deny decision includes agent context ---

    #[test]
    fn test_deny_decision_includes_agent_context() -> Result<()> {
        let settings =
            settings_with_policy("(default ask main)\n(profile main\n  (deny bash *))\n");
        let result = check_permission(&bash_input("ls -la"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Deny,
            Some("policy: denied"),
        );
        let ctx = get_additional_context(&result).expect("deny should have additional_context");
        assert!(
            ctx.contains("clash: denied"),
            "deny additional_context should contain structured deny context, got: {ctx}"
        );
        assert!(
            ctx.contains("Agent instructions"),
            "deny additional_context should contain agent instructions, got: {ctx}"
        );
        assert!(
            ctx.contains("clash policy allow bash"),
            "deny additional_context for bash should suggest 'clash policy allow bash', got: {ctx}"
        );
        Ok(())
    }

    #[test]
    fn test_deny_decision_edit_includes_allow_suggestion() -> Result<()> {
        let settings =
            settings_with_policy("(default ask main)\n(profile main\n  (deny edit *))\n");
        let input = ToolUseHookInput {
            tool_name: "Edit".into(),
            tool_input: json!({"file_path": "main.rs", "old_string": "a", "new_string": "b"}),
            ..Default::default()
        };
        let result = check_permission(&input, &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Deny,
            Some("policy: denied"),
        );
        let ctx = get_additional_context(&result).expect("deny should have additional_context");
        assert!(
            ctx.contains("clash policy allow edit"),
            "deny additional_context for edit should suggest 'clash policy allow edit', got: {ctx}"
        );
        Ok(())
    }

    #[test]
    fn test_default_deny_includes_agent_context() -> Result<()> {
        // When no rules match and default is deny, the additional_context
        // should still contain structured deny context.
        let settings = settings_with_policy("(default deny main)\n(profile main)\n");
        let result = check_permission(&bash_input("echo hello"), &settings)?;
        assert_decision(
            &result,
            claude_settings::PermissionRule::Deny,
            Some("policy: denied"),
        );
        let ctx = get_additional_context(&result).expect("deny should have additional_context");
        assert!(
            ctx.contains("clash: denied"),
            "default deny additional_context should contain 'clash: denied', got: {ctx}"
        );
        Ok(())
    }
}
