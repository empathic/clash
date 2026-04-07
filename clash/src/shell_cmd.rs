//! `clash shell` — bash-compatible shell with per-command sandbox enforcement.
//!
//! Uses brush (a bash-compatible shell implementation in Rust) with an external
//! command hook that evaluates the clash policy for every external command,
//! exactly as if Claude had issued it via the Bash tool. If the policy includes
//! a sandbox, the command is wrapped through `clash sandbox exec --policy <json>`.
//!
//! Three modes:
//! - `clash shell` — interactive REPL (brush-interactive with basic backend)
//! - `clash shell -c "cmd"` — execute a command string
//! - `clash shell script.sh` — execute a script file

use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::info;

use crate::policy::CompiledPolicy;
use crate::policy::Effect;
use crate::policy::sandbox_types::SandboxPolicy;
use crate::settings::ClashSettings;

/// Last policy decision made by the shell hook — read by the prompt renderer.
#[derive(Debug, Clone)]
pub struct LastDecision {
    /// 7-char audit log hash identifying this evaluation.
    pub hash: String,
    /// The policy effect (allow/deny/ask).
    pub effect: Effect,
    /// The full command string (e.g. "git push origin main").
    pub command: String,
    /// Whether the command was wrapped in sandbox-exec.
    pub sandboxed: bool,
}

/// Thread-safe shared state for the prompt to read the last decision.
pub type SharedDecision = Arc<std::sync::Mutex<Option<LastDecision>>>;

/// Thread-safe shared policy that can be reloaded between commands.
type SharedPolicy = Arc<std::sync::RwLock<Arc<CompiledPolicy>>>;

/// Build the external command hook that evaluates the policy for each command
/// and wraps it with the appropriate sandbox (same as Claude's Bash tool).
/// Shell builtins that should never be wrapped — they must run in-process.
const SHELL_BUILTINS: &[&str] = &[
    ".",
    ":",
    "[",
    "alias",
    "bg",
    "bind",
    "break",
    "builtin",
    "caller",
    "cd",
    "command",
    "compgen",
    "complete",
    "compopt",
    "continue",
    "declare",
    "dirs",
    "disown",
    "echo",
    "enable",
    "eval",
    "exec",
    "exit",
    "export",
    "false",
    "fc",
    "fg",
    "getopts",
    "hash",
    "help",
    "history",
    "jobs",
    "kill",
    "let",
    "local",
    "logout",
    "mapfile",
    "popd",
    "printf",
    "pushd",
    "pwd",
    "read",
    "readarray",
    "readonly",
    "return",
    "set",
    "shift",
    "shopt",
    "source",
    "suspend",
    "test",
    "times",
    "trap",
    "true",
    "type",
    "typeset",
    "ulimit",
    "umask",
    "unalias",
    "unset",
    "wait",
];

fn make_sandbox_hook(
    shared_policy: SharedPolicy,
    default_sandbox: Option<SandboxPolicy>,
    debug: bool,
    audit_config: crate::audit::AuditConfig,
    session_id: String,
    last_decision: SharedDecision,
) -> clash_brush_core::ExternalCommandHook {
    Arc::new(move |executable_path: &str, args: &[String]| {
        // Don't wrap shell builtins — they must run in the shell process.
        let basename = executable_path
            .rsplit('/')
            .next()
            .unwrap_or(executable_path);
        if SHELL_BUILTINS.contains(&basename) {
            return clash_brush_core::ExternalCommandAction::Passthrough;
        }

        // Reconstruct the command string as it would appear in a Bash tool call.
        // Use the basename — brush resolves to full paths (e.g. /bin/cat) but
        // policies match against bare names (e.g. exe("cat")).
        let mut cmd_parts = vec![basename.to_string()];
        cmd_parts.extend(args.iter().cloned());
        let command_str = cmd_parts.join(" ");

        // Build a tool_input that matches what Claude's Bash tool produces.
        let tool_input = serde_json::json!({
            "command": command_str,
        });

        // Read the current policy (reloaded each REPL iteration).
        let policy = shared_policy.read().unwrap_or_else(|e| e.into_inner());

        // Evaluate the policy exactly as check_permission would.
        let decision = policy.evaluate("Bash", &tool_input);

        // Write audit log entry so the hash is meaningful for `clash policy allow <hash>`.
        let audit_hash = crate::audit::log_decision(
            &audit_config,
            &session_id,
            "Bash",
            &tool_input,
            decision.effect,
            decision.reason.as_deref(),
            &decision.trace,
            None,
        );

        // Update shared state for the prompt (sandboxed field updated below if applicable).
        if let Ok(mut guard) = last_decision.lock() {
            *guard = Some(LastDecision {
                hash: audit_hash.clone(),
                effect: decision.effect,
                command: command_str.clone(),
                sandboxed: false,
            });
        }

        // Block denied commands with actionable hints.
        if decision.effect == Effect::Deny {
            let noun = if command_str.len() > 60 {
                // Truncate at a char boundary to avoid panicking on multi-byte UTF-8.
                let truncate_at = command_str
                    .char_indices()
                    .map(|(i, _)| i)
                    .take_while(|&i| i <= 60)
                    .last()
                    .unwrap_or(0);
                format!("{}...", &command_str[..truncate_at])
            } else {
                command_str.clone()
            };
            eprintln!("{} blocked shell on {}", "\x1b[1;31mclash:\x1b[0m", noun,);
            eprintln!(
                "  clash policy allow {}          # allow this exact command",
                audit_hash,
            );
            // Show --broad hint only when there are trailing args to glob.
            let parts: Vec<&str> = command_str.split_whitespace().collect();
            if parts.len() > 2 {
                eprintln!(
                    "  clash policy allow {} --broad  # allow all {}",
                    audit_hash,
                    parts[..2].join(" "),
                );
            }
            return clash_brush_core::ExternalCommandAction::Block;
        }

        // Use the policy's sandbox if present, otherwise fall back to the
        // user-specified default sandbox for the shell session.
        let effective_sandbox;
        let sandbox = match decision.sandbox {
            Some(ref sbx) => sbx,
            None => match default_sandbox {
                Some(ref fallback) => {
                    effective_sandbox = fallback.clone();
                    &effective_sandbox
                }
                None => {
                    if debug {
                        eprintln!("[clash-shell] {}: no sandbox", command_str);
                    }
                    return clash_brush_core::ExternalCommandAction::Passthrough;
                }
            },
        };

        // Resolve env vars in sandbox paths before serializing.
        // $HOME and $TMPDIR are process-global; $PWD is resolved by
        // brush's process cwd (which it sets correctly per command).
        let mut resolved = sandbox.clone();
        let resolver = crate::policy::path::PathResolver::from_env();
        for rule in &mut resolved.rules {
            rule.path = rule
                .path
                .replace("$HOME", resolver.home())
                .replace("$TMPDIR", resolver.tmpdir());
        }

        if debug {
            eprintln!(
                "[clash-shell] {}: effect={:?}",
                command_str, decision.effect
            );
            if let Ok(json) = serde_json::to_string_pretty(&resolved) {
                eprintln!("[clash-shell] sandbox: {}", json);
            }
        }

        // Compile the sandbox policy to a platform-specific profile and
        // invoke sandbox-exec directly. This avoids nesting sandbox-exec
        // (via `clash sandbox exec`) inside an already-sandboxed process,
        // which macOS seatbelt does not support.
        let cwd = std::env::current_dir().unwrap_or_default();
        let profile = match crate::sandbox::compile_sandbox_profile(&resolved, &cwd) {
            Ok(p) => p,
            Err(e) => {
                if debug {
                    eprintln!("[clash-shell] failed to compile sandbox profile: {e}");
                }
                return clash_brush_core::ExternalCommandAction::Passthrough;
            }
        };

        let mut new_args = vec![
            "-p".to_string(),
            profile,
            "--".to_string(),
            executable_path.to_string(),
        ];
        new_args.extend(args.iter().cloned());

        // Mark that this command is sandboxed so the REPL can detect sandbox failures.
        if let Ok(mut guard) = last_decision.lock() {
            if let Some(ref mut d) = *guard {
                d.sandboxed = true;
            }
        }

        clash_brush_core::ExternalCommandAction::Replace("sandbox-exec".to_string(), new_args)
    })
}

/// Run a bash-compatible shell with per-command sandbox enforcement.
pub fn run_shell(
    command: Option<String>,
    script_args: Vec<String>,
    cwd: String,
    sandbox_name: Option<String>,
    debug: bool,
) -> Result<()> {
    let cwd = crate::sandbox_cmd::resolve_cwd(&cwd)?;
    // Load the policy so we can evaluate it per-command.
    let settings = ClashSettings::load_or_create().context("failed to load clash settings")?;
    let policy = settings
        .policy_tree()
        .context("no compiled policy available — run `clash init` first")?
        .clone();

    // Resolve the default sandbox: CLI --sandbox flag overrides policy's default_sandbox.
    let effective_name = sandbox_name
        .as_deref()
        .or(policy.default_sandbox.as_deref());

    let default_sandbox = match effective_name {
        Some(name) => {
            let sbx = policy.sandboxes.get(name).cloned().ok_or_else(|| {
                anyhow::anyhow!(
                    "no sandbox named '{}' in policy (available: {:?})",
                    name,
                    policy.sandboxes.keys().collect::<Vec<_>>()
                )
            })?;
            Some(sbx)
        }
        None => None,
    };

    // Create a shell session for audit logging.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let session_id = format!(
        "shell-{:x}-{:03x}",
        now.as_secs() & 0xFFFF_FFFF,
        now.subsec_millis()
    );
    let _ = crate::audit::init_session(&session_id, &cwd, Some("clash-shell"), None);

    let last_decision: SharedDecision = Arc::new(std::sync::Mutex::new(None));
    let shared_policy: SharedPolicy = Arc::new(std::sync::RwLock::new(Arc::new(policy)));

    let hook = make_sandbox_hook(
        shared_policy.clone(),
        default_sandbox,
        debug,
        settings.audit.clone(),
        session_id,
        last_decision.clone(),
    );

    // Build a tokio runtime for brush's async API.
    let rt = tokio::runtime::Runtime::new().context("failed to create tokio runtime")?;

    rt.block_on(async {
        if let Some(ref cmd) = command {
            run_command_string(cmd, &cwd, hook).await
        } else if !script_args.is_empty() {
            run_script(&script_args, &cwd, hook).await
        } else {
            run_interactive(&cwd, hook, last_decision, shared_policy).await
        }
    })
}

/// Register the standard set of bash builtins (cd, export, source, etc.)
/// into a shell instance. brush-core doesn't include builtins by default;
/// they live in the separate brush-builtins crate.
fn register_builtins(shell: &mut clash_brush_core::Shell) {
    for (name, registration) in
        clash_brush_builtins::default_builtins(clash_brush_builtins::BuiltinSet::BashMode)
    {
        shell.register_builtin(&name, registration);
    }
}

/// Execute a command string (`clash shell -c "..."`).
async fn run_command_string(
    command: &str,
    cwd: &str,
    hook: clash_brush_core::ExternalCommandHook,
) -> Result<()> {
    let mut shell = clash_brush_core::Shell::builder()
        .command_string_mode(true)
        .working_dir(std::path::PathBuf::from(cwd))
        .external_command_hook(hook)
        .profile(clash_brush_core::ProfileLoadBehavior::Skip)
        .rc(clash_brush_core::RcLoadBehavior::Skip)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("failed to create shell: {e}"))?;

    register_builtins(&mut shell);

    let params = shell.default_exec_params();
    let source_info = clash_brush_core::SourceInfo::from("clash-shell");

    let result = shell
        .run_string(command, &source_info, &params)
        .await
        .map_err(|e| anyhow::anyhow!("execution error: {e}"))?;

    if !result.is_success() {
        std::process::exit(1);
    }
    Ok(())
}

/// Execute a script file (`clash shell script.sh arg1 arg2`).
async fn run_script(
    script_args: &[String],
    cwd: &str,
    hook: clash_brush_core::ExternalCommandHook,
) -> Result<()> {
    let script_path = &script_args[0];
    info!(script = %script_path, "executing script with sandbox hook");

    let args: Vec<String> = if script_args.len() > 1 {
        script_args[1..].to_vec()
    } else {
        vec![]
    };

    let mut shell = clash_brush_core::Shell::builder()
        .working_dir(std::path::PathBuf::from(cwd))
        .external_command_hook(hook)
        .profile(clash_brush_core::ProfileLoadBehavior::Skip)
        .rc(clash_brush_core::RcLoadBehavior::Skip)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("failed to create shell: {e}"))?;

    register_builtins(&mut shell);

    let result = shell
        .run_script(script_path, args.into_iter())
        .await
        .map_err(|e| anyhow::anyhow!("script execution error: {e}"))?;

    if !result.is_success() {
        std::process::exit(1);
    }
    Ok(())
}

/// Format the clash shell prompt based on the last policy decision.
fn format_prompt(last_decision: &SharedDecision) -> String {
    let guard = last_decision.lock().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref() {
        None => "clash $ ".to_string(),
        Some(d) => {
            let (symbol, color) = match d.effect {
                Effect::Allow => ("✓", "\x1b[32m"), // green
                Effect::Deny => ("✗", "\x1b[31m"),  // red
                Effect::Ask => ("?", "\x1b[33m"),   // yellow
            };
            let reset = "\x1b[0m";
            let dim = "\x1b[2m";
            // \x01 and \x02 bracket non-printing chars for readline;
            // brush's prompt expansion strips them (prompts.rs:69).
            format!(
                "clash[\x01{dim}\x02{}\x01{reset}\x02:\x01{color}\x02{}\x01{reset}\x02] $ ",
                d.hash, symbol
            )
        }
    }
}

/// Run an interactive shell REPL (`clash shell`).
async fn run_interactive(
    cwd: &str,
    hook: clash_brush_core::ExternalCommandHook,
    last_decision: SharedDecision,
    shared_policy: SharedPolicy,
) -> Result<()> {
    info!("starting interactive shell with sandbox hook");

    let mut shell = clash_brush_core::Shell::builder()
        .interactive(true)
        .working_dir(std::path::PathBuf::from(cwd))
        .external_command_hook(hook)
        .shell_name("clash-shell".to_string())
        .profile(clash_brush_core::ProfileLoadBehavior::Skip)
        .rc(clash_brush_core::RcLoadBehavior::Skip)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("failed to create shell: {e}"))?;

    register_builtins(&mut shell);

    // Set initial prompt (no decision yet).
    set_ps1(&mut shell, "clash $ ");

    let shell_ref = std::sync::Arc::new(tokio::sync::Mutex::new(shell));
    let mut input = clash_brush_interactive::BasicInputBackend;
    let options = clash_brush_interactive::InteractiveOptions::default();

    let mut interactive =
        clash_brush_interactive::InteractiveShell::new(&shell_ref, &mut input, &options)
            .map_err(|e| anyhow::anyhow!("failed to create interactive shell: {e}"))?;

    // Startup banner.
    eprintln!(
        "{}",
        "\x1b[2mRun `clash policy allow|deny <id>` to change policy for any command.\x1b[0m"
    );

    interactive
        .start()
        .await
        .map_err(|e| anyhow::anyhow!("failed to start interactive session: {e}"))?;

    loop {
        // Reload policy to pick up changes from other terminals.
        if let Ok(fresh_settings) = ClashSettings::load_or_create() {
            if let Some(fresh_policy) = fresh_settings.policy_tree() {
                if let Ok(mut guard) = shared_policy.write() {
                    *guard = Arc::new(fresh_policy.clone());
                }
            }
        }

        // Update prompt based on last decision.
        {
            let prompt_str = format_prompt(&last_decision);
            let mut sh = shell_ref.lock().await;
            set_ps1(&mut sh, &prompt_str);
        }

        match interactive.run_interactively_once().await {
            Ok(clash_brush_interactive::InteractiveExecutionResult::Eof) => break,
            Ok(clash_brush_interactive::InteractiveExecutionResult::Executed(result)) => {
                if matches!(
                    result.next_control_flow,
                    clash_brush_core::ExecutionControlFlow::ExitShell
                ) {
                    break;
                }
                // If a sandboxed command failed, flip the indicator to Deny —
                // the policy allowed it but the sandbox blocked execution.
                if !result.is_success() {
                    if let Ok(mut guard) = last_decision.lock() {
                        if let Some(ref mut d) = *guard {
                            if d.sandboxed {
                                d.effect = Effect::Deny;
                            }
                        }
                    }
                }
            }
            Ok(clash_brush_interactive::InteractiveExecutionResult::Failed(_)) => {}
            Err(e) => return Err(anyhow::anyhow!("interactive shell error: {e}")),
        }
    }

    interactive
        .finish()
        .await
        .map_err(|e| anyhow::anyhow!("failed to finish interactive session: {e}"))?;

    Ok(())
}

/// Set the PS1 environment variable on a shell instance.
fn set_ps1(shell: &mut clash_brush_core::Shell, value: &str) {
    let _ = shell.env_mut().update_or_add(
        "PS1",
        clash_brush_core::variables::ShellValueLiteral::Scalar(value.to_string()),
        |_| Ok(()),
        clash_brush_core::env::EnvironmentLookup::Anywhere,
        clash_brush_core::env::EnvironmentScope::Global,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::CompiledPolicy;

    /// Compile a Starlark policy string into a CompiledPolicy.
    fn compile_star(source: &str) -> CompiledPolicy {
        let output =
            clash_starlark::evaluate(source, "test.star", std::path::Path::new(".")).unwrap();
        let mut settings = ClashSettings::default();
        settings.set_policy_source(&output.json);
        settings.policy_tree().unwrap().clone()
    }

    /// Build a test policy that allows Bash with a sandbox.
    fn test_policy() -> Arc<CompiledPolicy> {
        use clash_starlark::codegen::ast::{Expr, Stmt};
        use clash_starlark::codegen::builder::*;

        let sb = sandbox(
            "test",
            vec![
                ("default", deny()),
                (
                    "fs",
                    Expr::list(vec![
                        cwd(vec![]).allow_kwargs(clash_starlark::kwargs!(read = true)),
                    ]),
                ),
            ],
        );
        let source = clash_starlark::codegen::serialize(&[
            load_std(&["policy", "settings", "sandbox", "cwd", "allow", "deny"]),
            Stmt::Expr(settings(deny(), None)),
            Stmt::Expr(policy(
                "test",
                deny(),
                vec![clash_starlark::match_tree! {
                    "Bash" => allow_with_sandbox(sb),
                }],
                None,
            )),
        ]);
        Arc::new(compile_star(&source))
    }

    fn test_hook() -> clash_brush_core::ExternalCommandHook {
        let last_decision: SharedDecision = Arc::new(std::sync::Mutex::new(None));
        let shared_policy: SharedPolicy = Arc::new(std::sync::RwLock::new(test_policy()));
        make_sandbox_hook(
            shared_policy,
            None,
            false,
            crate::audit::AuditConfig::default(),
            "test-session".to_string(),
            last_decision,
        )
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn hook_wraps_with_sandbox_exec_directly() {
        let hook = test_hook();
        // Brush resolves to full paths; hook should still match policy.
        let result = hook("/usr/bin/git", &["push".to_string()]);
        let (exe, args) = match result {
            clash_brush_core::ExternalCommandAction::Replace(exe, args) => (exe, args),
            other => panic!("expected Replace, got {other:?}"),
        };
        // Should invoke sandbox-exec directly, not clash sandbox exec.
        assert_eq!(exe, "sandbox-exec");
        assert_eq!(args[0], "-p");
        // args[1] is the compiled SBPL profile string
        assert!(
            args[1].contains("(version 1)"),
            "should be a compiled seatbelt profile"
        );
        assert_eq!(args[2], "--");
        assert_eq!(args[3], "/usr/bin/git");
        assert_eq!(args[4], "push");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn hook_preserves_args_order() {
        let hook = test_hook();
        let result = hook(
            "/bin/cat",
            &["file1.txt".to_string(), "file2.txt".to_string()],
        );
        let (exe, args) = match result {
            clash_brush_core::ExternalCommandAction::Replace(exe, args) => (exe, args),
            other => panic!("expected Replace, got {other:?}"),
        };
        assert_eq!(exe, "sandbox-exec");
        let dash_pos = args.iter().position(|a| a == "--").unwrap();
        assert_eq!(args[dash_pos + 1], "/bin/cat");
        assert_eq!(args[dash_pos + 2], "file1.txt");
        assert_eq!(args[dash_pos + 3], "file2.txt");
    }

    /// On Linux, compile_sandbox_profile returns Err (Landlock is in-process),
    /// so the hook falls through and returns None — no sandbox-exec wrapping.
    #[test]
    #[cfg(target_os = "linux")]
    fn hook_returns_none_on_linux() {
        let hook = test_hook();
        let result = hook("/usr/bin/git", &["push".to_string()]);
        assert!(
            matches!(result, clash_brush_core::ExternalCommandAction::Passthrough),
            "Linux uses Landlock (in-process), not sandbox-exec"
        );
    }

    #[test]
    fn hook_returns_none_without_sandbox() {
        use clash_starlark::codegen::ast::Stmt;
        use clash_starlark::codegen::builder::*;

        let source = clash_starlark::codegen::serialize(&[
            load_std(&["allow", "policy", "settings"]),
            Stmt::Expr(settings(allow(), None)),
            Stmt::Expr(policy("test", allow(), vec![], None)),
        ]);
        let policy = Arc::new(compile_star(&source));
        let last_decision: SharedDecision = Arc::new(std::sync::Mutex::new(None));
        let shared_policy: SharedPolicy = Arc::new(std::sync::RwLock::new(policy));
        let hook = make_sandbox_hook(
            shared_policy,
            None,
            false,
            crate::audit::AuditConfig::default(),
            "test-no-sandbox".to_string(),
            last_decision,
        );
        // No sandbox → command runs unchanged.
        let result = hook("/usr/bin/git", &["push".to_string()]);
        assert!(matches!(
            result,
            clash_brush_core::ExternalCommandAction::Passthrough
        ));
    }

    #[test]
    fn hook_blocks_denied_commands() {
        use clash_starlark::codegen::ast::Stmt;
        use clash_starlark::codegen::builder::*;

        // Policy that denies everything.
        let source = clash_starlark::codegen::serialize(&[
            load_std(&["deny", "policy", "settings"]),
            Stmt::Expr(settings(deny(), None)),
            Stmt::Expr(policy("test", deny(), vec![], None)),
        ]);
        let policy = Arc::new(compile_star(&source));
        let last_decision: SharedDecision = Arc::new(std::sync::Mutex::new(None));
        let shared_policy: SharedPolicy = Arc::new(std::sync::RwLock::new(policy));
        let hook = make_sandbox_hook(
            shared_policy,
            None,
            false,
            crate::audit::AuditConfig::default(),
            "test-deny".to_string(),
            last_decision.clone(),
        );

        let result = hook("/usr/bin/git", &["push".to_string()]);
        assert!(
            matches!(result, clash_brush_core::ExternalCommandAction::Block),
            "denied command should be blocked"
        );

        // Shared state should reflect the denial.
        let decision = last_decision.lock().unwrap();
        let d = decision.as_ref().expect("should have a decision");
        assert_eq!(d.effect, Effect::Deny);
        assert_eq!(d.command, "git push");
    }
}
