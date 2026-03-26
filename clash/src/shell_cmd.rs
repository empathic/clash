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
use crate::policy::sandbox_types::SandboxPolicy;
use crate::settings::ClashSettings;

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
    policy: Arc<CompiledPolicy>,
    default_sandbox: Option<SandboxPolicy>,
    debug: bool,
) -> clash_brush_core::ExternalCommandHook {
    Arc::new(move |executable_path: &str, args: &[String]| {
        // Don't wrap shell builtins — they must run in the shell process.
        let basename = executable_path
            .rsplit('/')
            .next()
            .unwrap_or(executable_path);
        if SHELL_BUILTINS.contains(&basename) {
            return None;
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

        // Evaluate the policy exactly as check_permission would.
        let decision = policy.evaluate("Bash", &tool_input);

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
                    return None;
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
                return None;
            }
        };

        let mut new_args = vec![
            "-p".to_string(),
            profile,
            "--".to_string(),
            executable_path.to_string(),
        ];
        new_args.extend(args.iter().cloned());
        Some(("sandbox-exec".to_string(), new_args))
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

    let hook = make_sandbox_hook(Arc::new(policy), default_sandbox, debug);

    // Build a tokio runtime for brush's async API.
    let rt = tokio::runtime::Runtime::new().context("failed to create tokio runtime")?;

    rt.block_on(async {
        if let Some(ref cmd) = command {
            run_command_string(cmd, &cwd, hook).await
        } else if !script_args.is_empty() {
            run_script(&script_args, &cwd, hook).await
        } else {
            run_interactive(&cwd, hook).await
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

/// Run an interactive shell REPL (`clash shell`).
async fn run_interactive(cwd: &str, hook: clash_brush_core::ExternalCommandHook) -> Result<()> {
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

    let shell_ref = std::sync::Arc::new(tokio::sync::Mutex::new(shell));

    let mut input = clash_brush_interactive::BasicInputBackend;

    let options = clash_brush_interactive::InteractiveOptions::default();

    let mut interactive =
        clash_brush_interactive::InteractiveShell::new(&shell_ref, &mut input, &options)
            .map_err(|e| anyhow::anyhow!("failed to create interactive shell: {e}"))?;

    interactive
        .run_interactively()
        .await
        .map_err(|e| anyhow::anyhow!("interactive shell error: {e}"))?;

    Ok(())
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

        let sb = sandbox("test", vec![
            ("default", deny()),
            ("fs", Expr::list(vec![
                cwd(vec![]).allow_kwargs(clash_starlark::kwargs!(read = true)),
            ])),
        ]);
        let source = clash_starlark::codegen::serialize(&[
            load_std(&["policy", "sandbox", "cwd", "match", "allow", "deny"]),
            Stmt::def("main", vec![
                Stmt::Return(policy(
                    deny(),
                    vec![clash_starlark::match_tree! {
                        "Bash" => allow_with_sandbox(sb),
                    }],
                    None,
                )),
            ]),
        ]);
        Arc::new(compile_star(&source))
    }

    fn test_hook() -> clash_brush_core::ExternalCommandHook {
        make_sandbox_hook(test_policy(), None, false)
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn hook_wraps_with_sandbox_exec_directly() {
        let hook = test_hook();
        // Brush resolves to full paths; hook should still match policy.
        let result = hook("/usr/bin/git", &["push".to_string()]);
        let (exe, args) = result.unwrap();
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
        let (exe, args) = result.unwrap();
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
            result.is_none(),
            "Linux uses Landlock (in-process), not sandbox-exec"
        );
    }

    #[test]
    fn hook_returns_none_without_sandbox() {
        use clash_starlark::codegen::ast::Stmt;
        use clash_starlark::codegen::builder::*;

        let source = clash_starlark::codegen::serialize(&[
            load_std(&["allow", "policy"]),
            Stmt::def("main", vec![
                Stmt::Return(policy(allow(), vec![], None)),
            ]),
        ]);
        let policy = Arc::new(compile_star(&source));
        let hook = make_sandbox_hook(policy, None, false);
        // No sandbox → command runs unchanged.
        let result = hook("/usr/bin/git", &["push".to_string()]);
        assert!(result.is_none());
    }
}
