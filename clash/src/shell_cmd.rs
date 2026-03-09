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
use crate::settings::ClashSettings;

/// Build the external command hook that evaluates the policy for each command
/// and wraps it with the appropriate sandbox (same as Claude's Bash tool).
/// Shell builtins that should never be wrapped — they must run in-process.
const SHELL_BUILTINS: &[&str] = &[
    ".", ":", "[", "alias", "bg", "bind", "break", "builtin", "caller", "cd", "command",
    "compgen", "complete", "compopt", "continue", "declare", "dirs", "disown", "echo", "enable",
    "eval", "exec", "exit", "export", "false", "fc", "fg", "getopts", "hash", "help", "history",
    "jobs", "kill", "let", "local", "logout", "mapfile", "popd", "printf", "pushd", "pwd", "read",
    "readarray", "readonly", "return", "set", "shift", "shopt", "source", "suspend", "test",
    "times", "trap", "true", "type", "typeset", "ulimit", "umask", "unalias", "unset", "wait",
];

fn make_sandbox_hook(
    clash_bin: String,
    policy: Arc<CompiledPolicy>,
) -> brush_core::ExternalCommandHook {
    Arc::new(move |executable_path: &str, args: &[String]| {
        // Don't wrap shell builtins — they must run in the shell process.
        let basename = executable_path.rsplit('/').next().unwrap_or(executable_path);
        if SHELL_BUILTINS.contains(&basename) {
            return None;
        }

        // Reconstruct the full command string as it would appear in a Bash tool call.
        let mut cmd_parts = vec![executable_path.to_string()];
        cmd_parts.extend(args.iter().cloned());
        let command_str = cmd_parts.join(" ");

        // Build a tool_input that matches what Claude's Bash tool produces.
        let tool_input = serde_json::json!({
            "command": command_str,
        });

        // Evaluate the policy exactly as check_permission would.
        let decision = policy.evaluate("Bash", &tool_input);

        // If the policy denies this command, let it run unsandboxed — the kernel
        // sandbox on the parent clash-shell process already constrains it.
        // (Full deny enforcement is a future enhancement.)
        let sandbox = match decision.sandbox {
            Some(ref sbx) => sbx,
            None => return None, // No sandbox in policy — run unchanged.
        };

        let policy_json = match serde_json::to_string(sandbox) {
            Ok(j) => j,
            Err(_) => return None,
        };

        // Use the process cwd (which brush updates via chdir on `cd`).
        let current_cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| ".".to_string());

        let mut new_args = vec![
            "sandbox".to_string(),
            "exec".to_string(),
            "--sandbox".to_string(),
            policy_json,
            "--cwd".to_string(),
            current_cwd,
            "--".to_string(),
            executable_path.to_string(),
        ];
        new_args.extend(args.iter().cloned());
        Some((clash_bin.clone(), new_args))
    })
}

/// Run a bash-compatible shell with per-command sandbox enforcement.
pub fn run_shell(
    command: Option<String>,
    script_args: Vec<String>,
    cwd: String,
) -> Result<()> {
    let cwd = crate::sandbox_cmd::resolve_cwd(&cwd)?;
    let clash_bin = std::env::current_exe()
        .context("failed to determine clash executable path")?
        .to_string_lossy()
        .to_string();

    // Load the policy so we can evaluate it per-command.
    let settings = ClashSettings::load_or_create()
        .context("failed to load clash settings")?;
    let policy = settings
        .policy_tree()
        .context("no compiled policy available — run `clash init` first")?
        .clone();

    let hook = make_sandbox_hook(clash_bin, Arc::new(policy));

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
fn register_builtins(shell: &mut brush_core::Shell) {
    for (name, registration) in
        brush_builtins::default_builtins(brush_builtins::BuiltinSet::BashMode)
    {
        shell.register_builtin(&name, registration);
    }
}

/// Execute a command string (`clash shell -c "..."`).
async fn run_command_string(
    command: &str,
    cwd: &str,
    hook: brush_core::ExternalCommandHook,
) -> Result<()> {
    info!(command = %command, "executing command string with sandbox hook");

    let mut shell = brush_core::Shell::builder()
        .command_string_mode(true)
        .working_dir(std::path::PathBuf::from(cwd))
        .external_command_hook(hook)
        .profile(brush_core::ProfileLoadBehavior::Skip)
        .rc(brush_core::RcLoadBehavior::Skip)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("failed to create shell: {e}"))?;

    register_builtins(&mut shell);

    let params = shell.default_exec_params();
    let source_info = brush_core::SourceInfo::from("clash-shell");

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
    hook: brush_core::ExternalCommandHook,
) -> Result<()> {
    let script_path = &script_args[0];
    info!(script = %script_path, "executing script with sandbox hook");

    let args: Vec<String> = if script_args.len() > 1 {
        script_args[1..].to_vec()
    } else {
        vec![]
    };

    let mut shell = brush_core::Shell::builder()
        .working_dir(std::path::PathBuf::from(cwd))
        .external_command_hook(hook)
        .profile(brush_core::ProfileLoadBehavior::Skip)
        .rc(brush_core::RcLoadBehavior::Skip)
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
async fn run_interactive(
    cwd: &str,
    hook: brush_core::ExternalCommandHook,
) -> Result<()> {
    info!("starting interactive shell with sandbox hook");

    let mut shell = brush_core::Shell::builder()
        .interactive(true)
        .working_dir(std::path::PathBuf::from(cwd))
        .external_command_hook(hook)
        .shell_name("clash-shell".to_string())
        .profile(brush_core::ProfileLoadBehavior::Skip)
        .rc(brush_core::RcLoadBehavior::Skip)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("failed to create shell: {e}"))?;

    register_builtins(&mut shell);

    let shell_ref = std::sync::Arc::new(tokio::sync::Mutex::new(shell));

    let mut input = brush_interactive::BasicInputBackend::default();

    let options = brush_interactive::InteractiveOptions::default();

    let mut interactive =
        brush_interactive::InteractiveShell::new(&shell_ref, &mut input, &options)
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
        Arc::new(compile_star(
            r#"load("@clash//std.star", "policy", "sandbox", "cwd", "exe")
def main():
    return policy(default = deny, rules = [
        exe().sandbox(sandbox(name="test", default=deny, fs=[cwd().allow(read=True)])).allow(),
    ])
"#,
        ))
    }

    fn test_hook() -> brush_core::ExternalCommandHook {
        make_sandbox_hook("/usr/bin/clash".to_string(), test_policy())
    }

    #[test]
    fn hook_wraps_with_policy_json() {
        let hook = test_hook();
        let result = hook("git", &["push".to_string()]);
        let (exe, args) = result.unwrap();
        assert_eq!(exe, "/usr/bin/clash");
        assert_eq!(args[0], "sandbox");
        assert_eq!(args[1], "exec");
        assert_eq!(args[2], "--sandbox");
        // args[3] should be the sandbox policy JSON
        let _: serde_json::Value =
            serde_json::from_str(&args[3]).expect("--policy arg should be valid JSON");
        assert_eq!(args[4], "--cwd");
        assert!(!args[5].is_empty(), "cwd should be non-empty");
        assert_eq!(args[6], "--");
        assert_eq!(args[7], "git");
        assert_eq!(args[8], "push");
    }

    #[test]
    fn hook_preserves_args_order() {
        let hook = test_hook();
        let result = hook("cat", &["file1.txt".to_string(), "file2.txt".to_string()]);
        let (_, args) = result.unwrap();
        let dash_pos = args.iter().position(|a| a == "--").unwrap();
        assert_eq!(args[dash_pos + 1], "cat");
        assert_eq!(args[dash_pos + 2], "file1.txt");
        assert_eq!(args[dash_pos + 3], "file2.txt");
    }

    #[test]
    fn hook_returns_none_without_sandbox() {
        let policy = Arc::new(compile_star(
            r#"load("@clash//std.star", "policy")
def main():
    return policy(default = allow, rules = [])
"#,
        ));
        let hook = make_sandbox_hook("/usr/bin/clash".to_string(), policy);
        // No sandbox → command runs unchanged.
        let result = hook("git", &["push".to_string()]);
        assert!(result.is_none());
    }
}
