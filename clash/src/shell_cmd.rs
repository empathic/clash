//! `clash shell` — bash-compatible shell with per-command sandbox enforcement.
//!
//! Uses brush (a bash-compatible shell implementation in Rust) with an external
//! command hook that wraps every external command invocation through
//! `clash sandbox exec --profile <binary> --fallback-default`. This gives
//! per-command sandbox resolution: each command in a pipeline, script, or
//! interactive session gets its own sandbox profile looked up by binary name,
//! falling back to the default sandbox when no command-specific profile exists.
//!
//! Three modes:
//! - `clash shell` — interactive REPL (brush-interactive with basic backend)
//! - `clash shell -c "cmd"` — execute a command string
//! - `clash shell script.sh` — execute a script file

use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::info;

/// Build the external command hook that wraps commands through `clash sandbox exec`.
fn make_sandbox_hook(
    clash_bin: String,
    cwd: String,
) -> brush_core::ExternalCommandHook {
    Arc::new(move |executable_path: &str, args: &[String]| {
        let mut new_args = vec![
            "sandbox".to_string(),
            "exec".to_string(),
            "--profile".to_string(),
            executable_path.to_string(),
            "--fallback-default".to_string(),
            "--cwd".to_string(),
            cwd.clone(),
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

    let hook = make_sandbox_hook(clash_bin, cwd.clone());

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
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("failed to create shell: {e}"))?;

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
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("failed to create shell: {e}"))?;

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

    let shell = brush_core::Shell::builder()
        .interactive(true)
        .working_dir(std::path::PathBuf::from(cwd))
        .external_command_hook(hook)
        .shell_name("clash-shell".to_string())
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("failed to create shell: {e}"))?;

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

    fn test_hook() -> brush_core::ExternalCommandHook {
        make_sandbox_hook("/usr/bin/clash".to_string(), "/tmp".to_string())
    }

    #[test]
    fn hook_wraps_external_command() {
        let hook = test_hook();
        let result = hook("git", &["push".to_string()]);
        let (exe, args) = result.unwrap();
        assert_eq!(exe, "/usr/bin/clash");
        assert!(args.contains(&"sandbox".to_string()));
        assert!(args.contains(&"exec".to_string()));
        assert!(args.contains(&"--profile".to_string()));
        assert!(args.contains(&"git".to_string()));
        assert!(args.contains(&"--fallback-default".to_string()));
        assert!(args.contains(&"push".to_string()));
    }

    #[test]
    fn hook_preserves_args_order() {
        let hook = test_hook();
        let result = hook("cat", &["file1.txt".to_string(), "file2.txt".to_string()]);
        let (exe, args) = result.unwrap();
        assert_eq!(exe, "/usr/bin/clash");
        // Args after "--" should be: cat file1.txt file2.txt
        let dash_pos = args.iter().position(|a| a == "--").unwrap();
        assert_eq!(args[dash_pos + 1], "cat");
        assert_eq!(args[dash_pos + 2], "file1.txt");
        assert_eq!(args[dash_pos + 3], "file2.txt");
    }

    #[test]
    fn hook_produces_correct_sandbox_command() {
        let hook = test_hook();
        let result = hook("cargo", &["build".to_string(), "--release".to_string()]);
        let (exe, args) = result.unwrap();
        assert_eq!(exe, "/usr/bin/clash");
        assert_eq!(args[0], "sandbox");
        assert_eq!(args[1], "exec");
        assert_eq!(args[2], "--profile");
        assert_eq!(args[3], "cargo");
        assert_eq!(args[4], "--fallback-default");
        assert_eq!(args[5], "--cwd");
        assert_eq!(args[6], "/tmp");
        assert_eq!(args[7], "--");
        assert_eq!(args[8], "cargo");
        assert_eq!(args[9], "build");
        assert_eq!(args[10], "--release");
    }
}
