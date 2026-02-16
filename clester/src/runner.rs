//! Test runner for clester.
//!
//! Invokes the clash binary as a subprocess, piping hook JSON via stdin
//! and capturing stdout/stderr/exit code.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::environment::TestEnvironment;
use crate::script::Step;

/// Result of invoking a single hook on the clash binary.
#[derive(Debug)]
pub struct HookResult {
    /// Exit code from the process.
    pub exit_code: i32,

    /// Parsed JSON output from stdout (if valid JSON).
    pub output: Option<serde_json::Value>,

    /// Raw stdout.
    pub stdout: String,

    /// Raw stderr.
    pub stderr: String,
}

/// Finds the clash binary, preferring a freshly-built one from the workspace.
pub fn find_clash_binary() -> Result<PathBuf> {
    // Look for it relative to the clester binary (both in target/debug)
    let self_path = std::env::current_exe().ok();

    if let Some(ref self_path) = self_path {
        // ../clash relative to clester binary (both in target/debug/)
        let sibling = self_path.parent().unwrap().join("clash");
        if sibling.exists() {
            return Ok(sibling);
        }
    }

    // Try the workspace target directory
    let workspace_debug = Path::new("target/debug/clash");
    if workspace_debug.exists() {
        return Ok(workspace_debug.to_path_buf());
    }

    // Try $PATH
    if let Ok(output) = Command::new("which").arg("clash").output()
        && output.status.success()
    {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }

    bail!("clash binary not found. Run `cargo build --bins` first.")
}

/// Execute a single test step by invoking the clash binary.
pub fn run_step(clash_bin: &Path, env: &TestEnvironment, step: &Step) -> Result<HookResult> {
    let stdin_json = build_stdin_json(env, step)?;
    let hook_subcommand = step
        .hook
        .as_ref()
        .context("run_step called on a step without a hook")?;

    let mut child = Command::new(clash_bin)
        .arg("hook")
        .arg(hook_subcommand)
        .env("HOME", &env.home_dir)
        .current_dir(&env.project_dir)
        // Prevent any system-level clash config from leaking in
        .env_remove("CLASH_CONFIG")
        .env_remove("CLASH_POLICY_FILE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn clash binary: {}", clash_bin.display()))?;

    // Write JSON to stdin
    {
        let child_stdin = child.stdin.as_mut().context("failed to open clash stdin")?;
        child_stdin
            .write_all(stdin_json.as_bytes())
            .context("failed to write to clash stdin")?;
    }

    let output = child
        .wait_with_output()
        .context("failed to wait for clash process")?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);

    let parsed_output = serde_json::from_str::<serde_json::Value>(&stdout).ok();

    Ok(HookResult {
        exit_code,
        output: parsed_output,
        stdout,
        stderr,
    })
}

/// Execute a command step by running `clash <args>` directly.
///
/// Unlike hook steps which pipe JSON to `clash hook <type>`, command steps
/// invoke clash CLI subcommands (e.g., `clash policy allow '(exec "git" *)'`).
pub fn run_command(clash_bin: &Path, env: &TestEnvironment, command: &str) -> Result<HookResult> {
    let args = shlex::split(command)
        .ok_or_else(|| anyhow::anyhow!("failed to parse command: {}", command))?;

    if args.is_empty() {
        bail!("empty command");
    }

    let output = Command::new(clash_bin)
        .args(&args)
        .env("HOME", &env.home_dir)
        .current_dir(&env.project_dir)
        .env_remove("CLASH_CONFIG")
        .env_remove("CLASH_POLICY_FILE")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn clash command: clash {}", command))?
        .wait_with_output()
        .with_context(|| format!("failed to wait for clash command: clash {}", command))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);
    let parsed_output = serde_json::from_str::<serde_json::Value>(&stdout).ok();

    Ok(HookResult {
        exit_code,
        output: parsed_output,
        stdout,
        stderr,
    })
}

/// Execute an arbitrary shell command step.
///
/// Runs the command via `sh -c` with the test environment's HOME and project dir.
/// Useful for filesystem setup between hook steps (e.g., writing session policy files).
pub fn run_shell(env: &TestEnvironment, shell_cmd: &str) -> Result<HookResult> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(shell_cmd)
        .env("HOME", &env.home_dir)
        .current_dir(&env.project_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn shell command: {}", shell_cmd))?
        .wait_with_output()
        .with_context(|| format!("failed to wait for shell command: {}", shell_cmd))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);
    let parsed_output = serde_json::from_str::<serde_json::Value>(&stdout).ok();

    Ok(HookResult {
        exit_code,
        output: parsed_output,
        stdout,
        stderr,
    })
}

/// Build the JSON that gets piped to clash's stdin for a given step.
fn build_stdin_json(env: &TestEnvironment, step: &Step) -> Result<String> {
    let hook = step
        .hook
        .as_ref()
        .context("build_stdin_json called on a step without a hook")?;
    match hook.as_str() {
        "pre-tool-use" | "post-tool-use" | "permission-request" => build_tool_use_json(env, step),
        "notification" => build_notification_json(env, step),
        "session-start" => build_session_start_json(env, step),
        other => bail!("unknown hook type: {}", other),
    }
}

fn build_tool_use_json(env: &TestEnvironment, step: &Step) -> Result<String> {
    let tool_name = step.tool_name.as_deref().unwrap_or("Bash");
    let tool_input = step
        .tool_input
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));

    let hook = step.hook.as_deref().unwrap_or("pre-tool-use");
    let hook_event_name = match hook {
        "pre-tool-use" => "PreToolUse",
        "post-tool-use" => "PostToolUse",
        "permission-request" => "PermissionRequest",
        _ => "PreToolUse",
    };

    let json = serde_json::json!({
        "session_id": "clester-test-session",
        "transcript_path": env.project_dir.join("transcript.jsonl").to_string_lossy(),
        "cwd": env.project_dir.to_string_lossy(),
        "permission_mode": "default",
        "hook_event_name": hook_event_name,
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": "clester_tool_001"
    });

    Ok(serde_json::to_string(&json)?)
}

fn build_session_start_json(env: &TestEnvironment, _step: &Step) -> Result<String> {
    let json = serde_json::json!({
        "session_id": "clester-test-session",
        "transcript_path": env.project_dir.join("transcript.jsonl").to_string_lossy(),
        "cwd": env.project_dir.to_string_lossy(),
        "permission_mode": "default",
        "hook_event_name": "SessionStart"
    });

    Ok(serde_json::to_string(&json)?)
}

fn build_notification_json(env: &TestEnvironment, step: &Step) -> Result<String> {
    let message = step.message.as_deref().unwrap_or("test notification");
    let notification_type = step.notification_type.as_deref().unwrap_or("unknown");

    let json = serde_json::json!({
        "session_id": "clester-test-session",
        "transcript_path": env.project_dir.join("transcript.jsonl").to_string_lossy(),
        "cwd": env.project_dir.to_string_lossy(),
        "permission_mode": "default",
        "hook_event_name": "Notification",
        "message": message,
        "notification_type": notification_type
    });

    Ok(serde_json::to_string(&json)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::{Expectation, SettingsConfig, Step};

    #[test]
    fn test_build_pre_tool_use_json() {
        let config = SettingsConfig::default();
        let env = TestEnvironment::setup(&config, None).unwrap();

        let step = Step {
            name: "test".into(),
            hook: Some("pre-tool-use".into()),
            command: None,
            shell: None,
            tool_name: Some("Bash".into()),
            tool_input: Some(serde_json::json!({"command": "git status"})),
            message: None,
            notification_type: None,
            expect: Expectation {
                decision: Some("allow".into()),
                exit_code: None,
                no_decision: None,
                reason_contains: None,
                stdout_contains: None,
                stderr_contains: None,
            },
        };

        let json_str = build_stdin_json(&env, &step).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["hook_event_name"], "PreToolUse");
        assert_eq!(parsed["tool_name"], "Bash");
        assert_eq!(parsed["tool_input"]["command"], "git status");
    }

    #[test]
    fn test_build_notification_json() {
        let config = SettingsConfig::default();
        let env = TestEnvironment::setup(&config, None).unwrap();

        let step = Step {
            name: "notif".into(),
            hook: Some("notification".into()),
            command: None,
            shell: None,
            tool_name: None,
            tool_input: None,
            message: Some("test message".into()),
            notification_type: Some("permission_prompt".into()),
            expect: Expectation {
                decision: None,
                exit_code: Some(0),
                no_decision: Some(true),
                reason_contains: None,
                stdout_contains: None,
                stderr_contains: None,
            },
        };

        let json_str = build_stdin_json(&env, &step).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["hook_event_name"], "Notification");
        assert_eq!(parsed["message"], "test message");
        assert_eq!(parsed["notification_type"], "permission_prompt");
    }
}
