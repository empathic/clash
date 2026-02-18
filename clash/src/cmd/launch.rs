use anyhow::{Context, Result};
use tracing::{Level, info, instrument};

use crate::settings::ClashSettings;

/// Launch Claude Code with clash managing hooks and sandbox enforcement.
#[instrument(level = Level::TRACE)]
pub fn run(policy_path: Option<String>, args: Vec<String>) -> Result<()> {
    // Resolve the clash binary path for hook commands
    let clash_bin = std::env::current_exe().context("failed to determine clash binary path")?;
    let clash_bin_str = clash_bin.to_string_lossy();

    // Validate that we have a policy if one was specified
    if let Some(ref path) = policy_path {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read policy file: {}", path))?;
        crate::policy::compile_policy(&contents)
            .with_context(|| format!("failed to compile policy file: {}", path))?;
        info!(path, "Using policy file");
    }

    // Build the hooks JSON that points to our own binary
    let hooks_json = serde_json::json!({
        "hooks": {
            "PreToolUse": [{
                "hooks": [{
                    "type": "command",
                    "command": format!("{} hook pre-tool-use", clash_bin_str),
                    "matcher": "*"
                }]
            }],
            "PostToolUse": [{
                "hooks": [{
                    "type": "command",
                    "command": format!("{} hook post-tool-use", clash_bin_str),
                    "matcher": "*"
                }]
            }],
            "PermissionRequest": [{
                "hooks": [{
                    "type": "command",
                    "command": format!("{} hook permission-request", clash_bin_str),
                    "matcher": "*"
                }]
            }],
            "SessionStart": [{
                "hooks": [{
                    "type": "command",
                    "command": format!("{} hook session-start", clash_bin_str),
                }]
            }],
        }
    });

    // Write hooks to a temp file that Claude Code can use
    let hooks_dir = ClashSettings::settings_dir()?.join("hooks");
    std::fs::create_dir_all(&hooks_dir)?;
    let hooks_file = hooks_dir.join("hooks.json");
    std::fs::write(&hooks_file, serde_json::to_string_pretty(&hooks_json)?)?;

    info!(hooks_file = %hooks_file.display(), "Wrote hooks configuration");

    // Build claude command with hooks
    let mut cmd = std::process::Command::new("claude");
    cmd.arg("--hooks-file").arg(&hooks_file);

    // Pass through any additional args
    for arg in &args {
        // Skip the "--" separator if present
        if arg != "--" {
            cmd.arg(arg);
        }
    }

    info!(cmd = ?cmd, "Launching Claude Code");

    let status = cmd.status().context("failed to launch claude")?;
    std::process::exit(status.code().unwrap_or(1));
}
