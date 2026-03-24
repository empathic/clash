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

use anyhow::{Context, Result};
use std::sync::{Arc, RwLock};
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

#[derive(Clone)]
struct PolicySnapshot {
    compiled: Arc<CompiledPolicy>,
    default_sandbox: Option<SandboxPolicy>,
}

struct PolicyCache {
    inner: RwLock<PolicySnapshot>,
    /// Instant of the last successful or attempted policy refresh; used to
    /// throttle reloads so we don't hit the filesystem on every command.
    last_refresh: std::sync::Mutex<std::time::Instant>,
}

const POLICY_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

impl PolicyCache {
    fn load_initial(sandbox_name: Option<&str>) -> anyhow::Result<Self> {
        let snap = Self::reload_snapshot(sandbox_name)?;
        Ok(Self {
            inner: RwLock::new(snap),
            last_refresh: std::sync::Mutex::new(std::time::Instant::now()),
        })
    }

    fn current(&self) -> PolicySnapshot {
        self.inner.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn try_refresh(&self, sandbox_name: Option<&str>, debug: bool) {
        let now = std::time::Instant::now();
        {
            let mut last = self.last_refresh.lock().unwrap_or_else(|e| e.into_inner());
            if now.duration_since(*last) < POLICY_REFRESH_INTERVAL {
                return;
            }
            *last = now;
        }

        match Self::reload_snapshot(sandbox_name) {
            Ok(new_snap) => {
                *self.inner.write().unwrap_or_else(|e| e.into_inner()) = new_snap;
            }
            Err(err) => {
                if debug {
                    eprintln!("[clash-shell] policy reload failed; using last-known-good: {err}");
                }
            }
        }
    }

    fn reload_snapshot(sandbox_name: Option<&str>) -> anyhow::Result<PolicySnapshot> {
        // NOTE: load_or_create() reads only the persisted (disk) settings. Any
        // session-level policy overrides (if ever introduced) would need to be
        // threaded in separately — they are not reloaded here.
        let settings = ClashSettings::load_or_create()?;
        let compiled = settings
            .policy_tree()
            .context("no compiled policy available")?
            .clone();

        let effective_name = sandbox_name.or(compiled.default_sandbox.as_deref());

        let default_sandbox = match effective_name {
            Some(name) => Some(
                compiled
                    .sandboxes
                    .get(name)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("no sandbox named '{name}' in policy"))?,
            ),
            None => None,
        };

        Ok(PolicySnapshot {
            compiled: Arc::new(compiled),
            default_sandbox,
        })
    }
}

fn make_sandbox_hook(
    clash_bin: String,
    cache: Arc<PolicyCache>,
    sandbox_name: Option<String>,
    debug: bool,
) -> clash_brush_core::ExternalCommandHook {
    Arc::new(move |executable_path: &str, args: &[String]| {
        let basename = executable_path
            .rsplit('/')
            .next()
            .unwrap_or(executable_path);

        if SHELL_BUILTINS.contains(&basename) {
            return None;
        }

        #[cfg(not(test))]
        cache.try_refresh(sandbox_name.as_deref(), debug);
        let snap = cache.current();

        let mut cmd_parts = vec![basename.to_string()];
        cmd_parts.extend(args.iter().cloned());
        let command_str = cmd_parts.join(" ");

        let tool_input = serde_json::json!({ "command": command_str });
        let decision = snap.compiled.evaluate("Bash", &tool_input);

        let effective_sandbox;
        let sandbox = match decision.sandbox {
            Some(ref sbx) => sbx,
            None => match snap.default_sandbox {
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

        let mut resolved = sandbox.clone();
        let resolver = crate::policy::path::PathResolver::from_env();
        for rule in &mut resolved.rules {
            rule.path = rule
                .path
                .replace("$HOME", resolver.home())
                .replace("$TMPDIR", resolver.tmpdir());
        }

        // Fail-closed: if the sandbox cannot be serialized the command must be
        // blocked rather than allowed to run unsandboxed.
        let policy_json = match serde_json::to_string(&resolved) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("[clash-shell] sandbox serialization failed; blocking command: {e}");
                return Some(("false".to_string(), vec![]));
            }
        };

        let mut new_args = vec![
            "sandbox".to_string(),
            "exec".to_string(),
            "--sandbox".to_string(),
            policy_json,
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
    sandbox_name: Option<String>,
    debug: bool,
) -> Result<()> {
    let cwd = crate::sandbox_cmd::resolve_cwd(&cwd)?;
    let clash_bin = std::env::current_exe()
        .context("failed to determine clash executable path")?
        .to_string_lossy()
        .to_string();

    // Load the policy cache (validated eagerly so we fail fast on bad config).
    // Hint about `clash init` only when the root cause is a missing policy.
    let cache = Arc::new(
        PolicyCache::load_initial(sandbox_name.as_deref()).map_err(|e| {
            if e.to_string().contains("no compiled policy") {
                e.context("run `clash init` first to compile a policy")
            } else {
                e
            }
        })?,
    );

    let hook = make_sandbox_hook(clash_bin, cache, sandbox_name, debug);

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
    info!(command = %command, "executing command string with sandbox hook");

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

    /// Wrap a CompiledPolicy in a PolicyCache for use in tests.
    fn policy_cache(policy: Arc<CompiledPolicy>) -> Arc<PolicyCache> {
        Arc::new(PolicyCache {
            inner: RwLock::new(PolicySnapshot {
                compiled: policy,
                default_sandbox: None,
            }),
            last_refresh: std::sync::Mutex::new(std::time::Instant::now()),
        })
    }

    /// Build a test policy that allows Bash with a sandbox.
    fn test_policy() -> Arc<PolicyCache> {
        policy_cache(Arc::new(compile_star(
            r#"load("@clash//std.star", "policy", "sandbox", "cwd", "exe", "deny")
def main():
    return policy(default = deny(), rules = [
        exe().sandbox(sandbox(name="test", default=deny(), fs=[cwd().allow(read=True)])).allow(),
    ])
"#,
        )))
    }

    fn test_hook() -> clash_brush_core::ExternalCommandHook {
        make_sandbox_hook("/usr/bin/clash".to_string(), test_policy(), None, false)
    }

    #[test]
    fn hook_wraps_with_policy_json() {
        let hook = test_hook();
        // Brush resolves to full paths; hook should still match policy.
        let result = hook("/usr/bin/git", &["push".to_string()]);
        let (exe, args) = result.unwrap();
        assert_eq!(exe, "/usr/bin/clash");
        assert_eq!(args[0], "sandbox");
        assert_eq!(args[1], "exec");
        assert_eq!(args[2], "--sandbox");
        // args[3] should be the sandbox policy JSON
        let _: serde_json::Value =
            serde_json::from_str(&args[3]).expect("--sandbox arg should be valid JSON");
        assert_eq!(args[4], "--");
        // The actual exec still uses the full path from brush.
        assert_eq!(args[5], "/usr/bin/git");
        assert_eq!(args[6], "push");
    }

    #[test]
    fn hook_preserves_args_order() {
        let hook = test_hook();
        let result = hook(
            "/bin/cat",
            &["file1.txt".to_string(), "file2.txt".to_string()],
        );
        let (_, args) = result.unwrap();
        let dash_pos = args.iter().position(|a| a == "--").unwrap();
        assert_eq!(args[dash_pos + 1], "/bin/cat");
        assert_eq!(args[dash_pos + 2], "file1.txt");
        assert_eq!(args[dash_pos + 3], "file2.txt");
    }

    #[test]
    fn hook_returns_none_without_sandbox() {
        let policy = policy_cache(Arc::new(compile_star(
            r#"load("@clash//std.star", "allow", "policy")
def main():
    return policy(default = allow(), rules = [])
"#,
        )));
        let hook = make_sandbox_hook("/usr/bin/clash".to_string(), policy, None, false);
        // No sandbox → command runs unchanged.
        let result = hook("/usr/bin/git", &["push".to_string()]);
        assert!(result.is_none());
    }
}
