use crate::policy::sandbox_types::{NetworkPolicy, SandboxPolicy};
use crate::sandbox;
use anyhow::{Context, Result};
use clap::Subcommand;
use tracing::{Level, info, instrument};

#[derive(Subcommand, Debug)]
pub enum SandboxCmd {
    /// Apply sandbox restrictions and exec a command
    Exec {
        /// Sandbox policy as JSON string (overrides --profile)
        #[arg(long)]
        policy: Option<String>,

        /// Profile name from policy.yaml (default: active profile)
        #[arg(long)]
        profile: Option<String>,

        /// Working directory for path resolution
        #[arg(long, default_value = ".")]
        cwd: String,

        /// Session ID for logging sandbox violations to the audit trail.
        /// When provided with --tool-use-id, violations captured from the
        /// kernel are written to the session audit.jsonl for PostToolUse.
        #[arg(long)]
        session_id: Option<String>,

        /// Tool use ID for correlating violations with the tool invocation.
        #[arg(long)]
        tool_use_id: Option<String>,

        /// Command and arguments to execute under sandbox
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Test sandbox enforcement interactively
    Test {
        /// Sandbox policy as JSON string (overrides --profile)
        #[arg(long)]
        policy: Option<String>,

        /// Profile name from policy.yaml (default: active profile)
        #[arg(long)]
        profile: Option<String>,

        /// Working directory for path resolution
        #[arg(long, default_value = ".")]
        cwd: String,

        /// Command and arguments to test
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Check if sandboxing is supported on this platform
    Check,
}

/// Resolve `--cwd` to an absolute path.
fn resolve_cwd(cwd: &str) -> Result<String> {
    let path = std::path::Path::new(cwd);
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to determine current directory")?
            .join(path)
    };
    Ok(abs.to_string_lossy().into_owned())
}

/// Resolve sandbox policy: `--policy` JSON wins, then `--profile` name,
/// then falls back to the active profile from policy.yaml.
fn resolve_sandbox_policy(
    policy_json: Option<&str>,
    profile_name: Option<&str>,
    cwd: &str,
) -> Result<SandboxPolicy> {
    if let Some(json) = policy_json {
        return serde_json::from_str(json).context("failed to parse --policy JSON");
    }
    // Empty string means "use default profile from config"
    let name = profile_name.unwrap_or("");
    load_sandbox_for_profile(name, cwd)
}

/// Load the policy file, compile it, and generate a sandbox policy.
fn load_sandbox_for_profile(profile_name: &str, cwd: &str) -> Result<SandboxPolicy> {
    use crate::settings::ClashSettings;

    let path = ClashSettings::policy_file()?;
    let source = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let tree = crate::policy::compile_policy(&source)
        .with_context(|| format!("failed to compile {}", path.display()))?;

    tree.build_sandbox_policy(profile_name, cwd).ok_or_else(|| {
        anyhow::anyhow!(
            "policy has no sandbox-relevant constraints (no fs rules found for profile '{}')",
            profile_name
        )
    })
}

/// Run a command inside a sandbox.
#[instrument(level = Level::TRACE)]
pub fn run_sandbox(cmd: SandboxCmd) -> Result<()> {
    match cmd {
        SandboxCmd::Exec {
            policy,
            profile,
            cwd,
            session_id,
            tool_use_id,
            command,
        } => {
            let cwd = resolve_cwd(&cwd)?;
            let sandbox_policy =
                resolve_sandbox_policy(policy.as_deref(), profile.as_deref(), &cwd)?;
            let cwd_path = std::path::PathBuf::from(&cwd);

            run_sandboxed_command(
                &sandbox_policy,
                &cwd_path,
                &command,
                session_id.as_deref(),
                tool_use_id.as_deref(),
            )
        }
        SandboxCmd::Test {
            policy,
            profile,
            cwd,
            command,
        } => {
            let cwd = resolve_cwd(&cwd)?;
            let sandbox_policy =
                resolve_sandbox_policy(policy.as_deref(), profile.as_deref(), &cwd)?;
            let cwd_path = std::path::PathBuf::from(&cwd);

            eprintln!("Testing sandbox with policy:");
            eprintln!("  default: {}", sandbox_policy.default.display());
            eprintln!("  network: {:?}", sandbox_policy.network);
            for rule in &sandbox_policy.rules {
                eprintln!(
                    "  {:?} {} in {}",
                    rule.effect,
                    rule.caps.display(),
                    rule.path
                );
            }
            eprintln!("  command: {:?}", command);
            eprintln!("---");

            run_sandboxed_command(&sandbox_policy, &cwd_path, &command, None, None)
        }
        SandboxCmd::Check => {
            let support = sandbox::check_support();
            match support {
                sandbox::SupportLevel::Full => {
                    println!("Sandbox: fully supported");
                }
                sandbox::SupportLevel::Partial { missing } => {
                    println!("Sandbox: partially supported");
                    for m in &missing {
                        println!("  missing: {}", m);
                    }
                }
                sandbox::SupportLevel::Unsupported { reason } => {
                    println!("Sandbox: not supported ({})", reason);
                    std::process::exit(1);
                }
            }
            Ok(())
        }
    }
}

/// Run a command under sandbox enforcement.
///
/// On macOS: spawns `sandbox-exec` as a child process, waits for it to complete,
/// then queries the unified log for sandbox violations. Any violations found are
/// written to the session audit log so PostToolUse can read them and provide
/// context to the model.
///
/// On other platforms: applies the sandbox in-process and execs the command
/// directly via `exec_sandboxed()` (no violation capture).
fn run_sandboxed_command(
    policy: &SandboxPolicy,
    cwd: &std::path::Path,
    command: &[String],
    session_id: Option<&str>,
    tool_use_id: Option<&str>,
) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        spawn_and_capture_macos(policy, cwd, command, session_id, tool_use_id)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (session_id, tool_use_id);
        exec_with_proxy(policy, cwd, command)
    }
}

// ── macOS: spawn + violation capture ─────────────────────────────────────

/// Spawn `sandbox-exec` as a child process, wait for it, and capture violations.
///
/// Instead of `exec_sandboxed()` (which replaces the process via execvp and
/// prevents any post-execution work), this function:
/// 1. Compiles the policy to an SBPL profile
/// 2. Starts a domain-filtering proxy if `AllowDomains` is active
/// 3. Spawns `sandbox-exec -p <profile> -- <command...>` as a child
/// 4. Waits for the child to exit
/// 5. Queries `log show` for sandbox violations by the child's PID
/// 6. Writes violations to the session audit log
/// 7. Exits with the child's exit code
#[cfg(target_os = "macos")]
fn spawn_and_capture_macos(
    policy: &SandboxPolicy,
    cwd: &std::path::Path,
    command: &[String],
    session_id: Option<&str>,
    tool_use_id: Option<&str>,
) -> Result<()> {
    let profile = sandbox::compile_sandbox_profile(policy, cwd)
        .context("failed to compile sandbox profile")?;

    // Start domain-filtering proxy if the policy uses AllowDomains.
    let proxy_handle = match &policy.network {
        NetworkPolicy::AllowDomains(domains) => {
            let handle = sandbox::proxy::start_proxy(sandbox::proxy::ProxyConfig {
                allowed_domains: domains.clone(),
            })
            .context("failed to start domain-filtering proxy")?;
            info!(addr = %handle.addr, "started domain-filtering proxy");
            Some(handle)
        }
        _ => None,
    };

    // Build: sandbox-exec -p <profile> -- <command...>
    let mut cmd = std::process::Command::new("sandbox-exec");
    cmd.args(["-p", &profile, "--"]);
    cmd.args(command);
    cmd.current_dir(cwd);
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    if let Some(ref handle) = proxy_handle {
        let proxy_url = format!("http://{}", handle.addr);
        cmd.env("HTTP_PROXY", &proxy_url)
            .env("HTTPS_PROXY", &proxy_url)
            .env("http_proxy", &proxy_url)
            .env("https_proxy", &proxy_url);
    }

    let start = std::time::Instant::now();
    let mut child = cmd.spawn().context("failed to spawn sandbox-exec")?;
    let child_pid = child.id();
    let status = child
        .wait()
        .context("failed to wait for sandboxed process")?;
    let elapsed = start.elapsed();

    // Shut down the proxy now that the child has exited.
    drop(proxy_handle);

    // Capture violations from the unified log and write to audit log.
    if let (Some(sid), Some(tuid)) = (session_id, tool_use_id) {
        capture_and_log_violations(child_pid, elapsed, sid, tuid, command);
    }

    // Exit with the child's exit code.
    let code = status.code().unwrap_or(1);
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

/// Query the macOS unified log for sandbox violations from a sandboxed process
/// and write them to the session audit log.
///
/// sandboxd log messages look like:
///   `Sandbox: bash(12345) deny(1) file-write-create /path/to/file`
///
/// We search a tight time window (command duration + buffer) for any file-deny
/// events. We intentionally do NOT filter by PID because the sandboxed process
/// may fork children (e.g., bash → mkdir) whose PIDs differ from the top-level
/// process but still inherit the sandbox profile.
#[cfg(target_os = "macos")]
fn capture_and_log_violations(
    _child_pid: u32,
    elapsed: std::time::Duration,
    session_id: &str,
    tool_use_id: &str,
    command: &[String],
) {
    // Brief sleep to let the unified log flush sandboxd messages.
    std::thread::sleep(std::time::Duration::from_millis(150));

    let last_secs = elapsed.as_secs() + 3; // 3s buffer for log propagation
    let last_arg = format!("{}s", last_secs.max(5)); // at least 5s window

    // No PID filter — sandbox-exec children (e.g., bash → mkdir) inherit the
    // sandbox but get their own PIDs, so filtering by the top-level PID misses
    // their violations. The time window is tight enough to avoid stray matches.
    let predicate =
        "eventMessage CONTAINS \"deny\" AND eventMessage CONTAINS \"file-\"".to_string();

    info!(
        predicate = %predicate,
        last = %last_arg,
        "Querying unified log for sandbox violations"
    );

    let output = match std::process::Command::new("log")
        .args([
            "show",
            "--last",
            &last_arg,
            "--predicate",
            &predicate,
            "--style",
            "compact",
            "--no-pager",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
    {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            info!(exit_code = ?o.status.code(), "log show returned non-zero");
            return;
        }
        Err(e) => {
            info!(error = %e, "Failed to run log show");
            return;
        }
    };

    let content = String::from_utf8_lossy(&output.stdout);
    let violations = parse_log_violations(&content);

    if violations.is_empty() {
        return;
    }

    info!(
        count = violations.len(),
        "Captured sandbox violations from unified log"
    );

    let tool_input_summary = if command.len() <= 3 {
        command.join(" ")
    } else {
        format!("{} {} {} ...", command[0], command[1], command[2])
    };

    crate::audit::log_sandbox_violations(
        session_id,
        "Bash",
        tool_use_id,
        &tool_input_summary,
        &violations,
    );
}

/// Paths that are commonly denied by macOS Seatbelt on process startup but
/// aren't user-visible errors. Filtered out to reduce noise in audit entries.
#[cfg(target_os = "macos")]
const NOISE_PATH_PREFIXES: &[&str] = &["/dev/dtrace", "/dev/dtracehelper", "/dev/oslog"];

/// Parse sandbox violations from macOS unified log (`log show`) output.
///
/// Extracts the operation and path from sandboxd deny messages:
///   `Sandbox: bash(12345) deny(1) file-write-create /Users/user/.fly/config`
///
/// Filters out known noise paths (e.g., `/dev/dtracehelper`) that appear on
/// every process startup and aren't meaningful violations.
#[cfg(target_os = "macos")]
fn parse_log_violations(content: &str) -> Vec<crate::audit::SandboxViolation> {
    let re = match regex::Regex::new(r"deny\(\d+\)\s+(file-\S+)\s+(/\S+)") {
        Ok(re) => re,
        Err(_) => return Vec::new(),
    };

    let mut violations = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    for line in content.lines() {
        if !line.contains("deny") || !line.contains("file-") {
            continue;
        }
        for cap in re.captures_iter(line) {
            if let (Some(op), Some(path)) = (cap.get(1), cap.get(2)) {
                let path_str = path.as_str().to_string();
                // Skip noise paths and duplicates.
                if path_str.starts_with('/')
                    && !NOISE_PATH_PREFIXES
                        .iter()
                        .any(|prefix| path_str.starts_with(prefix))
                    && seen.insert(path_str.clone())
                {
                    violations.push(crate::audit::SandboxViolation {
                        operation: op.as_str().to_string(),
                        path: path_str,
                    });
                }
            }
        }
    }

    violations
}

// ── Non-macOS: exec-based fallback ───────────────────────────────────────

/// Execute a command under the sandbox using exec (replaces the process).
///
/// When `AllowDomains` is active, forks first so the parent can run the
/// domain-filtering proxy while the child applies the sandbox and execs.
#[cfg(not(target_os = "macos"))]
fn exec_with_proxy(
    policy: &SandboxPolicy,
    cwd: &std::path::Path,
    command: &[String],
) -> Result<()> {
    match &policy.network {
        NetworkPolicy::AllowDomains(domains) => {
            let proxy_handle = sandbox::proxy::start_proxy(sandbox::proxy::ProxyConfig {
                allowed_domains: domains.clone(),
            })
            .context("failed to start domain-filtering proxy")?;
            let proxy_url = format!("http://{}", proxy_handle.addr);
            info!(addr = %proxy_handle.addr, "started domain-filtering proxy for exec");

            let pid = unsafe { libc::fork() };
            match pid {
                -1 => {
                    anyhow::bail!("fork failed: {}", std::io::Error::last_os_error());
                }
                0 => {
                    // Child: set proxy env vars, then apply sandbox + exec.
                    unsafe {
                        set_env_cstr("HTTP_PROXY", &proxy_url);
                        set_env_cstr("HTTPS_PROXY", &proxy_url);
                        set_env_cstr("http_proxy", &proxy_url);
                        set_env_cstr("https_proxy", &proxy_url);
                    }
                    match sandbox::exec_sandboxed(policy, cwd, command, None) {
                        Err(e) => {
                            eprintln!("sandbox exec failed: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                child_pid => {
                    // Parent: wait for the child, then clean up.
                    let mut status: libc::c_int = 0;
                    unsafe {
                        libc::waitpid(child_pid, &mut status, 0);
                    }
                    drop(proxy_handle);
                    if libc::WIFEXITED(status) {
                        let code = libc::WEXITSTATUS(status);
                        if code != 0 {
                            std::process::exit(code);
                        }
                    } else {
                        std::process::exit(1);
                    }
                    Ok(())
                }
            }
        }
        _ => {
            // No proxy needed — exec directly.
            match sandbox::exec_sandboxed(policy, cwd, command, None) {
                Err(e) => anyhow::bail!("sandbox exec failed: {}", e),
            }
        }
    }
}

/// Set an environment variable using libc (safe to call after fork).
#[cfg(not(target_os = "macos"))]
unsafe fn set_env_cstr(key: &str, val: &str) {
    use std::ffi::CString;
    if let (Ok(k), Ok(v)) = (CString::new(key), CString::new(val)) {
        unsafe { libc::setenv(k.as_ptr(), v.as_ptr(), 1) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_log_violations_basic() {
        let log = "2025-01-15 10:00:00.123 sandboxd Sandbox: bash(12345) deny(1) file-write-create /Users/user/.fly/perms.123";
        let violations = parse_log_violations(log);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].operation, "file-write-create");
        assert_eq!(violations[0].path, "/Users/user/.fly/perms.123");
    }

    #[test]
    fn test_parse_log_violations_multiple() {
        let log = "2025-01-15 10:00:00.123 sandboxd Sandbox: bash(12345) deny(1) file-write-create /Users/user/.fly/config\n\
                   2025-01-15 10:00:00.456 sandboxd Sandbox: bash(12345) deny(1) file-read-data /Users/user/.cache/db";
        let violations = parse_log_violations(log);
        assert_eq!(violations.len(), 2);
        assert_eq!(violations[0].operation, "file-write-create");
        assert_eq!(violations[0].path, "/Users/user/.fly/config");
        assert_eq!(violations[1].operation, "file-read-data");
        assert_eq!(violations[1].path, "/Users/user/.cache/db");
    }

    #[test]
    fn test_parse_log_violations_deduplicates() {
        let log = "2025-01-15 10:00:00.123 sandboxd Sandbox: bash(12345) deny(1) file-write-create /tmp/foo\n\
                   2025-01-15 10:00:00.456 sandboxd Sandbox: bash(12345) deny(1) file-write-data /tmp/foo";
        let violations = parse_log_violations(log);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].path, "/tmp/foo");
    }

    #[test]
    fn test_parse_log_violations_no_denies() {
        let log = "2025-01-15 10:00:00.123 sandboxd Sandbox: bash(12345) allow file-read-data /usr/lib/libSystem.B.dylib";
        let violations = parse_log_violations(log);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_parse_log_violations_ignores_non_file() {
        let log = "2025-01-15 10:00:00.123 sandboxd Sandbox: bash(12345) deny(1) network-outbound 1.2.3.4:443\n\
                   2025-01-15 10:00:00.456 sandboxd Sandbox: bash(12345) deny(1) file-write-create /Users/user/.fly/perms";
        let violations = parse_log_violations(log);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].path, "/Users/user/.fly/perms");
    }

    #[test]
    fn test_parse_log_violations_empty_input() {
        let violations = parse_log_violations("");
        assert!(violations.is_empty());
    }

    #[test]
    fn test_parse_log_violations_filters_noise_paths() {
        let log = "2025-01-15 10:00:00.123 sandboxd Sandbox: bash(12345) deny(1) file-read-data /dev/dtracehelper\n\
                   2025-01-15 10:00:00.456 sandboxd Sandbox: bash(12345) deny(1) file-write-create /Users/user/.fly/config";
        let violations = parse_log_violations(log);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].path, "/Users/user/.fly/config");
    }

    #[test]
    fn test_parse_log_violations_filters_all_noise() {
        let log = "2025-01-15 10:00:00.123 sandboxd Sandbox: bash(12345) deny(1) file-read-data /dev/dtracehelper\n\
                   2025-01-15 10:00:00.456 sandboxd Sandbox: bash(12345) deny(1) file-read-data /dev/oslog/foo";
        let violations = parse_log_violations(log);
        assert!(violations.is_empty());
    }
}
