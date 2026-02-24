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
            command,
        } => {
            let cwd = resolve_cwd(&cwd)?;
            let sandbox_policy =
                resolve_sandbox_policy(policy.as_deref(), profile.as_deref(), &cwd)?;
            let cwd_path = std::path::PathBuf::from(&cwd);
            exec_with_proxy(&sandbox_policy, &cwd_path, &command)
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

            exec_with_proxy(&sandbox_policy, &cwd_path, &command)
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

/// Execute a command under the sandbox, starting a domain-filtering proxy if
/// the policy uses `AllowDomains`.
///
/// `exec_sandboxed()` replaces the process via `execvp()`, which would kill
/// any proxy thread. When `AllowDomains` is active we fork first: the parent
/// runs the proxy and waits for the child; the child sets `HTTP_PROXY` env
/// vars, applies the sandbox, and execs the command.
fn exec_with_proxy(
    policy: &SandboxPolicy,
    cwd: &std::path::Path,
    command: &[String],
) -> Result<()> {
    match &policy.network {
        NetworkPolicy::AllowDomains(domains) => {
            // Start the proxy BEFORE forking so we know the address.
            let proxy_handle = sandbox::proxy::start_proxy(sandbox::proxy::ProxyConfig {
                allowed_domains: domains.clone(),
            })
            .context("failed to start domain-filtering proxy")?;
            let proxy_url = format!("http://{}", proxy_handle.addr);
            info!(addr = %proxy_handle.addr, "started domain-filtering proxy for exec");

            // Safety: we are single-threaded at this point in the CLI entry
            // path (the proxy's accept thread is the only other thread, and
            // it only touches its own socket).
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
                    match sandbox::exec_sandboxed(policy, cwd, command) {
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
            match sandbox::exec_sandboxed(policy, cwd, command) {
                Err(e) => anyhow::bail!("sandbox exec failed: {}", e),
            }
        }
    }
}

/// Set an environment variable using libc (safe to call after fork).
unsafe fn set_env_cstr(key: &str, val: &str) {
    use std::ffi::CString;
    if let (Ok(k), Ok(v)) = (CString::new(key), CString::new(val)) {
        unsafe { libc::setenv(k.as_ptr(), v.as_ptr(), 1) };
    }
}
