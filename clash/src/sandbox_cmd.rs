use crate::policy::sandbox_types::SandboxPolicy;
use crate::sandbox;
use anyhow::{Context, Result};
use clap::Subcommand;
use tracing::{Level, instrument};

#[derive(Subcommand, Debug)]
pub enum SandboxCmd {
    /// Apply sandbox restrictions and exec a command
    Exec {
        /// Sandbox policy as JSON string (overrides --profile)
        #[arg(long)]
        policy: Option<String>,

        /// Profile name from policy.sexp (default: active profile)
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

        /// Profile name from policy.sexp (default: active profile)
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
/// then falls back to the active profile from policy.sexp.
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

/// Load policy.sexp, compile the named profile, and generate a sandbox policy.
///
/// If `profile_name` is empty, uses the active profile's `default.profile`.
fn load_sandbox_for_profile(profile_name: &str, cwd: &str) -> Result<SandboxPolicy> {
    use crate::policy::parse::parse_policy;
    use crate::policy::{CompiledPolicy, DefaultConfig, Effect};
    use crate::settings::ClashSettings;

    let path = ClashSettings::policy_file()?;
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let mut doc =
        parse_policy(&text).with_context(|| format!("failed to parse {}", path.display()))?;

    // Resolve the profile name: empty means use the configured default.
    let resolved_name = if profile_name.is_empty() {
        doc.default_config
            .as_ref()
            .map(|dc| dc.profile.clone())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no default profile configured in {}; specify a profile name explicitly",
                    path.display()
                )
            })?
    } else {
        profile_name.to_string()
    };

    // Override the active profile to the requested one.
    let permission = doc
        .default_config
        .as_ref()
        .map(|dc| dc.permission)
        .unwrap_or(Effect::Ask);
    doc.default_config = Some(DefaultConfig {
        permission,
        profile: resolved_name.clone(),
    });

    let compiled = CompiledPolicy::compile(&doc).context("failed to compile policy")?;

    compiled.sandbox_for_active_profile(cwd).ok_or_else(|| {
        anyhow::anyhow!(
            "profile '{}' has no sandbox-relevant constraints (no fs rules found)",
            resolved_name
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
            match sandbox::exec_sandboxed(&sandbox_policy, &cwd_path, &command) {
                Err(e) => anyhow::bail!("sandbox exec failed: {}", e),
            }
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

            match sandbox::exec_sandboxed(&sandbox_policy, &cwd_path, &command) {
                Err(e) => anyhow::bail!("sandbox test failed: {}", e),
            }
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
