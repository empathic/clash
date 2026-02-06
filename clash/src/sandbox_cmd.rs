use crate::policy::sandbox_types::SandboxPolicy;
use crate::sandbox;
use anyhow::{Context, Result};
use clap::Subcommand;
use tracing::{Level, instrument};

#[derive(Subcommand, Debug)]
pub enum SandboxCmd {
    /// Apply sandbox restrictions and exec a command
    Exec {
        /// Sandbox policy as JSON string
        #[arg(long)]
        policy: String,

        /// Working directory for path resolution
        #[arg(long)]
        cwd: String,

        /// Command and arguments to execute under sandbox
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Test sandbox enforcement interactively
    Test {
        /// Sandbox policy as JSON string
        #[arg(long)]
        policy: String,

        /// Working directory for path resolution
        #[arg(long)]
        cwd: String,

        /// Command and arguments to test
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Check if sandboxing is supported on this platform
    Check,
}

/// Parse shared sandbox arguments (policy JSON + cwd).
fn parse_sandbox_args(policy_json: &str, cwd: &str) -> Result<(SandboxPolicy, std::path::PathBuf)> {
    let policy: SandboxPolicy =
        serde_json::from_str(policy_json).context("failed to parse --policy JSON")?;
    Ok((policy, std::path::PathBuf::from(cwd)))
}

/// Run a command inside a sandbox.
#[instrument(level = Level::TRACE)]
pub fn run_sandbox(cmd: SandboxCmd) -> Result<()> {
    match cmd {
        SandboxCmd::Exec {
            policy,
            cwd,
            command,
        } => {
            let (policy, cwd_path) = parse_sandbox_args(&policy, &cwd)?;
            // This does not return on success (replaces the process via execvp)
            match sandbox::exec_sandboxed(&policy, &cwd_path, &command) {
                Err(e) => anyhow::bail!("sandbox exec failed: {}", e),
            }
        }
        SandboxCmd::Test {
            policy,
            cwd,
            command,
        } => {
            let (policy, cwd_path) = parse_sandbox_args(&policy, &cwd)?;

            eprintln!("Testing sandbox with policy:");
            eprintln!("  default: {}", policy.default.display());
            eprintln!("  network: {:?}", policy.network);
            for rule in &policy.rules {
                eprintln!(
                    "  {:?} {} in {}",
                    rule.effect,
                    rule.caps.display(),
                    rule.path
                );
            }
            eprintln!("  command: {:?}", command);
            eprintln!("---");

            match sandbox::exec_sandboxed(&policy, &cwd_path, &command) {
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
