use std::fmt::Display;
use std::fs::OpenOptions;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use claude_settings::SettingsLevel;
use claude_settings::policy::parse::{desugar_legacy, format_rule};
use claude_settings::policy::{Effect, LegacyPermissions, PolicyConfig, PolicyDocument};
use tracing::{error, info};
use tracing_subscriber::fmt::FormatFields;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::prelude::*;

mod hooks;
mod notifications;
mod permissions;
mod sandbox;
mod settings;

use claude_settings::PermissionRule;
use claude_settings::sandbox::SandboxPolicy;
use hooks::{HookOutput, HookSpecificOutput, NotificationHookInput, ToolUseHookInput, exit_code};
use permissions::check_permission;

#[derive(Parser, Debug)]
#[command(name = "clash")]
#[command(about = "Claude shell")]
struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Debug, Default, Copy, ValueEnum)]
#[value(rename_all = "kebab_case")]
enum LevelArg {
    #[default]
    User,
    ProjectLocal,
    Project,
}

impl Display for LevelArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            LevelArg::User => "user",
            LevelArg::ProjectLocal => "project-local",
            LevelArg::Project => "project",
        };
        write!(f, "{}", s)
    }
}

impl From<LevelArg> for SettingsLevel {
    fn from(val: LevelArg) -> Self {
        match val {
            LevelArg::User => SettingsLevel::User,
            LevelArg::ProjectLocal => SettingsLevel::ProjectLocal,
            LevelArg::Project => SettingsLevel::Project,
        }
    }
}

#[derive(Subcommand, Debug)]
enum HooksCmd {
    /// Handle PreToolUse hook - called before a tool is executed
    #[command(name = "pre-tool-use")]
    PreToolUse,

    /// Handle PostToolUse hook - called after a tool is executed
    #[command(name = "post-tool-use")]
    PostToolUse,

    /// Handle PermissionRequest hook - respond to permission prompts on behalf of user
    #[command(name = "permission-request")]
    PermissionRequest,

    /// Handle Notification hook - informational events from Claude Code
    #[command(name = "notification")]
    Notification,
}

impl HooksCmd {
    fn run(&self) -> anyhow::Result<()> {
        let settings = settings::ClashSettings::load_or_create()?;

        let output = match self {
            Self::PreToolUse => {
                let input = ToolUseHookInput::from_reader(std::io::stdin().lock())?;
                check_permission(&input, &settings)?
            }
            Self::PostToolUse => {
                let _input = ToolUseHookInput::from_reader(std::io::stdin().lock())?;
                // PostToolUse is informational - just continue
                // Could be extended to log tool results, update state, etc.
                HookOutput::continue_execution()
            }
            Self::PermissionRequest => {
                let input = ToolUseHookInput::from_reader(std::io::stdin().lock())?;
                // Decide whether to approve or deny the permission request
                handle_permission_request(&input, &settings)?
            }
            Self::Notification => {
                let _input = NotificationHookInput::from_reader(std::io::stdin().lock())?;
                // Notifications are informational - just continue
                // Could be extended to send desktop notifications, etc.
                HookOutput::continue_execution()
            }
        };

        output.write_stdout()?;
        std::process::exit(exit_code::SUCCESS);
    }
}

/// Handle a permission request - decide whether to approve or deny on behalf of user
fn handle_permission_request(
    input: &ToolUseHookInput,
    settings: &settings::ClashSettings,
) -> anyhow::Result<HookOutput> {
    let pre_tool_result = check_permission(input, settings)?;

    // Convert PreToolUse decision to PermissionRequest format.
    // Claude Code validates that hookEventName matches the event type.
    Ok(match pre_tool_result.hook_specific_output {
        Some(HookSpecificOutput::PreToolUse(ref pre)) => match pre.permission_decision {
            Some(PermissionRule::Allow) => HookOutput::approve_permission(None),
            Some(PermissionRule::Deny) => {
                let reason = pre
                    .permission_decision_reason
                    .clone()
                    .unwrap_or_else(|| "denied by policy".into());
                HookOutput::deny_permission(reason, false)
            }
            // Ask or no decision: don't respond, let the user decide
            _ => HookOutput::continue_execution(),
        },
        _ => pre_tool_result,
    })
}

#[derive(Subcommand, Debug)]
enum SandboxCmd {
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

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(subcommand, about = "commands for agents to call back into clash")]
    Hook(HooksCmd),

    /// Apply sandbox restrictions and exec commands
    #[command(subcommand)]
    Sandbox(SandboxCmd),

    /// Launch Claude Code with clash managing hooks and sandbox enforcement
    Launch {
        /// Path to policy file (default: ~/.clash/policy.yaml)
        #[arg(long)]
        policy: Option<String>,

        /// Arguments to pass through to Claude Code
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Migrate legacy Claude Code permissions to a policy.yaml file
    Migrate {
        /// Print generated policy to stdout instead of writing to ~/.clash/policy.yaml
        #[arg(long)]
        dry_run: bool,

        /// Override the default effect for unmatched requests (ask, deny)
        #[arg(long, default_value = "ask")]
        default: String,
    },
}

fn init_tracing() {
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/clash.log")
        .expect("failed to open /tmp/clash.log");

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .pretty()
                .with_level(true)
                .with_writer(log_file)
                .with_file(true)
                .with_line_number(true)
                .with_target(false)
                .with_span_events(FmtSpan::CLOSE)
                .with_ansi(true),
        )
        .init();
}

fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    info!(args = ?std::env::args(), "clash started");

    match cli.command {
        Commands::Hook(hook_cmd) => {
            if let Err(e) = hook_cmd.run() {
                error!(cmd=?hook_cmd, "Hook error: {}", e);
                std::process::exit(exit_code::BLOCKING_ERROR);
            }
        }
        Commands::Sandbox(sandbox_cmd) => {
            if let Err(e) = run_sandbox(sandbox_cmd) {
                error!("Sandbox error: {}", e);
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Launch { policy, args } => {
            if let Err(e) = run_launch(policy, args) {
                error!("Launch error: {}", e);
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Migrate { dry_run, default } => {
            if let Err(e) = run_migrate(dry_run, &default) {
                error!("Migration error: {}", e);
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

/// Run a command inside a sandbox.
fn run_sandbox(cmd: SandboxCmd) -> Result<()> {
    match cmd {
        SandboxCmd::Exec { policy, cwd, command } => {
            let policy: SandboxPolicy = serde_json::from_str(&policy)
                .context("failed to parse --policy JSON")?;
            let cwd_path = std::path::Path::new(&cwd);

            // This does not return on success (replaces the process via execvp)
            match sandbox::exec_sandboxed(&policy, cwd_path, &command) {
                Err(e) => anyhow::bail!("sandbox exec failed: {}", e),
                // exec_sandboxed returns Infallible on success, so Ok is unreachable
            }
        }
        SandboxCmd::Test { policy, cwd, command } => {
            let policy: SandboxPolicy = serde_json::from_str(&policy)
                .context("failed to parse --policy JSON")?;
            let cwd_path = std::path::Path::new(&cwd);

            eprintln!("Testing sandbox with policy:");
            eprintln!("  default: {}", policy.default.display());
            eprintln!("  network: {:?}", policy.network);
            for rule in &policy.rules {
                eprintln!("  {:?} {} in {}", rule.effect, rule.caps.display(), rule.path);
            }
            eprintln!("  command: {:?}", command);
            eprintln!("---");

            match sandbox::exec_sandboxed(&policy, cwd_path, &command) {
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

/// Launch Claude Code with clash managing hooks and sandbox enforcement.
fn run_launch(policy_path: Option<String>, args: Vec<String>) -> Result<()> {
    // Resolve the clash binary path for hook commands
    let clash_bin = std::env::current_exe()
        .context("failed to determine clash binary path")?;
    let clash_bin_str = clash_bin.to_string_lossy();

    // Validate that we have a policy if one was specified
    if let Some(ref path) = policy_path {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read policy file: {}", path))?;
        // Validate it parses
        claude_settings::policy::parse::parse_yaml(&contents)
            .with_context(|| format!("failed to parse policy file: {}", path))?;
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
            "Notification": [{
                "hooks": [{
                    "type": "command",
                    "command": format!("{} hook notification", clash_bin_str),
                    "matcher": "*"
                }]
            }]
        }
    });

    // Write hooks to a temp file that Claude Code can use
    let hooks_dir = settings::ClashSettings::settings_dir().join("hooks");
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

/// Migrate legacy Claude Code permissions to a policy.yaml file.
///
/// Reads the effective Claude Code settings, desugars the permission rules
/// into policy statements, and writes a `policy.yaml` file.
fn run_migrate(dry_run: bool, default_effect: &str) -> Result<()> {
    let default = match default_effect {
        "ask" => Effect::Ask,
        "deny" => Effect::Deny,
        "allow" => Effect::Allow,
        other => anyhow::bail!(
            "invalid default effect '{}': expected ask, deny, or allow",
            other
        ),
    };

    // Load existing Claude Code settings
    let claude = claude_settings::ClaudeSettings::new();
    let effective = claude
        .effective()
        .context("failed to load Claude Code settings")?;

    // Convert PermissionSet to Permissions (string lists), then to LegacyPermissions
    let perms = effective.permissions.to_permissions();
    let legacy = LegacyPermissions {
        allow: perms.allow,
        deny: perms.deny,
        ask: perms.ask,
    };

    let statements = desugar_legacy(&legacy);

    if statements.is_empty() {
        println!("No legacy permissions found to migrate.");
        return Ok(());
    }

    // Build the policy document
    let doc = PolicyDocument {
        policy: PolicyConfig { default },
        permissions: None,
        constraints: Default::default(),
        profiles: Default::default(),
        statements,
    };

    // Build YAML output with header comment
    let mut output = String::new();
    output.push_str("# Policy generated by `clash migrate` from Claude Code settings.\n");
    output.push_str("# Review and customize as needed.\n");
    output.push_str("#\n");
    output.push_str(
        "# Evaluation: all matching statements are collected, then precedence applies:\n",
    );
    output.push_str("#   deny > ask > allow\n");
    output.push_str("# If no statement matches, the default effect is used.\n");
    output.push('\n');
    output.push_str(&format!("default: {}\n", doc.policy.default));
    output.push('\n');
    output.push_str("rules:\n");
    for stmt in &doc.statements {
        output.push_str(&format!("  - {}\n", format_rule(stmt)));
    }

    if dry_run {
        print!("{}", output);
    } else {
        let path = settings::ClashSettings::policy_file();
        if path.exists() {
            eprintln!(
                "Warning: {} already exists. Use --dry-run to preview, or remove the file first.",
                path.display()
            );
            anyhow::bail!("policy.yaml already exists at {}", path.display());
        }
        std::fs::create_dir_all(settings::ClashSettings::settings_dir())?;
        std::fs::write(&path, &output)?;
        println!("Wrote policy to {}", path.display());
        println!(
            "Migrated {} rule(s) from legacy Claude Code permissions.",
            doc.statements.len()
        );
    }

    Ok(())
}
