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
mod settings;

use hooks::{HookOutput, NotificationHookInput, ToolUseHookInput, exit_code};
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
    // Use the same permission checking logic, but return PermissionRequest responses
    let pre_tool_result = check_permission(input, settings)?;

    // Convert PreToolUse decision to PermissionRequest decision
    // If PreToolUse would allow, approve the permission request
    // If PreToolUse would deny, deny the permission request
    // If PreToolUse would ask, don't respond (let user decide)
    Ok(pre_tool_result)
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(subcommand, about = "commands for agents to call back into clash")]
    Hook(HooksCmd),

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
