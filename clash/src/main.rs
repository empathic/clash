use std::fmt::Display;
use std::fs::OpenOptions;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use claude_settings::SettingsLevel;
use tracing::{error, info};
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
                .with_level(true)
                .with_writer(log_file)
                .with_file(true)
                .with_line_number(true)
                .with_thread_ids(true)
                .with_target(false)
                .with_span_events(FmtSpan::CLOSE)
                .with_ansi(true)
                .compact(),
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
    }

    Ok(())
}
