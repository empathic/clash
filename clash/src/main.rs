use std::fmt::Display;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use claude_settings::{ClaudeSettings, SettingsLevel};

mod hooks;
mod permissions;

use claude_settings::PermissionRule;
use hooks::{HookInput, HookOutput, exit_code};
use permissions::check_permission;

#[derive(Parser)]
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

#[derive(Subcommand)]
enum HooksCmd {
    #[command(about = "get the status of clash configuration on your system")]
    CanRun {
        /// Arguments
        #[arg(long, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<String>,
    },
}

impl HooksCmd {
    fn run(&self) -> anyhow::Result<()> {
        let settings = ClaudeSettings::new().effective()?;
        match self {
            Self::CanRun { args: _ } => {
                let input = HookInput::from_stdin()?;
                let decision = check_permission(&input, &settings)?;

                let output = match decision {
                    PermissionRule::Allow => HookOutput::allow(None),
                    PermissionRule::Deny => HookOutput::deny("Denied by clash policy".into()),
                    PermissionRule::Ask | PermissionRule::Unset => HookOutput::ask(None),
                };

                output.write_stdout()?;
                std::process::exit(exit_code::SUCCESS);
            }
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    #[command(subcommand, about = "commands for agents to call back into clash")]
    Hook(HooksCmd),
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.verbose {
        eprintln!("Verbose mode enabled");
    }

    match cli.command {
        Commands::Hook(hook_cmd) => {
            if let Err(e) = hook_cmd.run() {
                eprintln!("Hook error: {}", e);
                std::process::exit(exit_code::BLOCKING_ERROR);
            }
        }
    }

    Ok(())
}
