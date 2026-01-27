#![allow(dead_code)]

use std::fmt::Display;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use claude_settings::{ClaudeSettings, SettingsLevel};
use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System};

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
    #[command(
        about = "install clash hooks for claude. Note, hooks only work when installed at the user or project level.
Project-local hooks appear to be ignored for now."
    )]
    Install {
        #[arg(long, short, default_value_t)]
        level: LevelArg,
    },
    #[command(about = "uninstall clash hooks for claude")]
    Uninstall {
        #[arg(long, short, default_value_t)]
        level: LevelArg,
    },
    #[command(
        about = "enter a subshell with clash hooks installed. Will be removed when parent shell exits."
    )]
    Enter {
        #[arg(long, short, default_value_t)]
        level: LevelArg,
    },
    #[command(about = "get the status of clash configuration on your system")]
    Status {
        #[arg(long, short, default_value = "false")]
        verbose: bool,
    },
    #[command(subcommand, about = "commands for agents to call back into clash")]
    Hook(HooksCmd),
}

fn current_shell() -> anyhow::Result<String> {
    let sys = System::new_with_specifics(
        RefreshKind::nothing()
            .with_processes(ProcessRefreshKind::nothing().with_exe(sysinfo::UpdateKind::Always)),
    );
    let proc = sys
        .process(Pid::from_u32(std::os::unix::process::parent_id()))
        .context("can't get parent process")?;
    proc.exe()
        .and_then(|x| x.to_str())
        .map(|s| s.to_string())
        .context("unable to get parent executable")
}

fn run_shell() -> Result<()> {
    let shell = current_shell()?;

    println!("Starting shell: {shell}");

    let status = std::process::Command::new(&shell).spawn()?.wait()?;

    if !status.success() {
        match status.code() {
            Some(code) => eprintln!("subshell exited with non-zero code: {}", code),
            None => eprintln!(
                "subshell exited without a return code. Probably killed by external signal"
            ),
        }
    }

    Ok(())
}

const DEFAULT_BACKUP_SUFFIX: &str = "bak";

fn install_and_backup(level: SettingsLevel) -> anyhow::Result<()> {
    let manager = ClaudeSettings::new();
    // TODO(eliot): with_clash_installed is just a marker for now so we can tell it things are "owned by clash".
    // Actual hook installation will be later
    let mut settings = manager.read_or_default(level)?.with_clash_installed();
    let hooks = settings.hooks.get_or_insert_default();
    let pre = hooks.pre_tool_use.clone().unwrap_or_default();
    hooks.pre_tool_use = Some(pre.insert(
        "*",
        &format!(
            "{} hook can-run",
            std::env::current_exe()?.to_string_lossy()
        ),
    ));
    manager.write_with_backup(level, &settings, DEFAULT_BACKUP_SUFFIX)?;
    Ok(())
}

fn restore_from_backup(level: SettingsLevel) -> anyhow::Result<()> {
    let manager = ClaudeSettings::new();
    manager.restore_from_backup(level, DEFAULT_BACKUP_SUFFIX)?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.verbose {
        eprintln!("Verbose mode enabled");
    }

    match cli.command {
        Commands::Enter { level } => {
            install_and_backup(level.into())?;
            eprintln!("entering subshell with clash hooks installed");
            // TODO(eliot): handle custom args or running single commands like "claude" rather than just dropping into a sub-shell
            let res = run_shell();
            eprintln!("exiting subshell. Uninstalling clash hooks");
            restore_from_backup(level.into())?;
            res?;
        }
        Commands::Install { level } => {
            eprintln!("WARNING: 'clash install' is deprecated.");
            eprintln!("Consider using the clash Claude Code plugin instead:");
            eprintln!("  claude --plugin-dir /path/to/clash-plugin");
            eprintln!("");
            install_and_backup(level.into())?;
        }
        Commands::Uninstall { level } => {
            eprintln!("WARNING: 'clash uninstall' is deprecated.");
            eprintln!("If using the clash plugin, simply remove it from your plugin directory.");
            eprintln!("");
            restore_from_backup(level.into())?;
        }
        Commands::Status { verbose } => {
            let manager = ClaudeSettings::new();

            for level in SettingsLevel::all_by_priority() {
                match manager.read(*level) {
                    Ok(Some(settings)) => {
                        println!(
                            "{}:{}",
                            level.name(),
                            if settings.is_clash_installed() {
                                "installed"
                            } else {
                                "not installed"
                            }
                        );

                        if verbose {
                            eprintln!("{settings:#?}");
                        }
                    }
                    Ok(None) => println!("{}:unset", level.name()),
                    Err(err) => {
                        eprintln!("Unable to read {} settings. {err}", level.name());
                    }
                }
            }
        }
        Commands::Hook(hook_cmd) => {
            if let Err(e) = hook_cmd.run() {
                eprintln!("Hook error: {}", e);
                std::process::exit(exit_code::BLOCKING_ERROR);
            }
        }
    }

    Ok(())
}
