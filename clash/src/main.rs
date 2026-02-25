use anyhow::Result;
use clap::Parser;
use tracing::{debug_span, error, info};

use clash::cli::{Cli, Commands};
use clash::cmd;
use clash::hooks::exit_code;
use clash::policy::Effect;
use clash::sandbox_cmd::run_sandbox;
use clash::tracing_init::init_tracing;

fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    info!(args = ?std::env::args(), "clash started");

    debug_span!("main", cmd = ?cli.command).in_scope(|| {
        let resp = match cli.command {
            Commands::Init { no_bypass, scope } => cmd::init::run(no_bypass, scope),
            Commands::Status { json } => cmd::status::run(json, cli.verbose),
            Commands::Allow {
                rule,
                dry_run,
                scope,
            } => cmd::policy::handle_allow_deny(Effect::Allow, &rule, dry_run, scope.as_deref()),
            Commands::Deny {
                rule,
                dry_run,
                scope,
            } => cmd::policy::handle_allow_deny(Effect::Deny, &rule, dry_run, scope.as_deref()),
            Commands::Ask {
                rule,
                dry_run,
                scope,
            } => cmd::policy::handle_allow_deny(Effect::Ask, &rule, dry_run, scope.as_deref()),
            Commands::Amend {
                rules,
                remove,
                dry_run,
                scope,
            } => cmd::policy::handle_amend(rules, remove, dry_run, scope.as_deref()),
            Commands::Edit { dry_run, scope } => {
                clash::shell::ShellSession::new(scope.as_deref(), dry_run, true)
                    .and_then(|mut s| s.run_interactive())
            }
            Commands::ShowCommands { json, all } => cmd::commands::run(json, all),
            Commands::Explain { json, tool, args } => {
                let input = if args.is_empty() {
                    None
                } else {
                    Some(args.join(" "))
                };
                cmd::explain::run(json, Some(tool), input)
            }
            Commands::Policy(policy_cmd) => cmd::policy::run(policy_cmd),
            Commands::Sandbox(sandbox_cmd) => run_sandbox(sandbox_cmd),
            Commands::Doctor => cmd::doctor::run(),
            Commands::Hook(hook_cmd) => {
                if let Err(e) = hook_cmd.run() {
                    error!(cmd=?hook_cmd, "Hook error: {:?}", e);
                    clash::errors::display_error(&e, cli.verbose);
                    std::process::exit(exit_code::BLOCKING_ERROR);
                }
                Ok(())
            }
            Commands::Update {
                check,
                yes,
                version,
            } => cmd::update::run(check, yes, version),
            Commands::Statusline(cmd) => cmd::statusline::run(cmd),
            Commands::Launch { policy, args } => cmd::launch::run(policy, args),
            Commands::Bug {
                title,
                description,
                include_config,
                include_logs,
            } => cmd::bug::run(title, description, include_config, include_logs),
        };
        if let Err(err) = resp {
            error!("{:?}", err);
            clash::errors::display_error(&err, cli.verbose);
            std::process::exit(1);
        }
    });

    Ok(())
}
