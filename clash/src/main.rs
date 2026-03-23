use anyhow::Result;
use clap::Parser;
use tracing::{debug_span, error};

use clash::cli::{Cli, Commands};
use clash::cmd;
use clash::hooks::exit_code;
use clash::sandbox_cmd::run_sandbox;
use clash::tracing_init::init_tracing;

fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    debug_span!("main", cmd = ?cli.command).in_scope(|| {
        let resp = match cli.command {
            Commands::Init { no_bypass, scope, quick } => cmd::init::run(no_bypass, scope, quick),
            Commands::Uninstall { yes } => cmd::uninstall::run(yes),
            Commands::Status { json } => cmd::status::run(json, cli.verbose),
            Commands::ShowCommands { json, all } => cmd::commands::run(json, all),
            Commands::Explain {
                json,
                trace,
                tool,
                args,
            } => {
                let input = args.join(" ");
                cmd::explain::run(json, trace, tool, input)
            }
            Commands::Fmt { check, files } => cmd::fmt::run(check, files),
            Commands::Policy(policy_cmd) => cmd::policy::run(policy_cmd),
            Commands::Shell {
                command,
                cwd,
                sandbox,
                debug,
                args,
            } => clash::shell_cmd::run_shell(command, args, cwd, sandbox, debug),
            Commands::Sandbox(sandbox_cmd) => run_sandbox(sandbox_cmd),
            Commands::Playground => cmd::playground::run(),
            Commands::Doctor => cmd::doctor::run(),
            Commands::Debug(cmd) => cmd::debug::run(cmd),
            Commands::Trace(cmd) => cmd::trace::run(cmd),
            Commands::Session(cmd) => cmd::session::run(cmd),
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
                include_trace,
            } => cmd::bug::run(
                title,
                description,
                include_config,
                include_logs,
                include_trace,
            ),
        };
        if let Err(err) = resp {
            error!("{:?}", err);
            clash::errors::display_error(&err, cli.verbose);
            std::process::exit(1);
        }
    });

    Ok(())
}
