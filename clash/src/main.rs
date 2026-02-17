use std::fs::OpenOptions;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use clash::policy::Effect;
use dialoguer::Confirm;
use tracing::level_filters::LevelFilter;
use tracing::{Level, debug_span, error, info, instrument, warn};
use tracing_subscriber::Layer;
use tracing_subscriber::prelude::*;

use clash::handlers;
use clash::hooks::{HookOutput, ToolUseHookInput, exit_code};
use clash::permissions::check_permission;
use clash::sandbox_cmd;
use clash::settings::{ClashSettings, DEFAULT_POLICY, PolicyLevel};

use sandbox_cmd::{SandboxCmd, run_sandbox};

#[derive(Parser, Debug)]
#[command(name = "clash")]
#[command(about = "Command line agent safety harness")]
struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
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

    /// Handle SessionStart hook - called when a Claude Code session begins
    #[command(name = "session-start")]
    SessionStart,
}

impl HooksCmd {
    #[instrument(level = Level::TRACE, skip(self))]
    fn run(&self) -> anyhow::Result<()> {
        let output = match self {
            Self::PreToolUse => {
                let input = ToolUseHookInput::from_reader(std::io::stdin().lock())?;
                let settings = ClashSettings::load_or_create_with_session(Some(&input.session_id))?;
                check_permission(&input, &settings)?
            }
            Self::PostToolUse => {
                let _input = ToolUseHookInput::from_reader(std::io::stdin().lock())?;
                // PostToolUse is informational - just continue
                HookOutput::continue_execution()
            }
            Self::PermissionRequest => {
                let input = ToolUseHookInput::from_reader(std::io::stdin().lock())?;
                let settings = ClashSettings::load_or_create_with_session(Some(&input.session_id))?;
                handlers::handle_permission_request(&input, &settings)?
            }
            Self::SessionStart => {
                let input =
                    clash::hooks::SessionStartHookInput::from_reader(std::io::stdin().lock())?;
                handlers::handle_session_start(&input)?
            }
        };

        output.write_stdout()?;
        Ok(())
    }
}

#[derive(Subcommand, Debug)]
enum PolicyCmd {
    /// Add an allow rule (bare verb like "edit" or s-expr like '(exec "git" *)')
    Allow {
        /// S-expr rule body or bare verb (edit, bash, read, web)
        rule: String,
        /// Print modified policy to stdout without writing
        #[arg(long)]
        dry_run: bool,
        /// Policy level to modify: "user" or "project"
        #[arg(long)]
        scope: Option<String>,
    },
    /// Add a deny rule (bare verb like "bash" or s-expr like '(exec "git" "push" *)')
    Deny {
        /// S-expr rule body or bare verb (bash, edit, read, web)
        rule: String,
        #[arg(long)]
        dry_run: bool,
        /// Policy level to modify: "user" or "project"
        #[arg(long)]
        scope: Option<String>,
    },
    /// Add an ask rule (requires approval before executing)
    Ask {
        /// S-expr rule body or bare verb (bash, edit, read, web)
        rule: String,
        #[arg(long)]
        dry_run: bool,
        /// Policy level to modify: "user" or "project"
        #[arg(long)]
        scope: Option<String>,
    },
    /// Remove a rule from the policy
    Remove {
        /// Rule text to remove (Display form, e.g. '(deny (exec "git" "push" *))')
        rule: String,
        #[arg(long)]
        dry_run: bool,
        /// Policy level to modify: "user" or "project"
        #[arg(long)]
        scope: Option<String>,
    },
    /// List rules in the active policy
    List {
        #[arg(long)]
        json: bool,
    },
    // --- Hidden/power-user subcommands ---
    /// Show policy summary: active policy, default effect, rule count
    #[command(hide = true)]
    Show {
        #[arg(long)]
        json: bool,
    },
    /// Show the full schema of policy settings
    #[command(hide = true)]
    Schema {
        #[arg(long)]
        json: bool,
    },
    /// Explain which policy rule would match a given tool invocation
    #[command(hide = true)]
    Explain {
        /// Output as JSON instead of human-readable text
        #[arg(long)]
        json: bool,
        /// Tool type: bash, read, write, edit (or full tool name like Bash, Read, etc.)
        tool: Option<String>,
        /// The command, file path, or noun to check (remaining args joined)
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
#[allow(clippy::enum_variant_names)]
enum Commands {
    /// Initialize a new clash policy with a safe default configuration
    Init {
        /// Skip setting bypassPermissions in Claude Code settings
        #[arg(long)]
        no_bypass: Option<bool>,
        /// Initialize a project-level policy instead of user-level
        #[arg(long)]
        project: Option<bool>,
    },

    /// Show policy status: layers, rules with shadowing, and potential issues
    Status {
        /// Output as JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },

    /// Allow a capability (bash, edit, read, web) or s-expr rule
    Allow {
        /// Verb or s-expr rule
        rule: String,
        #[arg(long)]
        dry_run: bool,
        /// Policy level to modify: "user" or "project"
        #[arg(long)]
        scope: Option<String>,
    },

    /// Deny a capability (bash, edit, read, web) or s-expr rule
    Deny {
        /// Verb or s-expr rule
        rule: String,
        #[arg(long)]
        dry_run: bool,
        /// Policy level to modify: "user" or "project"
        #[arg(long)]
        scope: Option<String>,
    },

    /// Require approval for a capability (bash, edit, read, web) or s-expr rule
    Ask {
        /// Verb or s-expr rule
        rule: String,
        #[arg(long)]
        dry_run: bool,
        /// Policy level to modify: "user" or "project"
        #[arg(long)]
        scope: Option<String>,
    },

    /// Interactive policy editor
    Edit,

    /// View and edit policy rules
    #[command(subcommand)]
    Policy(PolicyCmd),

    /// Print the full command and subcommand hierarchy
    #[command(name = "commands")]
    ShowCommands {
        /// Output as JSON (for programmatic use by skills/agents)
        #[arg(long)]
        json: bool,
        /// Include hidden/internal commands
        #[arg(long)]
        all: bool,
    },

    /// Apply sandbox restrictions and exec commands
    #[command(subcommand)]
    Sandbox(SandboxCmd),

    // --- Hidden/internal commands ---
    /// Agent hook callbacks
    #[command(subcommand, hide = true)]
    Hook(HooksCmd),

    /// Launch Claude Code with clash managing hooks and sandbox enforcement
    #[command(hide = true)]
    Launch {
        /// Path to policy file (default: ~/.clash/policy.sexpr)
        #[arg(long)]
        policy: Option<String>,

        /// Arguments to pass through to Claude Code
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Explain which policy rule would match a given tool invocation
    Explain {
        /// Output as JSON instead of human-readable text
        #[arg(long)]
        json: bool,
        /// Tool type: bash, read, write, edit (or full tool name like Bash, Read, etc.)
        tool: String,
        /// The command, file path, or noun to check (remaining args joined)
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// File a bug report to the clash issue tracker
    #[command(alias = "rage", hide = true)]
    Bug {
        /// Short summary of the bug
        title: String,
        /// Detailed description of the bug
        #[arg(short, long)]
        description: Option<String>,
        /// Include the clash policy config in the report
        #[arg(long)]
        include_config: bool,
        /// Include recent debug logs in the report
        #[arg(long)]
        include_logs: bool,
    },
}

fn init_tracing() {
    // Log path: CLASH_LOG env var > ~/.clash/clash.log > stderr fallback.
    let log_path = std::env::var("CLASH_LOG").ok().unwrap_or_else(|| {
        ClashSettings::settings_dir()
            .map(|d| d.join("clash.log"))
            .unwrap_or_else(|_| std::path::PathBuf::from("clash.log"))
            .to_string_lossy()
            .into_owned()
    });

    // Ensure parent directory exists.
    let log_file = std::path::Path::new(&log_path)
        .parent()
        .and_then(|parent| std::fs::create_dir_all(parent).ok())
        .and_then(|_| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .ok()
        });

    let layer: Box<dyn Layer<_> + Send + Sync> = match log_file {
        Some(file) => tracing_subscriber::fmt::layer()
            .with_writer(file)
            .pretty()
            .with_ansi(false)
            .with_filter(LevelFilter::from_level(Level::DEBUG))
            .boxed(),
        None => {
            // Fallback to stderr if log file can't be opened.
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .pretty()
                .with_ansi(false)
                .with_filter(LevelFilter::from_level(Level::INFO))
                .boxed()
        }
    };

    tracing_subscriber::registry().with(layer).init()
}

fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    info!(args = ?std::env::args(), "clash started");

    debug_span!("main", cmd = ?cli.command).in_scope(|| {
        let resp = match cli.command {
            Commands::Init { no_bypass, project } => run_init(no_bypass, project),
            Commands::Status { json } => run_status(json),
            Commands::Allow {
                rule,
                dry_run,
                scope,
            } => handle_allow_deny(Effect::Allow, &rule, dry_run, scope.as_deref()),
            Commands::Deny {
                rule,
                dry_run,
                scope,
            } => handle_allow_deny(Effect::Deny, &rule, dry_run, scope.as_deref()),
            Commands::Ask {
                rule,
                dry_run,
                scope,
            } => handle_allow_deny(Effect::Ask, &rule, dry_run, scope.as_deref()),
            Commands::Edit => clash::wizard::run(),
            Commands::ShowCommands { json, all } => run_commands(json, all),
            Commands::Explain { json, tool, args } => {
                let input = if args.is_empty() {
                    None
                } else {
                    Some(args.join(" "))
                };
                run_explain(json, Some(tool), input)
            }
            Commands::Policy(cmd) => run_policy(cmd),
            Commands::Sandbox(cmd) => run_sandbox(cmd),
            Commands::Hook(hook_cmd) => {
                if let Err(e) = hook_cmd.run() {
                    error!(cmd=?hook_cmd, "Hook error: {:?}", e);
                    clash::errors::display_error(&e, cli.verbose);
                    std::process::exit(exit_code::BLOCKING_ERROR);
                }
                Ok(())
            }
            Commands::Launch { policy, args } => run_launch(policy, args),
            Commands::Bug {
                title,
                description,
                include_config,
                include_logs,
            } => run_bug_report(title, description, include_config, include_logs),
        };
        if let Err(err) = resp {
            error!("{:?}", err);
            clash::errors::display_error(&err, cli.verbose);
            std::process::exit(1);
        }
    });

    Ok(())
}

/// Launch Claude Code with clash managing hooks and sandbox enforcement.
#[instrument(level = Level::TRACE)]
fn run_launch(policy_path: Option<String>, args: Vec<String>) -> Result<()> {
    // Resolve the clash binary path for hook commands
    let clash_bin = std::env::current_exe().context("failed to determine clash binary path")?;
    let clash_bin_str = clash_bin.to_string_lossy();

    // Validate that we have a policy if one was specified
    if let Some(ref path) = policy_path {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read policy file: {}", path))?;
        clash::policy::compile_policy(&contents)
            .with_context(|| format!("failed to compile policy file: {}", path))?;
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
            "SessionStart": [{
                "hooks": [{
                    "type": "command",
                    "command": format!("{} hook session-start", clash_bin_str),
                }]
            }],
        }
    });

    // Write hooks to a temp file that Claude Code can use
    let hooks_dir = ClashSettings::settings_dir()?.join("hooks");
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

/// Print the full command + subcommand hierarchy.
fn run_commands(json: bool, show_all: bool) -> Result<()> {
    use clap::CommandFactory;
    let cmd = Cli::command();

    if json {
        let tree = command_to_json(&cmd, show_all);
        println!("{}", serde_json::to_string_pretty(&tree)?);
    } else {
        print_command_tree(&cmd, 0, show_all);
    }
    Ok(())
}

fn command_to_json(cmd: &clap::Command, show_all: bool) -> serde_json::Value {
    let args: Vec<serde_json::Value> = cmd
        .get_arguments()
        .filter(|a| a.get_id() != "help" && a.get_id() != "version")
        .map(|a| {
            let mut obj = serde_json::json!({
                "name": a.get_id().to_string(),
                "required": a.is_required_set(),
            });
            if let Some(short) = a.get_short() {
                obj["short"] = serde_json::json!(format!("-{short}"));
            }
            if let Some(long) = a.get_long() {
                obj["long"] = serde_json::json!(format!("--{long}"));
            }
            if let Some(help) = a.get_help() {
                obj["help"] = serde_json::json!(help.to_string());
            }
            obj
        })
        .collect();

    let subcommands: Vec<serde_json::Value> = cmd
        .get_subcommands()
        .filter(|s| s.get_name() != "help" && (show_all || !s.is_hide_set()))
        .map(|s| command_to_json(s, show_all))
        .collect();

    let mut obj = serde_json::json!({
        "name": cmd.get_name(),
        "args": args,
        "subcommands": subcommands,
    });
    if let Some(about) = cmd.get_about() {
        obj["about"] = serde_json::json!(about.to_string());
    }
    obj
}

fn print_command_tree(cmd: &clap::Command, depth: usize, show_all: bool) {
    let indent = "  ".repeat(depth);

    if depth == 0 {
        let about = cmd
            .get_about()
            .map(|a| format!(" - {a}"))
            .unwrap_or_default();
        println!("{}{}{}", indent, cmd.get_name(), about);
    }

    // Print arguments for this command
    for arg in cmd.get_arguments() {
        if arg.get_id() == "help" || arg.get_id() == "version" {
            continue;
        }
        let arg_indent = "  ".repeat(depth + 1);
        let help = arg.get_help().map(|h| format!("  {h}")).unwrap_or_default();
        if let Some(long) = arg.get_long() {
            println!("{arg_indent}--{long}{help}");
        } else if let Some(short) = arg.get_short() {
            println!("{arg_indent}-{short}{help}");
        } else {
            let req = if arg.is_required_set() { "" } else { "?" };
            println!("{arg_indent}<{}>{req}{help}", arg.get_id());
        }
    }

    // Print subcommands
    for sub in cmd.get_subcommands() {
        if sub.get_name() == "help" || (!show_all && sub.is_hide_set()) {
            continue;
        }
        let sub_indent = "  ".repeat(depth + 1);
        let about = sub
            .get_about()
            .map(|a| format!("  {a}"))
            .unwrap_or_default();
        println!("{sub_indent}{}{}", sub.get_name(), about);
        print_command_tree(sub, depth + 1, show_all);
    }
}

/// Lightweight input for the explain command — only requires tool_name and tool_input.
#[derive(serde::Deserialize)]
struct ExplainInput {
    tool_name: String,
    tool_input: serde_json::Value,
    #[serde(default = "default_cwd")]
    cwd: String,
}

fn default_cwd() -> String {
    std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Explain which policy rule would match a given tool invocation.
///
/// Accepts CLI args (`clash explain bash "git push"`) or JSON from stdin.
#[instrument(level = Level::TRACE)]
fn run_explain(json_output: bool, tool: Option<String>, input_arg: Option<String>) -> Result<()> {
    let input: ExplainInput = if let Some(tool_str) = tool {
        // Build from CLI arguments
        let (tool_name, input_field) = match tool_str.to_lowercase().as_str() {
            "bash" => ("Bash", "command"),
            "read" => ("Read", "file_path"),
            "write" => ("Write", "file_path"),
            "edit" => ("Edit", "file_path"),
            _ => {
                // Allow full tool names (Bash, Read, etc.) as-is
                let field = match tool_str.as_str() {
                    "Bash" => "command",
                    "Read" | "Write" | "Edit" | "NotebookEdit" => "file_path",
                    "Glob" | "Grep" => "pattern",
                    "WebFetch" => "url",
                    "WebSearch" => "query",
                    _ => "command",
                };
                // Leak to get 'static -- fine for a CLI tool that runs once
                let name: &'static str = Box::leak(tool_str.into_boxed_str());
                (name, field)
            }
        };
        let noun = input_arg.unwrap_or_default();
        ExplainInput {
            tool_name: tool_name.to_string(),
            tool_input: serde_json::json!({ input_field: noun }),
            cwd: default_cwd(),
        }
    } else {
        // Read from stdin
        serde_json::from_reader(std::io::stdin().lock()).context(
            "failed to parse JSON from stdin (expected {\"tool_name\":..., \"tool_input\":...})\n\nUsage: clash explain bash \"git push\"  OR  echo '{...}' | clash explain",
        )?
    };

    let settings = ClashSettings::load_or_create()?;
    let tree = match settings.decision_tree() {
        Some(t) => t,
        None => {
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({"error": "no compiled policy available"})
                );
            } else {
                eprintln!("No compiled policy available.");
                eprintln!("Create ~/.clash/policy.sexpr or run `clash init`.");
            }
            return Ok(());
        }
    };

    let multi_level = settings.loaded_policies().len() > 1;
    let decision = tree.evaluate(&input.tool_name, &input.tool_input, &input.cwd);
    let noun = clash::permissions::extract_noun(&input.tool_name, &input.tool_input);

    // Helper to look up origin_level for a matched rule by searching all domain
    // rule lists. The rule_index is relative to its domain list, so we check
    // each list at that index for a matching description.
    let find_origin_level = |m: &clash::policy::ir::RuleMatch| -> Option<&PolicyLevel> {
        let rule_lists: &[&[clash::policy::decision_tree::CompiledRule]] = &[
            &tree.exec_rules,
            &tree.fs_rules,
            &tree.net_rules,
            &tree.tool_rules,
        ];
        for rules in rule_lists {
            if let Some(rule) = rules.get(m.rule_index) {
                let desc = rule.source.to_string();
                if m.description.starts_with(&desc) {
                    return rule.origin_level.as_ref();
                }
            }
        }
        None
    };

    if json_output {
        let mut output = serde_json::json!({
            "effect": format!("{}", decision.effect),
            "reason": decision.reason,
            "matched_rules": decision.trace.matched_rules.iter().map(|m| {
                let mut entry = serde_json::json!({
                    "rule_index": m.rule_index,
                    "description": m.description,
                    "effect": format!("{}", m.effect),
                });
                if multi_level
                    && let Some(level) = find_origin_level(m)
                {
                    entry["level"] = serde_json::json!(level.to_string());
                }
                entry
            }).collect::<Vec<_>>(),
            "skipped_rules": decision.trace.skipped_rules.iter().map(|s| {
                serde_json::json!({
                    "rule_index": s.rule_index,
                    "description": s.description,
                    "reason": s.reason,
                })
            }).collect::<Vec<_>>(),
            "resolution": decision.trace.final_resolution,
            "sandbox": decision.sandbox.as_ref().map(|s| serde_json::to_value(s).ok()),
        });
        // Add top-level "level" from the first (winning) matched rule.
        if multi_level
            && let Some(first_match) = decision.trace.matched_rules.first()
            && let Some(level) = find_origin_level(first_match)
        {
            output["level"] = serde_json::json!(level.to_string());
        }
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Input:");
        println!("  tool:   {}", input.tool_name);
        println!("  noun:   {}", noun);
        println!();

        println!("Decision: {}", decision.effect);
        if let Some(ref reason) = decision.reason {
            println!("Reason:   {}", reason);
        }
        if multi_level
            && let Some(first_match) = decision.trace.matched_rules.first()
            && let Some(level) = find_origin_level(first_match)
        {
            println!("Level:    {}", level);
        }
        println!();

        if !decision.trace.matched_rules.is_empty() {
            println!("Matched rules:");
            for m in &decision.trace.matched_rules {
                if multi_level {
                    if let Some(level) = find_origin_level(m) {
                        println!(
                            "  [{}] [{}] {} -> {}",
                            m.rule_index, level, m.description, m.effect
                        );
                    } else {
                        println!("  [{}] {} -> {}", m.rule_index, m.description, m.effect);
                    }
                } else {
                    println!("  [{}] {} -> {}", m.rule_index, m.description, m.effect);
                }
            }
            println!();
        }

        if !decision.trace.skipped_rules.is_empty() {
            println!("Skipped rules:");
            for s in &decision.trace.skipped_rules {
                println!("  [{}] {} ({})", s.rule_index, s.description, s.reason);
            }
            println!();
        }

        println!("Resolution: {}", decision.trace.final_resolution);

        if let Some(ref sandbox) = decision.sandbox {
            println!();
            println!("Sandbox policy:");
            println!("  default: {}", sandbox.default.display());
            println!("  network: {:?}", sandbox.network);
            for rule in &sandbox.rules {
                println!(
                    "  {:?} {} in {}",
                    rule.effect,
                    rule.caps.display(),
                    rule.path
                );
            }
        }
    }

    Ok(())
}

/// Initialize or reconfigure a clash policy.
///
/// - If a sexp policy already exists, drop into the interactive wizard.
/// - If only a legacy YAML policy exists, convert it via `claude -p` then
///   drop into the wizard.
/// - Otherwise, write the default policy and launch the wizard.
#[instrument(level = Level::TRACE)]
fn run_init(no_bypass: Option<bool>, project: Option<bool>) -> Result<()> {
    if project.unwrap_or_else(|| {
        dialoguer::Confirm::new()
            .with_prompt("Init clash for the current project?")
            .interact()
            .unwrap_or(false)
    }) {
        return run_init_project();
    }

    let sexpr_path = ClashSettings::policy_file()?;

    if sexpr_path.exists() && sexpr_path.is_dir() {
        if dialoguer::Confirm::new()
            .with_prompt(&format!(
                "{} is a directory. Remove it and continue onboarding?",
                sexpr_path.to_string_lossy(),
            ))
            .interact()
            .context("confirm removeal of dir at sexpr path")?
        {
            std::fs::remove_dir_all(&sexpr_path)?;
        } else {
            anyhow::bail!(
                "{} is a directory. Remove it first, then run `clash init`.",
                sexpr_path.display()
            );
        }
    }

    if sexpr_path.exists() {
        if !dialoguer::Confirm::new()
            .with_prompt(&format!(
                "A policy already exists at {}. Reconfigure existing policy?",
                sexpr_path.to_string_lossy()
            ))
            .interact()
            .unwrap_or_default()
        {
            anyhow::bail!(
                "Cowardly refusing to configure clash due to existin policy at {}\n",
                sexpr_path.display()
            );
        }
    }

    let yaml_path = ClashSettings::legacy_policy_file()?;
    if yaml_path.exists() && yaml_path.is_file() && Confirm::new().with_prompt("An existing policy.yaml file was found at {}. Should we attempt to migrate your settings?").default(false).interact().unwrap_or(false){
        // Legacy YAML policy found — attempt migration, then launch wizard.
        migrate_yaml_policy(&yaml_path, &sexpr_path)?;
        return clash::wizard::run();
    }

    // Fresh install — write default policy.
    std::fs::create_dir_all(ClashSettings::settings_dir()?)?;
    std::fs::write(&sexpr_path, DEFAULT_POLICY)?;

    // TODO: detect whether the clash plugin is installed so this prompt can be more helpful
    if !no_bypass.unwrap_or_else(||dialoguer::Confirm::new().with_prompt("Use clash as your default permissions provider in claude? (This will set bypassPermissions in your claude settings, which is only safe if you have the clash plugin installed)").interact().unwrap_or(true)) {
    if let Err(e) = set_bypass_permissions() {
        warn!(error = %e, "Could not set bypassPermissions in Claude Code settings");
        eprintln!(
            "warning: could not configure Claude Code to use clash as sole permission handler.\n\
             You may see double prompts. Run with --dangerously-skip-permissions to avoid this."
        );
    }
}

    println!("Clash initialized at {}\n", sexpr_path.display());

    // Launch the wizard so the user can customize immediately.
    clash::wizard::run()
}

/// Initialize a project-level policy in the project root's `.clash/` directory.
fn run_init_project() -> Result<()> {
    let project_root = ClashSettings::project_root()
        .context("could not find project root — are you inside a git repository?")?;

    let clash_dir = project_root.join(".clash");
    let policy_path = clash_dir.join("policy.sexpr");

    if policy_path.exists() {
        println!("Project policy already exists at {}", policy_path.display());
        return Ok(());
    }

    std::fs::create_dir_all(&clash_dir)
        .with_context(|| format!("failed to create {}", clash_dir.display()))?;

    let project_policy = "(default deny \"main\")\n(policy \"main\")\n";
    std::fs::write(&policy_path, project_policy)
        .with_context(|| format!("failed to write {}", policy_path.display()))?;

    println!("Project policy initialized at {}", policy_path.display());
    Ok(())
}

/// Migrate a legacy YAML policy to s-expression format using `claude -p`.
fn migrate_yaml_policy(yaml_path: &std::path::Path, sexpr_path: &std::path::Path) -> Result<()> {
    let yaml_content =
        std::fs::read_to_string(yaml_path).context("failed to read legacy policy.yaml")?;

    let grammar = include_str!("../../docs/policy-grammar.md");

    let prompt = format!(
        "Convert this YAML clash policy to the s-expression format described in the grammar below.\n\
         Output ONLY the s-expression policy text. No markdown fences, no explanation.\n\n\
         ## Grammar\n\n{grammar}\n\n\
         ## YAML Policy\n\n```yaml\n{yaml_content}\n```"
    );

    println!("Migrating legacy policy.yaml to s-expression format...");

    let output = std::process::Command::new("claude")
        .arg("-p")
        .arg(&prompt)
        .output()
        .context("failed to run `claude -p` for policy migration — is claude on PATH?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!(stderr = %stderr, "claude -p failed during YAML migration");
        eprintln!("Migration failed — writing default policy instead.");
        eprintln!(
            "Your legacy policy.yaml is preserved at {}",
            yaml_path.display()
        );
        std::fs::create_dir_all(sexpr_path.parent().unwrap())?;
        std::fs::write(sexpr_path, DEFAULT_POLICY)?;
        return Ok(());
    }

    let sexpr_content = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // Validate the converted policy compiles.
    match clash::policy::compile_policy(&sexpr_content) {
        Ok(_) => {
            std::fs::create_dir_all(sexpr_path.parent().unwrap())?;
            std::fs::write(sexpr_path, &sexpr_content)?;
            println!("Migrated policy written to {}", sexpr_path.display());
            println!("Legacy policy.yaml preserved at {}\n", yaml_path.display());
        }
        Err(e) => {
            warn!(error = %e, "migrated policy failed validation");
            eprintln!("Converted policy failed validation: {e}");
            eprintln!("Writing default policy instead. Your legacy policy.yaml is preserved.");
            std::fs::create_dir_all(sexpr_path.parent().unwrap())?;
            std::fs::write(sexpr_path, DEFAULT_POLICY)?;
        }
    }

    Ok(())
}

/// Set `bypassPermissions: true` in user-level Claude Code settings.
///
/// This tells Claude Code to skip its built-in permission system so Clash
/// becomes the sole permission handler, avoiding double-prompting.
fn set_bypass_permissions() -> Result<()> {
    let claude = claude_settings::ClaudeSettings::new();
    claude.set_bypass_permissions(claude_settings::SettingsLevel::User, true)?;
    println!("Configured Claude Code to use clash as the sole permission handler.");
    Ok(())
}

/// Show policy status: layers, rules with shadowing, and potential issues.
#[instrument(level = Level::TRACE)]
fn run_status(_json: bool) -> Result<()> {
    let settings = ClashSettings::load_or_create()?;
    let tree = match settings.decision_tree() {
        Some(t) => t,
        None => {
            if let Some(err) = settings.policy_error() {
                eprintln!("Policy error: {}", err);
            } else {
                eprintln!("No policy configured. Run `clash init` to get started.");
            }
            return Ok(());
        }
    };

    let loaded = settings.loaded_policies();
    let multi_level = loaded.len() > 1;

    // Build a lookup for level paths.
    let level_path = |level: PolicyLevel| -> Option<String> {
        loaded
            .iter()
            .find(|lp| lp.level == level)
            .map(|lp| lp.path.display().to_string())
    };

    // 1. Policy layers
    println!("Policy layers");
    println!("=============");
    for &level in &[
        PolicyLevel::User,
        PolicyLevel::Project,
        PolicyLevel::Session,
    ] {
        match level_path(level) {
            Some(path) => println!("  {:<10} {}", format!("{}:", level), path),
            None => println!("  {:<10} (none)", format!("{}:", level)),
        }
    }
    if multi_level {
        println!();
        println!("  Precedence: session > project > user (automatic)");
    }
    println!();

    // 2. Effective policy — rules in evaluation order with shadow detection
    println!("Effective policy (default: {})", tree.default);
    println!("=================================");

    let shadows = clash::policy::detect_all_shadows(tree);

    let print_rules =
        |label: &str,
         rules: &[clash::policy::decision_tree::CompiledRule],
         shadow_map: &std::collections::HashMap<usize, clash::policy::ShadowInfo>| {
            if rules.is_empty() {
                return;
            }
            println!("  {}:", label);
            for (i, rule) in rules.iter().enumerate() {
                let builtin = rule
                    .origin_policy
                    .as_ref()
                    .is_some_and(|p| p.starts_with("__internal_"));

                // Source tag: [builtin], [user], [project], [session]
                let tag = if builtin {
                    "[builtin]".to_string()
                } else if let Some(ref level) = rule.origin_level {
                    format!("[{}]", level)
                } else {
                    String::new()
                };

                // Shadow indicator
                let shadow_note = if let Some(info) = shadow_map.get(&i) {
                    format!("  <- shadowed by {}", info.shadowed_by_level)
                } else {
                    String::new()
                };

                println!(
                    "    [{:<5}] {:<45} {}{}",
                    rule.effect, rule.source.matcher, tag, shadow_note,
                );
            }
        };

    print_rules("Exec", &tree.exec_rules, &shadows.exec);
    print_rules("Filesystem", &tree.fs_rules, &shadows.fs);
    print_rules("Network", &tree.net_rules, &shadows.net);
    print_rules("Tool", &tree.tool_rules, &shadows.tool);

    let total =
        tree.exec_rules.len() + tree.fs_rules.len() + tree.net_rules.len() + tree.tool_rules.len();
    if total == 0 {
        println!(
            "  (no rules — default {} applies to everything)",
            tree.default
        );
    }

    println!(
        "\n  Everything else: {}",
        match tree.default {
            Effect::Allow => "allowed",
            Effect::Deny => "denied",
            Effect::Ask => "requires approval",
        }
    );
    println!();

    // 3. Potential issues
    println!("Potential issues");
    println!("================");
    let mut issues = Vec::new();

    // Check for overly permissive wildcard exec rules
    for rule in &tree.exec_rules {
        if rule.effect == Effect::Allow
            && !rule
                .origin_policy
                .as_ref()
                .is_some_and(|p| p.starts_with("__internal_"))
            && let clash::policy::ast::CapMatcher::Exec(ref m) = rule.source.matcher
            && matches!(m.bin, clash::policy::ast::Pattern::Any)
        {
            issues.push(
                "Wildcard exec allow: all commands are allowed. Consider restricting to specific programs."
                    .to_string(),
            );
        }
    }

    // Check for overly permissive fs rules
    for rule in &tree.fs_rules {
        if rule.effect == Effect::Allow
            && !rule
                .origin_policy
                .as_ref()
                .is_some_and(|p| p.starts_with("__internal_"))
            && let clash::policy::ast::CapMatcher::Fs(ref m) = rule.source.matcher
            && matches!(m.op, OpPattern::Any)
            && m.path.is_none()
        {
            issues.push(
                "Wildcard filesystem allow: all file operations on all paths are allowed."
                    .to_string(),
            );
        }
    }

    // Check for overly permissive net rules
    for rule in &tree.net_rules {
        if rule.effect == Effect::Allow
            && !rule
                .origin_policy
                .as_ref()
                .is_some_and(|p| p.starts_with("__internal_"))
            && let clash::policy::ast::CapMatcher::Net(ref m) = rule.source.matcher
            && matches!(m.domain, clash::policy::ast::Pattern::Any)
        {
            issues.push(
                "Wildcard network allow: all domains are accessible. Consider restricting to specific domains."
                    .to_string(),
            );
        }
    }

    // Check default allow with no deny rules
    if tree.default == Effect::Allow
        && tree
            .exec_rules
            .iter()
            .chain(&tree.fs_rules)
            .chain(&tree.net_rules)
            .all(|r| r.effect != Effect::Deny)
    {
        issues.push("Default is allow with no deny rules: everything is permitted.".to_string());
    }

    // Check for shadowed rules
    let shadow_count =
        shadows.exec.len() + shadows.fs.len() + shadows.net.len() + shadows.tool.len();
    if shadow_count > 0 {
        issues.push(format!(
            "{} rule(s) shadowed by higher-precedence layers (marked with <- above).",
            shadow_count
        ));
    }

    if issues.is_empty() {
        println!("  No issues detected.");
    } else {
        for issue in &issues {
            println!("  - {}", issue);
        }
    }

    Ok(())
}

/// Handle `clash policy schema`.
fn handle_schema(json: bool) -> Result<()> {
    let schema = clash::schema::policy_schema();

    if json {
        println!("{}", serde_json::to_string_pretty(&schema)?);
    } else {
        println!("Policy Schema");
        println!("=============\n");

        for section in &schema.sections {
            println!("{}:", section.key);
            println!("  {}\n", section.description);
            print_fields(&section.fields, 2);
            println!();
        }

        println!("Rule Syntax:");
        println!("  Format: {}\n", schema.rule_syntax.format);
        println!("  Effects: {}", schema.rule_syntax.effects.join(", "));
        println!("  Fs ops:  {}", schema.rule_syntax.fs_operations.join(", "));
        println!("\n  Capability domains:");
        print_fields(&schema.rule_syntax.domains, 4);
        println!("\n  Patterns:");
        print_fields(&schema.rule_syntax.patterns, 4);
        println!("\n  Path filters:");
        print_fields(&schema.rule_syntax.path_filters, 4);
    }
    Ok(())
}

fn print_fields(fields: &[clash::schema::SchemaField], indent: usize) {
    let pad = " ".repeat(indent);
    for f in fields {
        let req = if f.required { " (required)" } else { "" };
        let default_str = match &f.default {
            Some(v) => format!(" [default: {}]", v),
            None => String::new(),
        };
        let values_str = match &f.values {
            Some(vals) => format!(" ({})", vals.join("|")),
            None => String::new(),
        };
        println!(
            "{}{}: {}{}{}{} — {}",
            pad, f.key, f.type_name, values_str, default_str, req, f.description
        );
        if let Some(ref sub) = f.fields {
            print_fields(sub, indent + 2);
        }
    }
}

/// File a bug report to Linear if the key was supplied at compile time
#[instrument(level = Level::TRACE)]
fn run_bug_report(
    title: String,
    description: Option<String>,
    include_config: bool,
    include_logs: bool,
) -> Result<()> {
    use clash::linear;

    if !linear::api_key_available() {
        anyhow::bail!(
            "Bug reporting is not configured in this build.\n\
             Rebuild with CLASH_LINEAR_API_KEY set to enable it."
        );
    }

    let mut attachments = Vec::new();

    if include_config {
        match ClashSettings::policy_file().and_then(|p| {
            std::fs::read_to_string(&p).with_context(|| format!("failed to read {}", p.display()))
        }) {
            Ok(contents) => attachments.push(linear::Attachment {
                filename: "policy.sexpr".into(),
                content_type: "text/plain".into(),
                title: "Policy Config".into(),
                body: contents.into_bytes(),
            }),
            Err(e) => eprintln!("Warning: could not read config: {}", e),
        }
    }

    if include_logs {
        match read_recent_logs(100) {
            Ok(contents) => attachments.push(linear::Attachment {
                filename: "clash.log".into(),
                content_type: "text/plain".into(),
                title: "Debug Logs".into(),
                body: contents.into_bytes(),
            }),
            Err(e) => eprintln!("Warning: could not read logs: {}", e),
        }
    }

    let report = linear::BugReport {
        title,
        description,
        attachments,
    };

    let issue = linear::create_issue(&report).context("failed to file bug report")?;
    println!("Filed bug {}: {}", issue.identifier, issue.url);
    Ok(())
}

/// Read the last `n` lines from the clash log file.
fn read_recent_logs(n: usize) -> Result<String> {
    let log_path = std::env::var("CLASH_LOG").ok().unwrap_or_else(|| {
        ClashSettings::settings_dir()
            .map(|d| d.join("clash.log"))
            .unwrap_or_else(|_| std::path::PathBuf::from("clash.log"))
            .to_string_lossy()
            .into_owned()
    });

    let contents = std::fs::read_to_string(&log_path)
        .with_context(|| format!("failed to read {}", log_path))?;

    let lines: Vec<&str> = contents.lines().collect();
    let start = lines.len().saturating_sub(n);
    Ok(lines[start..].join("\n"))
}

/// Handle `clash policy` subcommands.
#[instrument(level = Level::TRACE)]
fn run_policy(cmd: PolicyCmd) -> Result<()> {
    match cmd {
        PolicyCmd::Schema { json } => handle_schema(json),
        PolicyCmd::Explain { json, tool, args } => {
            let input = if args.is_empty() {
                None
            } else {
                Some(args.join(" "))
            };
            run_explain(json, tool, input)
        }
        PolicyCmd::Allow {
            rule,
            dry_run,
            scope,
        } => handle_allow_deny(Effect::Allow, &rule, dry_run, scope.as_deref()),
        PolicyCmd::Deny {
            rule,
            dry_run,
            scope,
        } => handle_allow_deny(Effect::Deny, &rule, dry_run, scope.as_deref()),
        PolicyCmd::Ask {
            rule,
            dry_run,
            scope,
        } => handle_allow_deny(Effect::Ask, &rule, dry_run, scope.as_deref()),
        PolicyCmd::Remove {
            rule,
            dry_run,
            scope,
        } => handle_remove(&rule, dry_run, scope.as_deref()),
        PolicyCmd::List { json } => handle_list(json),
        PolicyCmd::Show { json } => handle_show(json),
    }
}

// ---------------------------------------------------------------------------
// Policy file I/O
// ---------------------------------------------------------------------------

/// Parse a `--scope` flag value into a `PolicyLevel`.
///
/// If `None`, uses `ClashSettings::default_scope()` (project if a project policy
/// exists, otherwise user).
fn resolve_scope(scope: Option<&str>) -> Result<PolicyLevel> {
    match scope {
        Some(s) => s.parse::<PolicyLevel>().context("invalid --scope value"),
        None => Ok(ClashSettings::default_scope()),
    }
}

/// Read the policy source from disk.
///
/// If a `PolicyLevel` is specified, loads from that level's path.
/// Otherwise, uses the user-level policy (backward-compatible default).
fn load_policy_source(level: Option<PolicyLevel>) -> Result<(std::path::PathBuf, String)> {
    let path = match level {
        Some(l) => ClashSettings::policy_file_for_level(l)?,
        None => ClashSettings::policy_file()?,
    };
    let source = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read policy file: {}", path.display()))?;
    Ok((path, source))
}

/// Write policy source back to disk after validating it compiles.
fn write_policy(path: &std::path::Path, source: &str) -> Result<()> {
    // Validate before writing — never write a broken policy.
    clash::policy::compile_policy(source)
        .context("modified policy failed to compile — not writing")?;
    // Ensure parent directory exists (important for project-level policies).
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory: {}", parent.display()))?;
    }
    std::fs::write(path, source)
        .with_context(|| format!("failed to write policy file: {}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// CLI rule parsing: bare verbs and s-expr syntax
// ---------------------------------------------------------------------------

use clash::policy::ast::Rule as AstRule;
use clash::policy::ast::{
    CapMatcher, ExecMatcher, FsMatcher, FsOp, NetMatcher, OpPattern, PathExpr, PathFilter, Pattern,
    ToolMatcher,
};

/// Parse a CLI rule string into one or more AST rules.
///
/// Bare verbs (edit, bash, read, web) expand to convenient defaults.
/// Strings starting with `(` are parsed as s-expr matcher bodies.
fn parse_cli_rule(effect: Effect, rule_str: &str) -> Result<Vec<AstRule>> {
    if rule_str.starts_with('(') {
        // Power-user s-expr: parse as a capability matcher body and wrap with effect.
        let full = format!("(policy \"_\" ({effect} {rule_str}))");
        let top_levels =
            clash::policy::parse::parse(&full).context("failed to parse s-expr rule")?;
        match top_levels.into_iter().next() {
            Some(clash::policy::ast::TopLevel::Policy { mut body, .. }) => {
                let rules: Vec<AstRule> = body
                    .drain(..)
                    .filter_map(|item| match item {
                        clash::policy::ast::PolicyItem::Rule(r) => Some(r),
                        _ => None,
                    })
                    .collect();
                if rules.is_empty() {
                    bail!("no rule parsed from: {rule_str}");
                }
                Ok(rules)
            }
            _ => bail!("unexpected parse result for: {rule_str}"),
        }
    } else {
        // Bare verb shortcuts
        match rule_str {
            "bash" => Ok(vec![
                AstRule {
                    effect,
                    matcher: CapMatcher::Exec(ExecMatcher {
                        bin: Pattern::Any,
                        args: vec![],
                        has_args: vec![],
                    }),
                    sandbox: None,
                },
                AstRule {
                    effect,
                    matcher: CapMatcher::Fs(FsMatcher {
                        op: OpPattern::Or(vec![
                            FsOp::Read,
                            FsOp::Write,
                            FsOp::Create,
                            FsOp::Delete,
                        ]),
                        path: Some(PathFilter::Subpath(PathExpr::Env("PWD".into()))),
                    }),
                    sandbox: None,
                },
            ]),
            "edit" => Ok(vec![AstRule {
                effect,
                matcher: CapMatcher::Fs(FsMatcher {
                    op: OpPattern::Or(vec![FsOp::Write, FsOp::Create]),
                    path: Some(PathFilter::Subpath(PathExpr::Env("PWD".into()))),
                }),
                sandbox: None,
            }]),
            "read" => Ok(vec![AstRule {
                effect,
                matcher: CapMatcher::Fs(FsMatcher {
                    op: OpPattern::Single(FsOp::Read),
                    path: Some(PathFilter::Subpath(PathExpr::Env("PWD".into()))),
                }),
                sandbox: None,
            }]),
            "web" => Ok(vec![AstRule {
                effect,
                matcher: CapMatcher::Net(NetMatcher {
                    domain: Pattern::Any,
                }),
                sandbox: None,
            }]),
            "tool" => Ok(vec![AstRule {
                effect,
                matcher: CapMatcher::Tool(ToolMatcher { name: Pattern::Any }),
                sandbox: None,
            }]),
            other => bail!(
                "unknown verb: {other}\n\nSupported verbs: bash, edit, read, web, tool\n\
                 Or pass an s-expr: clash policy allow '(exec \"git\" *)'"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Subcommand handlers
// ---------------------------------------------------------------------------

/// Minimal policy source used when creating a new project-level policy file.
const MINIMAL_POLICY: &str = "(default deny \"main\")\n(policy \"main\")\n";

/// Handle `clash allow`, `clash deny`, `clash ask`, `clash policy allow`, etc.
fn handle_allow_deny(
    effect: Effect,
    rule_str: &str,
    dry_run: bool,
    scope: Option<&str>,
) -> Result<()> {
    let level = resolve_scope(scope)?;

    // Load source for this level, creating a minimal policy for project scope if needed.
    let (path, source) = match load_policy_source(Some(level)) {
        Ok(ps) => ps,
        Err(_) if level == PolicyLevel::Project || level == PolicyLevel::Session => {
            let path = ClashSettings::policy_file_for_level(level)?;
            (path, MINIMAL_POLICY.to_string())
        }
        Err(e) => return Err(e),
    };

    let policy_name = clash::policy::edit::active_policy(&source)?;
    let rules = parse_cli_rule(effect, rule_str)?;

    let mut modified = source.clone();

    for rule in &rules {
        modified = clash::policy::edit::add_rule(&modified, &policy_name, rule)?;
    }

    if dry_run {
        print!("{modified}");
    } else if modified == source {
        println!("Rule already exists (no change).");
    } else {
        write_policy(&path, &modified)?;
        let level_msg = format!("Added rule to {} policy", level);
        // Print a friendly confirmation for bare verbs, raw s-expr for power users.
        if let Some(msg) = friendly_confirmation(effect, rule_str) {
            println!("{msg}");
            println!("{level_msg}");
        } else {
            for rule in &rules {
                println!("Added: {rule}");
            }
            println!("{level_msg}");
        }
    }
    Ok(())
}

/// Return a human-friendly confirmation message for bare verb shortcuts.
fn friendly_confirmation(effect: Effect, verb: &str) -> Option<String> {
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| ".".into());

    let action = match effect {
        Effect::Allow => "can now",
        Effect::Deny => "can no longer",
        Effect::Ask => "will be asked before",
    };

    match verb {
        "edit" => Some(format!(
            "Claude {action} edit files in {cwd}.\n  \
             Files outside this directory are still protected."
        )),
        "bash" => Some(format!(
            "Claude {action} run commands.\n  \
             Use 'clash deny' to block specific dangerous commands."
        )),
        "read" => Some(format!("Claude {action} read files in {cwd}.")),
        "web" => Some(format!("Claude {action} search the web and fetch URLs.")),
        "tool" => Some(format!(
            "Claude {action} use agent tools (Skill, Task, etc.)."
        )),
        _ => None,
    }
}

/// Handle `clash policy remove`.
fn handle_remove(rule_str: &str, dry_run: bool, scope: Option<&str>) -> Result<()> {
    let level = resolve_scope(scope)?;

    let (path, source) = load_policy_source(Some(level))?;
    let policy_name = clash::policy::edit::active_policy(&source)?;
    let modified = clash::policy::edit::remove_rule(&source, &policy_name, rule_str)?;

    if dry_run {
        print!("{modified}");
    } else {
        write_policy(&path, &modified)?;
        println!("Removed rule from {} policy: {rule_str}", level);
    }
    Ok(())
}

/// Handle `clash policy list`.
fn handle_list(json: bool) -> Result<()> {
    let settings = ClashSettings::load_or_create()?;
    let tree = match settings.decision_tree() {
        Some(t) => t,
        None => {
            if let Some(err) = settings.policy_error() {
                anyhow::bail!("{}", err);
            }
            anyhow::bail!("no policy configured — run `clash init`");
        }
    };

    let all_rules: Vec<&clash::policy::decision_tree::CompiledRule> = tree
        .exec_rules
        .iter()
        .chain(&tree.fs_rules)
        .chain(&tree.net_rules)
        .chain(&tree.tool_rules)
        .collect();

    if json {
        let entries: Vec<serde_json::Value> = all_rules
            .iter()
            .map(|r| {
                let origin = r.origin_policy.as_deref().unwrap_or(&tree.policy_name);
                let builtin = origin.starts_with("__internal_");
                let mut entry = serde_json::json!({
                    "effect": format!("{}", r.effect),
                    "rule": r.source.to_string(),
                    "origin": origin,
                    "builtin": builtin,
                });
                if let Some(ref level) = r.origin_level {
                    entry["level"] = serde_json::json!(level.to_string());
                }
                entry
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        if all_rules.is_empty() {
            println!("No rules in policy \"{}\".", tree.policy_name);
            return Ok(());
        }
        println!(
            "Policy \"{}\" (default: {}, {} rules):\n",
            tree.policy_name,
            tree.default,
            all_rules.len()
        );
        for rule in &all_rules {
            let tag = if let Some(ref level) = rule.origin_level {
                format!("[{}] ", level)
            } else if rule
                .origin_policy
                .as_ref()
                .is_some_and(|p| p.starts_with("__internal_"))
            {
                "[builtin] ".to_string()
            } else {
                String::new()
            };
            println!("  {}{}", tag, rule.source);
        }
    }
    Ok(())
}

/// Handle `clash policy show`.
fn handle_show(json: bool) -> Result<()> {
    let settings = ClashSettings::load_or_create()?;
    let tree = match settings.decision_tree() {
        Some(t) => t,
        None => {
            if let Some(err) = settings.policy_error() {
                anyhow::bail!("{}", err);
            }
            anyhow::bail!("no policy configured — run `clash init`");
        }
    };

    let loaded = settings.loaded_policies();

    if json {
        let rule_count = tree.exec_rules.len()
            + tree.fs_rules.len()
            + tree.net_rules.len()
            + tree.tool_rules.len();
        let output = serde_json::json!({
            "policy_name": tree.policy_name,
            "default": format!("{}", tree.default),
            "rule_count": rule_count,
            "source": tree.to_source(),
            "levels": loaded
                .iter()
                .map(|lp| {
                    serde_json::json!({
                        "level": lp.level.to_string(),
                        "path": lp.path.display().to_string(),
                        "source": &lp.source,
                    })
                })
                .collect::<Vec<serde_json::Value>>(),
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        for lp in loaded {
            println!("[{}] {}", lp.level, lp.path.display());
            println!("{}", "-".repeat(40));
            print!("{}", lp.source);
            if !lp.source.ends_with('\n') {
                println!();
            }
            println!();
        }
        if loaded.is_empty() {
            print!("{}", clash::policy::print_tree(tree));
        }
    }
    Ok(())
}
