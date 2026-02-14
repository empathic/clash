use std::fs::OpenOptions;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use clash::policy::edit;
use clash::policy::parse::{desugar_claude_permissions, flatten_profile, format_rule};
use clash::policy::{ClaudePermissions, Effect};
use tracing::level_filters::LevelFilter;
use tracing::{Level, debug_span, error, info, instrument, warn};
use tracing_subscriber::Layer;
use tracing_subscriber::prelude::*;

use clash::handlers;
use clash::hooks::{HookOutput, ToolUseHookInput, exit_code};
use clash::permissions::check_permission;
use clash::sandbox_cmd;
use clash::settings::{ClashSettings, DEFAULT_POLICY};

use sandbox_cmd::{SandboxCmd, run_sandbox};

#[derive(Parser, Debug)]
#[command(name = "clash")]
#[command(about = "Claude shell")]
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
        let settings = ClashSettings::load_or_create()?;

        let output = match self {
            Self::PreToolUse => {
                let input = ToolUseHookInput::from_reader(std::io::stdin().lock())?;
                check_permission(&input, &settings)?
            }
            Self::PostToolUse => {
                let _input = ToolUseHookInput::from_reader(std::io::stdin().lock())?;
                // PostToolUse is informational - just continue
                HookOutput::continue_execution()
            }
            Self::PermissionRequest => {
                let input = ToolUseHookInput::from_reader(std::io::stdin().lock())?;
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
    /// Add an allow rule (bare verb like "edit" or full rule like "bash git *")
    Allow {
        /// Verb or rule: bare verb (e.g. "edit", "bash", "web") or full rule (e.g. "bash git *")
        rule: String,
        /// Target profile (default: active profile from default.profile)
        #[arg(long)]
        profile: Option<String>,
        /// Filesystem constraints: "caps:filter_expr" (e.g. "full:subpath(~/dir)", "read+write:subpath(.)")
        #[arg(long)]
        fs: Vec<String>,
        /// URL constraints: require or forbid domains (e.g. "github.com", "!evil.com")
        #[arg(long)]
        url: Vec<String>,
        /// Argument constraints: require or forbid args (e.g. "--dry-run", "!-delete")
        #[arg(long)]
        args: Vec<String>,
        /// Allow piping (stdin/stdout redirection between commands)
        #[arg(long)]
        pipe: Option<bool>,
        /// Allow shell redirects (>, >>, <)
        #[arg(long)]
        redirect: Option<bool>,
        /// Print modified policy to stdout without writing
        #[arg(long)]
        dry_run: bool,
    },
    /// Add a deny rule (bare verb like "bash" or full rule like "bash git push*")
    Deny {
        /// Verb or rule: bare verb (e.g. "bash") or full rule (e.g. "bash git push*")
        rule: String,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        fs: Vec<String>,
        #[arg(long)]
        url: Vec<String>,
        #[arg(long)]
        args: Vec<String>,
        #[arg(long)]
        pipe: Option<bool>,
        #[arg(long)]
        redirect: Option<bool>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove a rule from the policy
    Remove {
        /// Rule to remove (e.g. "allow bash *", "deny bash git push*")
        rule: String,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    /// List rules in the active profile
    List {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Switch the active profile
    Use {
        /// Profile name to activate
        profile: String,
    },
    /// Interactive policy configuration wizard
    Setup,

    // --- Hidden/power-user subcommands ---
    /// Show active profile, default permission, and available profiles
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
        /// The command, file path, or noun to check
        input: Option<String>,
    },
    /// Migrate legacy Claude Code permissions into clash policy
    #[command(hide = true)]
    Migrate {
        /// Preview the migration: show which rules would be added
        #[arg(long)]
        dry_run: bool,
        /// Default effect when creating a new policy (ignored when merging)
        #[arg(long, default_value = "ask")]
        default: String,
    },
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize a new clash policy with a safe default configuration
    Init {
        /// Skip setting bypassPermissions in Claude Code settings
        #[arg(long)]
        no_bypass: bool,
    },

    /// Show what Claude can and cannot do (human-readable policy summary)
    Status {
        /// Output as JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },

    /// View and edit policy rules
    #[command(subcommand)]
    Policy(PolicyCmd),

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
        /// Path to policy file (default: ~/.clash/policy.sexp)
        #[arg(long)]
        policy: Option<String>,

        /// Active profile override (default: from policy file)
        #[arg(long)]
        profile: Option<String>,

        /// Arguments to pass through to Claude Code
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
            Commands::Init { no_bypass } => run_init(no_bypass),
            Commands::Status { json } => run_status(json),
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
            Commands::Launch {
                policy,
                args,
                profile,
            } => run_launch(policy, args, profile),
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
fn run_launch(
    policy_path: Option<String>,
    args: Vec<String>,
    profile: Option<String>,
) -> Result<()> {
    // Resolve the clash binary path for hook commands
    let clash_bin = std::env::current_exe().context("failed to determine clash binary path")?;
    let clash_bin_str = clash_bin.to_string_lossy();

    // Validate that we have a policy if one was specified
    if let Some(ref path) = policy_path {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read policy file: {}", path))?;
        // Validate it parses
        clash::policy::parse::parse_policy(&contents)
            .with_context(|| format!("failed to parse policy file: {}", path))?;
        info!(path, "Using policy file");
    }

    // Set CLASH_PROFILE so hook subprocesses pick up the profile override.
    if let Some(ref p) = profile {
        // SAFETY: This is called early in main, before spawning any threads,
        // so modifying the environment is safe.
        unsafe { std::env::set_var("CLASH_PROFILE", p) };
        info!(profile = p, "Overriding active profile via CLASH_PROFILE");
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

/// Migrate legacy Claude Code permissions into clash policy.
///
/// If no policy file exists, creates a fresh one. If one already exists,
/// merges only new rules into the active profile.
#[instrument(level = Level::TRACE)]
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

    // Convert PermissionSet to ClaudePermissions (allow/deny/ask string lists)
    let perms = effective.permissions.to_permissions();
    let claude_perms = ClaudePermissions {
        allow: perms.allow,
        deny: perms.deny,
        ask: perms.ask,
    };

    let statements = desugar_claude_permissions(&claude_perms);

    if statements.is_empty() {
        println!("No legacy permissions found to migrate.");
        return Ok(());
    }

    // Convert statements to rule strings for add_rule
    let rules: Vec<String> = statements.iter().map(format_rule).collect();

    let path = ClashSettings::policy_file()?;
    if path.exists() {
        merge_rules_into_policy(&path, &rules, dry_run)
    } else {
        create_fresh_policy(&path, &statements, default, dry_run)
    }
}

/// Merge rule strings into an existing policy's active profile.
fn merge_rules_into_policy(path: &std::path::Path, rules: &[String], dry_run: bool) -> Result<()> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let profile = edit::resolve_profile(&text, None)?;

    let mut current = text.clone();
    let mut added: Vec<String> = Vec::new();
    let mut skipped: usize = 0;

    for rule in rules {
        let modified = edit::add_rule(
            &current,
            &profile,
            rule,
            &edit::InlineConstraintArgs::default(),
        )?;
        if modified == current {
            skipped += 1;
        } else {
            added.push(rule.clone());
            current = modified;
        }
    }

    if added.is_empty() {
        println!(
            "All {} Claude permission(s) already exist in profile '{}'. Nothing to do.",
            rules.len(),
            profile
        );
        return Ok(());
    }

    if dry_run {
        println!(
            "Would add {} new rule(s) to profile '{}':\n",
            added.len(),
            profile
        );
        for rule in &added {
            println!("  + {}", rule);
        }
        if skipped > 0 {
            println!("\n({} existing rule(s) already present, skipped.)", skipped);
        }
    } else {
        std::fs::write(path, &current)?;
        println!(
            "Merged {} new rule(s) into profile '{}' at {}:",
            added.len(),
            profile,
            path.display()
        );
        for rule in &added {
            println!("  + {}", rule);
        }
        if skipped > 0 {
            println!("({} rule(s) already existed, skipped.)", skipped);
        }
    }

    Ok(())
}

/// Create a fresh policy from migrated statements.
fn create_fresh_policy(
    path: &std::path::Path,
    statements: &[clash::policy::Statement],
    default: Effect,
    dry_run: bool,
) -> Result<()> {
    let effect_str = default.to_string();

    let mut output = String::new();
    output.push_str("; Policy generated by `clash migrate` from Claude Code settings.\n");
    output.push_str("; Review and customize as needed.\n");
    output.push_str(";\n");
    output.push_str(
        "; Evaluation: all matching statements are collected, then precedence applies:\n",
    );
    output.push_str(";   deny > ask > allow\n");
    output.push_str("; If no statement matches, the default effect is used.\n");
    output.push('\n');
    output.push_str(&format!(
        "(default (permission {}) (profile main))\n\n",
        effect_str
    ));
    output.push_str("(profile main\n");
    for stmt in statements {
        let rule = format_rule(stmt);
        // Parse rule to get effect, verb, noun for s-expr formatting
        let parts: Vec<&str> = rule.split_whitespace().collect();
        if parts.len() >= 3 {
            let noun = parts[2..].join(" ");
            let noun_fmt = if noun.contains(' ') {
                format!("\"{}\"", noun)
            } else {
                noun
            };
            output.push_str(&format!("  ({} {} {})\n", parts[0], parts[1], noun_fmt));
        }
    }
    output.push_str(")\n");

    if dry_run {
        print!("{}", output);
    } else {
        std::fs::create_dir_all(
            path.parent()
                .ok_or_else(|| anyhow::anyhow!("policy path has no parent directory"))?,
        )?;
        std::fs::write(path, &output)?;
        println!("Wrote policy to {}", path.display());
        println!(
            "Migrated {} rule(s) from legacy Claude Code permissions.",
            statements.len()
        );
    }

    Ok(())
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
    use clash::permissions::{extract_noun, resolve_verb};
    use clash::policy::EvalContext;

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
                // Leak to get 'static — fine for a CLI tool that runs once
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

    // Load settings and compile policy
    let settings = ClashSettings::load_or_create()?;
    let compiled = match settings.compiled_policy() {
        Some(c) => c,
        None => {
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({"error": "no compiled policy available"})
                );
            } else {
                eprintln!("No compiled policy available.");
                eprintln!("Create ~/.clash/policy.sexp or configure Claude Code permissions.");
            }
            return Ok(());
        }
    };

    let (verb, verb_str_owned) = resolve_verb(&input.tool_name);
    let noun = extract_noun(&input.tool_name, &input.tool_input);
    let entity = "agent";
    let ctx = EvalContext {
        entity,
        verb: &verb,
        noun: &noun,
        cwd: &input.cwd,
        tool_input: &input.tool_input,
        verb_str: &verb_str_owned,
    };

    let decision = compiled.evaluate_with_context(&ctx);

    if json_output {
        let output = serde_json::json!({
            "effect": format!("{}", decision.effect),
            "reason": decision.reason,
            "matched_rules": decision.trace.matched_rules.iter().map(|m| {
                serde_json::json!({
                    "rule_index": m.rule_index,
                    "description": m.description,
                    "effect": format!("{}", m.effect),
                })
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
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Input:");
        println!("  tool:   {}", input.tool_name);
        println!("  entity: {}", entity);
        println!("  verb:   {}", verb_str_owned);
        println!("  noun:   {}", noun);
        println!();

        println!("Decision: {}", decision.effect);
        if let Some(ref reason) = decision.reason {
            println!("Reason:   {}", reason);
        }
        println!();

        if !decision.trace.matched_rules.is_empty() {
            println!("Matched rules:");
            for m in &decision.trace.matched_rules {
                println!("  [{}] {} -> {}", m.rule_index, m.description, m.effect);
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

/// Initialize a new clash policy with deny-all defaults.
///
/// When a policy already exists and stdin is a TTY, offers the user a choice
/// to reconfigure from scratch or update the existing configuration.
#[instrument(level = Level::TRACE)]
fn run_init(no_bypass: bool) -> Result<()> {
    use std::io::IsTerminal;

    let path = ClashSettings::policy_file()?;

    if path.exists() && path.is_dir() {
        anyhow::bail!(
            "{} is a directory. Remove it first, then run `clash init`.",
            path.display()
        );
    }

    if path.exists() {
        if !std::io::stdin().is_terminal() {
            anyhow::bail!(
                "Clash is already configured at {}.\n\
                 Run `clash init` interactively to reconfigure, or use `clash policy setup` to update.",
                path.display()
            );
        }

        let theme = dialoguer::theme::ColorfulTheme::default();
        let choice = dialoguer::Select::with_theme(&theme)
            .with_prompt(format!(
                "Clash is already configured at {}. What would you like to do?",
                path.display()
            ))
            .items(&[
                "Reconfigure from scratch (replaces current policy)",
                "Update existing configuration",
                "Cancel",
            ])
            .default(1)
            .interact()?;

        return match choice {
            0 => {
                // Reconfigure: overwrite with defaults, then run wizard
                std::fs::write(&path, DEFAULT_POLICY)?;
                println!("Reset to default policy.\n");
                run_init_wizard(&path)
            }
            1 => {
                // Update: run wizard against existing policy
                run_init_wizard(&path)
            }
            _ => {
                println!("Cancelled.");
                Ok(())
            }
        };
    }

    // Fresh install
    std::fs::create_dir_all(ClashSettings::settings_dir()?)?;
    std::fs::write(&path, DEFAULT_POLICY)?;

    // Set bypass_permissions by default so clash is the sole permission handler.
    if !no_bypass && let Err(e) = set_bypass_permissions() {
        warn!(error = %e, "Could not set bypassPermissions in Claude Code settings");
        eprintln!(
            "warning: could not configure Claude Code to use clash as sole permission handler.\n\
             You may see double prompts. Run with --dangerously-skip-permissions to avoid this."
        );
    }

    println!("Clash initialized.\n");
    println!("What happens now:");
    println!("  - Claude can read files in this project");
    println!("  - Everything else (editing, commands, web access) is blocked");
    println!("  - When Claude hits a block, you'll see how to allow it");
    println!();

    // Offer to run the wizard
    let run_wizard = dialoguer::Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt("Configure what Claude can do now?")
        .default(true)
        .interact()
        .unwrap_or(false);

    if run_wizard {
        run_init_wizard(&path)?;
    } else {
        println!("Everything is blocked except reading files.");
        println!("Run \"clash policy setup\" when you're ready to configure.");
    }

    Ok(())
}

/// Run the interactive wizard against the policy at `path`.
fn run_init_wizard(path: &std::path::Path) -> Result<()> {
    let text = std::fs::read_to_string(path)?;
    let profile = clash::policy::edit::resolve_profile(&text, None)?;
    let cwd = std::env::current_dir()
        .context("could not determine current directory")?
        .to_string_lossy()
        .into_owned();

    let modified = clash::wizard::run(&text, &profile, &cwd)?;
    if modified != text {
        std::fs::write(path, &modified)?;
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

/// Verb shortcut: bare verb → (rule string, default fs constraints).
/// Returns None if the input isn't a known bare verb (i.e. it's a full rule).
///
/// Note: bash rules have no per-rule fs constraints — sandbox is set at profile level.
fn verb_shortcut(verb: &str, cwd: &str) -> Option<Vec<(&'static str, Vec<String>)>> {
    match verb {
        "read" => Some(vec![(
            "allow read *",
            vec![format!("read:subpath({})", cwd)],
        )]),
        "edit" | "editing" => Some(vec![
            ("allow edit *", vec![format!("write:subpath({})", cwd)]),
            (
                "allow write *",
                vec![format!("write+create:subpath({})", cwd)],
            ),
        ]),
        "bash" | "commands" => Some(vec![(
            "allow bash *",
            vec![], // No per-rule fs; sandbox is profile-level
        )]),
        "web" => Some(vec![
            ("allow webfetch *", vec![]),
            ("allow websearch *", vec![]),
        ]),
        _ => None,
    }
}

/// Returns sandbox statements for a bare verb shortcut, if applicable.
fn verb_sandbox_statements(verb: &str, cwd: &str) -> Option<Vec<String>> {
    match verb {
        "bash" | "commands" => Some(vec![format!("fs full subpath({})", cwd)]),
        _ => None,
    }
}

/// Like verb_shortcut but for deny effect.
fn deny_verb_shortcut(verb: &str) -> Option<Vec<&'static str>> {
    match verb {
        "read" => Some(vec!["deny read *"]),
        "edit" | "editing" => Some(vec!["deny edit *", "deny write *"]),
        "bash" | "commands" => Some(vec!["deny bash *"]),
        "web" => Some(vec!["deny webfetch *", "deny websearch *"]),
        _ => None,
    }
}

/// Handle `clash policy allow <rule>` and `clash policy deny <rule>`.
///
/// Supports two forms:
/// - Bare verb: `clash policy allow edit` → expands with cwd-scoped defaults
/// - Full rule: `clash policy allow "bash git *" --fs "..."` → passed through as-is
#[instrument(level = Level::TRACE)]
fn handle_allow_or_deny(
    effect: Effect,
    rule: &str,
    profile: Option<&str>,
    constraints: edit::InlineConstraintArgs,
    dry_run: bool,
) -> Result<()> {
    let cwd = std::env::current_dir()
        .context("could not determine current directory")?
        .to_string_lossy()
        .into_owned();

    let has_explicit_constraints = !constraints.fs.is_empty()
        || !constraints.url.is_empty()
        || !constraints.args.is_empty()
        || constraints.pipe.is_some()
        || constraints.redirect.is_some()
        || constraints.network.is_some();

    // Check for bare verb shortcut (only when no explicit constraints given)
    if effect == Effect::Allow
        && !has_explicit_constraints
        && let Some(expansions) = verb_shortcut(rule, &cwd)
    {
        let (path, text) = load_policy()?;
        let target_profile = edit::resolve_profile(&text, profile)?;

        let mut current = text.clone();
        let mut any_added = false;

        // Set profile-level sandbox if this verb requires one (e.g. bash)
        if let Some(sandbox_stmts) = verb_sandbox_statements(rule, &cwd) {
            let stmt_refs: Vec<&str> = sandbox_stmts.iter().map(|s| s.as_str()).collect();
            let modified = edit::set_sandbox(&current, &target_profile, &stmt_refs)?;
            if modified != current {
                any_added = true;
                current = modified;
            }
        }

        for (rule_str, default_fs) in &expansions {
            let constraints = edit::InlineConstraintArgs {
                fs: default_fs.clone(),
                ..Default::default()
            };
            let modified = edit::add_rule(&current, &target_profile, rule_str, &constraints)?;
            if modified != current {
                any_added = true;
                current = modified;
            }
        }

        if any_added {
            if dry_run {
                print!("{}", current);
            } else {
                std::fs::write(&path, &current)?;
                let has_sandbox = verb_sandbox_statements(rule, &cwd).is_some();
                let scope = if has_sandbox || expansions.iter().any(|(_, fs)| !fs.is_empty()) {
                    format!(" (files in {})", cwd)
                } else {
                    String::new()
                };
                println!("Allowed: {}{}", rule, scope);
            }
        } else {
            println!("Already allowed: {} is already in your policy.", rule);
        }
        return Ok(());
    }

    if effect == Effect::Deny
        && !has_explicit_constraints
        && let Some(deny_rules) = deny_verb_shortcut(rule)
    {
        let (path, text) = load_policy()?;
        let target_profile = edit::resolve_profile(&text, profile)?;

        let mut current = text.clone();
        let mut any_added = false;

        for rule_str in &deny_rules {
            let constraints = edit::InlineConstraintArgs::default();
            let modified = edit::add_rule(&current, &target_profile, rule_str, &constraints)?;
            if modified != current {
                any_added = true;
                current = modified;
            }
        }

        if any_added {
            if dry_run {
                print!("{}", current);
            } else {
                std::fs::write(&path, &current)?;
                println!("Denied: {}", rule);
            }
        } else {
            println!("Already denied: {} is already in your policy.", rule);
        }
        return Ok(());
    }

    // Full rule form: prepend effect and pass through
    let full_rule = format!("{} {}", effect, rule);
    constraints.validate()?;
    handle_add_rule(&full_rule, profile, &constraints, dry_run)
}

/// Show what Claude can and cannot do (human-readable).
#[instrument(level = Level::TRACE)]
fn run_status(_json: bool) -> Result<()> {
    // TODO: implement full status rendering (Task #4)
    let (_path, text) = load_policy()?;
    let doc = clash::policy::parse::parse_policy(&text).context("failed to parse policy file")?;

    let default_perm = doc.policy.default;
    let profile_name = doc
        .default_config
        .as_ref()
        .map(|dc| dc.profile.as_str())
        .unwrap_or("(none)");

    let rules = flatten_profile(profile_name, &doc.profile_defs).unwrap_or_default();

    let default_desc = match default_perm {
        Effect::Deny => "blocked",
        Effect::Allow => "allowed",
        _ => "prompted",
    };

    if rules.is_empty() && doc.statements.is_empty() {
        println!("No rules configured.");
        println!(
            "Default: {} (unmatched actions are {})",
            default_perm, default_desc
        );
        println!("\nRun \"clash policy setup\" to configure what Claude can do.");
        return Ok(());
    }

    // Collect allow and deny summaries
    let mut allowed = Vec::new();
    let mut blocked = Vec::new();

    for r in &rules {
        let noun_str = clash::policy::ast::format_pattern_str(&r.noun);
        match r.effect {
            Effect::Allow => allowed.push(format!("{} {}", r.verb, noun_str)),
            Effect::Deny => blocked.push(format!("{} {}", r.verb, noun_str)),
            _ => {}
        }
    }

    if !allowed.is_empty() {
        println!("Claude can:");
        for a in &allowed {
            println!("  {}", a);
        }
    }

    if !blocked.is_empty() {
        println!("\nBlocked:");
        for b in &blocked {
            println!("  {}", b);
        }
    }

    println!(
        "\nDefault: {} (unmatched actions are {})",
        default_perm, default_desc
    );

    let path = ClashSettings::policy_file()?;
    let rule_count = rules.len() + doc.statements.len();
    println!(
        "Policy: {} ({} rules, profile: {})",
        path.display(),
        rule_count,
        profile_name
    );
    println!("\nRun \"clash policy setup\" to reconfigure.");

    Ok(())
}

/// Interactive policy configuration wizard.
fn run_setup_wizard() -> Result<()> {
    let (path, text) = load_policy()?;
    let profile = clash::policy::edit::resolve_profile(&text, None)?;
    let cwd = std::env::current_dir()
        .context("could not determine current directory")?
        .to_string_lossy()
        .into_owned();

    let modified = clash::wizard::run(&text, &profile, &cwd)?;

    if modified != text {
        std::fs::write(&path, &modified)?;
    }

    Ok(())
}

/// Load the policy file, returning its path and contents.
fn load_policy() -> Result<(std::path::PathBuf, String)> {
    let path = ClashSettings::policy_file()?;
    if path.is_dir() {
        anyhow::bail!(
            "{} is a directory, not a file. Remove it and run `clash init` to create a policy.",
            path.display()
        );
    }
    let text = std::fs::read_to_string(&path).with_context(|| {
        if !path.exists() {
            format!(
                "No policy file found at {}. Run `clash init` first.",
                path.display()
            )
        } else {
            format!("Failed to read {}", path.display())
        }
    })?;
    Ok((path, text))
}

/// Handle `clash policy add-rule`.
fn handle_add_rule(
    rule: &str,
    profile: Option<&str>,
    constraints: &edit::InlineConstraintArgs,
    dry_run: bool,
) -> Result<()> {
    let (path, text) = load_policy()?;
    let target_profile = edit::resolve_profile(&text, profile)?;
    let modified = edit::add_rule(&text, &target_profile, rule, constraints)?;

    if modified == text {
        println!(
            "Rule already exists in profile '{}': {}",
            target_profile, rule
        );
        return Ok(());
    }

    if dry_run {
        print!("{}", modified);
    } else {
        std::fs::write(&path, &modified)?;
        println!("Added rule to profile '{}': {}", target_profile, rule);
    }
    Ok(())
}

/// Handle `clash policy remove-rule`.
fn handle_remove_rule(rule: &str, profile: Option<&str>, dry_run: bool) -> Result<()> {
    let (path, text) = load_policy()?;
    let target_profile = edit::resolve_profile(&text, profile)?;
    let modified = edit::remove_rule(&text, &target_profile, rule)?;

    if dry_run {
        print!("{}", modified);
    } else {
        std::fs::write(&path, &modified)?;
        println!("Removed rule from profile '{}': {}", target_profile, rule);
    }
    Ok(())
}

/// Handle `clash policy list-rules`.
fn handle_list_rules(profile: Option<&str>, json: bool) -> Result<()> {
    let (_path, text) = load_policy()?;
    let doc = clash::policy::parse::parse_policy(&text).context("failed to parse policy file")?;

    // Determine target profile
    let target = match profile {
        Some(p) => p.to_string(),
        None => doc.default_config
            .as_ref()
            .map(|dc| dc.profile.clone())
            .ok_or_else(|| anyhow::anyhow!(
                "No active profile found. Use --profile or upgrade to the new policy format with `clash init`."
            ))?,
    };

    let rules = flatten_profile(&target, &doc.profile_defs)
        .with_context(|| format!("failed to resolve profile '{}'", target))?;

    if json {
        let json_rules: Vec<serde_json::Value> = rules
            .iter()
            .map(|r| {
                let noun_str = clash::policy::ast::format_pattern_str(&r.noun);
                let mut obj = serde_json::json!({
                    "effect": r.effect.to_string(),
                    "verb": r.verb,
                    "noun": noun_str,
                });
                if r.constraints.is_some() {
                    obj["has_constraints"] = serde_json::json!(true);
                }
                obj
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "profile": target,
                "rules": json_rules,
            }))?
        );
    } else {
        println!("Profile: {}", target);
        println!();
        if rules.is_empty() {
            println!("  (no rules)");
        } else {
            println!("  {:<8} {:<12} NOUN", "EFFECT", "VERB");
            println!("  {:<8} {:<12} ----", "------", "----");
            for r in &rules {
                let noun_str = clash::policy::ast::format_pattern_str(&r.noun);
                let constraint_note = if r.constraints.is_some() {
                    " [+constraints]"
                } else {
                    ""
                };
                println!(
                    "  {:<8} {:<12} {}{}",
                    r.effect.to_string(),
                    r.verb,
                    noun_str,
                    constraint_note
                );
            }
        }
    }
    Ok(())
}

/// Handle `clash policy use <profile>`.
fn handle_use_profile(profile: &str) -> Result<()> {
    let (path, text) = load_policy()?;

    // Validate the profile exists by parsing.
    let doc = clash::policy::parse::parse_policy(&text).context("failed to parse policy")?;
    if !doc.profile_defs.contains_key(profile) {
        let mut available: Vec<&str> = doc.profile_defs.keys().map(|s| s.as_str()).collect();
        available.sort();
        anyhow::bail!(
            "profile '{}' not found. Available profiles: {}",
            profile,
            available.join(", ")
        );
    }

    let updated =
        edit::set_active_profile(&text, profile).context("failed to update active profile")?;
    std::fs::write(&path, &updated)
        .with_context(|| format!("failed to write {}", path.display()))?;
    println!("Active profile set to '{}'", profile);
    Ok(())
}

/// Handle `clash policy show`.
fn handle_show_policy(json: bool) -> Result<()> {
    let (path, text) = load_policy()?;
    let info = edit::policy_info(&text)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "default_permission": info.default_permission,
                "active_profile": info.active_profile,
                "profiles": info.profiles,
                "policy_file": path.display().to_string(),
            }))?
        );
    } else {
        println!("Policy file:        {}", path.display());
        println!("Default permission: {}", info.default_permission);
        println!("Active profile:     {}", info.active_profile);
        println!("Profiles:           {}", info.profiles.join(", "));
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
        println!("  Verbs:   {}", schema.rule_syntax.verbs.join(", "));
        println!("  Caps:    {}", schema.rule_syntax.capabilities.join(", "));
        println!("\n  Constraints:");
        print_fields(&schema.rule_syntax.constraints, 4);
        println!("\n  Filesystem filters:");
        print_fields(&schema.rule_syntax.fs_filters, 4);
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
                filename: "policy.sexp".into(),
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
        PolicyCmd::Allow {
            rule,
            profile,
            fs,
            url,
            args,
            pipe,
            redirect,
            dry_run,
        } => {
            let constraints = edit::InlineConstraintArgs {
                fs,
                url,
                args,
                pipe,
                redirect,
                network: None,
            };
            handle_allow_or_deny(
                Effect::Allow,
                &rule,
                profile.as_deref(),
                constraints,
                dry_run,
            )
        }
        PolicyCmd::Deny {
            rule,
            profile,
            fs,
            url,
            args,
            pipe,
            redirect,
            dry_run,
        } => {
            let constraints = edit::InlineConstraintArgs {
                fs,
                url,
                args,
                pipe,
                redirect,
                network: None,
            };
            handle_allow_or_deny(
                Effect::Deny,
                &rule,
                profile.as_deref(),
                constraints,
                dry_run,
            )
        }
        PolicyCmd::Remove {
            rule,
            profile,
            dry_run,
        } => handle_remove_rule(&rule, profile.as_deref(), dry_run),
        PolicyCmd::List { profile, json } => handle_list_rules(profile.as_deref(), json),
        PolicyCmd::Use { profile } => handle_use_profile(&profile),
        PolicyCmd::Setup => run_setup_wizard(),
        PolicyCmd::Show { json } => handle_show_policy(json),
        PolicyCmd::Schema { json } => handle_schema(json),
        PolicyCmd::Explain { json, tool, input } => run_explain(json, tool, input),
        PolicyCmd::Migrate { dry_run, default } => run_migrate(dry_run, &default),
    }
}
