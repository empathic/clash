use std::fmt::Display;
use std::fs::OpenOptions;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use clash::policy::edit;
use clash::policy::parse::{desugar_legacy, flatten_profile, format_rule};
use clash::policy::{Effect, LegacyPermissions, PolicyConfig, PolicyDocument};
use claude_settings::SettingsLevel;
use tracing::level_filters::LevelFilter;
use tracing::{Level, error, info, instrument};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::prelude::*;

use clash::handlers;
use clash::hooks::{HookOutput, SessionStartHookInput, ToolUseHookInput, exit_code};
use clash::permissions::check_permission;
use clash::sandbox;
use clash::settings::{ClashSettings, DEFAULT_POLICY};

use clash::policy::sandbox_types::SandboxPolicy;

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

    /// Handle SessionStart hook - validate settings and report status
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
                let input = SessionStartHookInput::from_reader(std::io::stdin().lock())?;
                handlers::handle_session_start(&input)?
            }
        };

        output.write_stdout()?;
        Ok(())
    }
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
enum PolicyCmd {
    /// Add a rule to the policy
    AddRule {
        /// Rule in "effect verb noun" format (e.g. "allow bash git *", "deny read .env")
        rule: String,
        /// Target profile (default: active profile from default.profile)
        #[arg(long)]
        profile: Option<String>,
        /// Print modified policy to stdout without writing
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove a rule from the policy
    RemoveRule {
        /// Rule in "effect verb noun" format to remove (e.g. "deny bash git push*")
        rule: String,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        dry_run: bool,
    },
    /// List rules in the active profile (with includes resolved)
    ListRules {
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Show active profile, default permission, and available profiles
    Show {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(subcommand, about = "commands for agents to call back into clash")]
    Hook(HooksCmd),

    /// Apply sandbox restrictions and exec commands
    #[command(subcommand)]
    Sandbox(SandboxCmd),

    /// View and edit policy rules
    #[command(subcommand)]
    Policy(PolicyCmd),

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

    /// Explain which policy rule would match a given tool invocation
    ///
    /// Accepts either CLI arguments or JSON from stdin.
    /// CLI:   clash explain bash "git push"
    /// Stdin: echo '{"tool_name":"Bash","tool_input":{"command":"git push"}}' | clash explain
    Explain {
        /// Output as JSON instead of human-readable text
        #[arg(long)]
        json: bool,

        /// Tool type: bash, read, write, edit (or full tool name like Bash, Read, etc.)
        tool: Option<String>,

        /// The command, file path, or noun to check
        input: Option<String>,
    },

    /// Initialize a new clash policy.yaml with a safe default configuration
    Init {
        /// Overwrite an existing policy.yaml file
        #[arg(long)]
        force: bool,
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
    if let Some(parent) = std::path::Path::new(&log_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let log_file = OpenOptions::new().create(true).append(true).open(&log_path);

    match log_file {
        Ok(file) => {
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .pretty()
                        .with_level(true)
                        .with_writer(file)
                        .with_file(true)
                        .with_line_number(true)
                        .with_target(false)
                        .with_span_events(FmtSpan::CLOSE)
                        .with_filter(LevelFilter::from_level(Level::DEBUG)),
                )
                .init();
        }
        Err(_) => {
            // Fallback to stderr if log file can't be opened.
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_level(true)
                        .with_writer(std::io::stderr)
                        .with_file(true)
                        .with_line_number(true)
                        .with_target(false)
                        .with_filter(LevelFilter::from_level(Level::INFO)),
                )
                .init();
        }
    }
}

/// Log an error and exit with code 1. Used for all non-hook subcommands.
fn run_or_exit(label: &str, result: Result<()>) {
    if let Err(e) = result {
        error!("{} error: {}", label, e);
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
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
        Commands::Sandbox(cmd) => run_or_exit("Sandbox", run_sandbox(cmd)),
        Commands::Launch { policy, args } => run_or_exit("Launch", run_launch(policy, args)),
        Commands::Migrate { dry_run, default } => {
            run_or_exit("Migration", run_migrate(dry_run, &default))
        }
        Commands::Explain { json, tool, input } => {
            run_or_exit("Explain", run_explain(json, tool, input))
        }
        Commands::Init { force } => run_or_exit("Init", run_init(force)),
        Commands::Policy(cmd) => run_or_exit("Policy", run_policy(cmd)),
    }

    Ok(())
}

/// Parse shared sandbox arguments (policy JSON + cwd).
fn parse_sandbox_args(policy_json: &str, cwd: &str) -> Result<(SandboxPolicy, std::path::PathBuf)> {
    let policy: SandboxPolicy =
        serde_json::from_str(policy_json).context("failed to parse --policy JSON")?;
    Ok((policy, std::path::PathBuf::from(cwd)))
}

/// Run a command inside a sandbox.
#[instrument(level = Level::TRACE)]
fn run_sandbox(cmd: SandboxCmd) -> Result<()> {
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
        // Validate it parses
        clash::policy::parse::parse_yaml(&contents)
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
            "SessionStart": [{
                "hooks": [{
                    "type": "command",
                    "command": format!("{} hook session-start", clash_bin_str)
                }]
            }]
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

/// Migrate legacy Claude Code permissions to a policy.yaml file.
///
/// Reads the effective Claude Code settings, desugars the permission rules
/// into policy statements, and writes a `policy.yaml` file.
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
        default_config: None,
        profile_defs: Default::default(),
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
        let path = ClashSettings::policy_file()?;
        if path.exists() {
            eprintln!(
                "Warning: {} already exists. Use --dry-run to preview, or remove the file first.",
                path.display()
            );
            anyhow::bail!("policy.yaml already exists at {}", path.display());
        }
        std::fs::create_dir_all(ClashSettings::settings_dir()?)?;
        std::fs::write(&path, &output)?;
        println!("Wrote policy to {}", path.display());
        println!(
            "Migrated {} rule(s) from legacy Claude Code permissions.",
            doc.statements.len()
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
    use clash::permissions::{build_eval_context, extract_noun, resolve_verb};

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
                eprintln!("Create ~/.clash/policy.yaml or configure Claude Code permissions.");
            }
            return Ok(());
        }
    };

    let (verb, verb_str_owned) = resolve_verb(&input.tool_name);
    let noun = extract_noun(&input.tool_name, &input.tool_input);
    let entity = "agent";
    let ctx = build_eval_context(
        entity,
        &verb,
        &verb_str_owned,
        &noun,
        &input.cwd,
        &input.tool_input,
    );

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

/// Initialize a new clash policy.yaml with safe defaults.
#[instrument(level = Level::TRACE)]
fn run_init(force: bool) -> Result<()> {
    let path = ClashSettings::policy_file()?;

    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists. Use --force to overwrite.",
            path.display()
        );
    }

    std::fs::create_dir_all(ClashSettings::settings_dir()?)?;
    std::fs::write(&path, DEFAULT_POLICY)?;
    println!("Wrote default policy to {}", path.display());
    println!("Edit the file to customize rules for your environment.");

    Ok(())
}

/// Load the policy.yaml file, returning its path and contents.
fn load_policy_yaml() -> Result<(std::path::PathBuf, String)> {
    let path = ClashSettings::policy_file()?;
    let yaml = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "No policy.yaml found at {}. Run `clash init` first.",
            path.display()
        )
    })?;
    Ok((path, yaml))
}

/// Handle `clash policy add-rule`.
fn handle_add_rule(rule: &str, profile: Option<&str>, dry_run: bool) -> Result<()> {
    let (path, yaml) = load_policy_yaml()?;
    let target_profile = edit::resolve_profile(&yaml, profile)?;
    let modified = edit::add_rule(&yaml, &target_profile, rule)?;

    if modified == yaml {
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
    let (path, yaml) = load_policy_yaml()?;
    let target_profile = edit::resolve_profile(&yaml, profile)?;
    let modified = edit::remove_rule(&yaml, &target_profile, rule)?;

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
    let (_path, yaml) = load_policy_yaml()?;
    let doc = clash::policy::parse::parse_yaml(&yaml).context("failed to parse policy.yaml")?;

    // Determine target profile
    let target = match profile {
        Some(p) => p.to_string(),
        None => doc.default_config
            .as_ref()
            .map(|dc| dc.profile.clone())
            .ok_or_else(|| anyhow::anyhow!(
                "No active profile found. Use --profile or upgrade to the new policy format with `clash init --force`."
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

/// Handle `clash policy show`.
fn handle_show_policy(json: bool) -> Result<()> {
    let (path, yaml) = load_policy_yaml()?;
    let info = edit::policy_info(&yaml)?;

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

/// Handle `clash policy` subcommands.
#[instrument(level = Level::TRACE)]
fn run_policy(cmd: PolicyCmd) -> Result<()> {
    match cmd {
        PolicyCmd::AddRule {
            rule,
            profile,
            dry_run,
        } => handle_add_rule(&rule, profile.as_deref(), dry_run),
        PolicyCmd::RemoveRule {
            rule,
            profile,
            dry_run,
        } => handle_remove_rule(&rule, profile.as_deref(), dry_run),
        PolicyCmd::ListRules { profile, json } => handle_list_rules(profile.as_deref(), json),
        PolicyCmd::Show { json } => handle_show_policy(json),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_start_output_serialization() {
        let output = HookOutput::session_start(Some("test context".into()));
        let mut buf = Vec::new();
        output.write_to(&mut buf).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(json["hookSpecificOutput"]["hookEventName"], "SessionStart");
        assert_eq!(
            json["hookSpecificOutput"]["additionalContext"],
            "test context"
        );
        assert_eq!(json["continue"], true);
    }
}
