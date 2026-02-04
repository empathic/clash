use std::fmt::Display;
use std::fs::OpenOptions;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use claude_settings::SettingsLevel;
use claude_settings::policy::parse::{desugar_legacy, format_rule};
use claude_settings::policy::{Effect, LegacyPermissions, PolicyConfig, PolicyDocument};
use tracing::level_filters::LevelFilter;
use tracing::{Level, error, info, instrument};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::prelude::*;

mod audit;
mod hooks;
mod notifications;
mod permissions;
mod sandbox;
mod settings;

use claude_settings::PermissionRule;
use claude_settings::sandbox::SandboxPolicy;
use hooks::{HookOutput, HookSpecificOutput, SessionStartHookInput, ToolUseHookInput, exit_code};
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

    /// Handle SessionStart hook - validate settings and report status
    #[command(name = "session-start")]
    SessionStart,
}

impl HooksCmd {
    #[instrument(level = Level::TRACE, skip(self))]
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
            Self::SessionStart => {
                let input = SessionStartHookInput::from_reader(std::io::stdin().lock())?;
                handle_session_start(&input)?
            }
        };

        output.write_stdout()?;
        std::process::exit(exit_code::SUCCESS);
    }
}

/// Handle a permission request - decide whether to approve or deny on behalf of user.
///
/// When the policy evaluates to "ask" and a Zulip bot is configured, the request
/// is forwarded to Zulip and we poll for a human response. If no Zulip config is
/// present or the poll times out, we fall through to let the terminal user decide.
#[instrument(level = Level::TRACE, skip(input, settings))]
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
            // Ask or no decision: notify and try Zulip resolution.
            _ => {
                send_permission_desktop_notification(input, settings);
                resolve_via_zulip_or_continue(input, settings)
            }
        },
        _ => pre_tool_result,
    })
}

/// Send a desktop notification for a permission request, if enabled.
fn send_permission_desktop_notification(
    input: &ToolUseHookInput,
    settings: &settings::ClashSettings,
) {
    if !settings.notifications.desktop {
        return;
    }
    let summary = match input.tool_name.as_str() {
        "Bash" => {
            let cmd = input.tool_input["command"].as_str().unwrap_or("(unknown)");
            format!("Permission needed: Bash `{}`", cmd)
        }
        _ => format!("Permission needed: {}", input.tool_name),
    };
    notifications::send_desktop_notification("Clash: Permission Request", &summary);
}

/// Attempt to resolve a permission ask via Zulip. Falls back to `continue_execution`.
#[instrument(level = Level::TRACE, skip(input, settings))]
fn resolve_via_zulip_or_continue(
    input: &ToolUseHookInput,
    settings: &settings::ClashSettings,
) -> HookOutput {
    let Some(ref zulip_config) = settings.notifications.zulip else {
        return HookOutput::continue_execution();
    };

    let request = notifications::PermissionRequest {
        tool_name: input.tool_name.clone(),
        tool_input: input.tool_input.clone(),
        session_id: input.session_id.clone(),
        cwd: input.cwd.clone(),
    };

    let client = notifications::ZulipClient::new(zulip_config);
    match client.resolve_permission(&request) {
        Ok(Some(notifications::PermissionResponse::Approve)) => {
            HookOutput::approve_permission(None)
        }
        Ok(Some(notifications::PermissionResponse::Deny(reason))) => {
            HookOutput::deny_permission(reason, false)
        }
        Ok(None) => {
            // Timeout — fall through to terminal.
            info!("Zulip resolution timed out, falling through to terminal");
            HookOutput::continue_execution()
        }
        Err(e) => {
            tracing::warn!(error = %e, "Zulip resolution failed, falling through to terminal");
            HookOutput::continue_execution()
        }
    }
}

/// Handle a session start event — validate policy/settings and report status to Claude.
#[instrument(level = Level::TRACE, skip(input))]
fn handle_session_start(input: &SessionStartHookInput) -> anyhow::Result<HookOutput> {
    let mut lines: Vec<String> = Vec::new();

    // 1. Check policy file
    let policy_path = settings::ClashSettings::policy_file();
    if policy_path.exists() {
        match std::fs::read_to_string(&policy_path) {
            Ok(contents) => match claude_settings::policy::parse::parse_yaml(&contents) {
                Ok(doc) => {
                    let rule_count = doc.statements.len()
                        + doc
                            .profile_defs
                            .values()
                            .map(|p| p.rules.len())
                            .sum::<usize>();
                    let format = if doc.profile_defs.is_empty() {
                        "legacy"
                    } else {
                        "new"
                    };
                    match claude_settings::policy::CompiledPolicy::compile(&doc) {
                        Ok(_) => {
                            lines.push(format!(
                                "policy.yaml: OK ({} rules, format={}, default={})",
                                rule_count, format, doc.policy.default,
                            ));
                        }
                        Err(e) => {
                            lines.push(format!("ISSUE: policy.yaml compile error: {}", e));
                        }
                    }
                }
                Err(e) => {
                    lines.push(format!("ISSUE: policy.yaml parse error: {}", e));
                }
            },
            Err(e) => {
                lines.push(format!("ISSUE: policy.yaml read error: {}", e));
            }
        }
    } else {
        lines.push("policy.yaml: not found (using legacy permissions)".into());
    }

    // 2. Validate notification config from the same policy file
    if policy_path.exists()
        && let Ok(contents) = std::fs::read_to_string(&policy_path)
    {
        let (notif_config, notif_warning) = settings::parse_notification_config(&contents);
        if let Some(warning) = notif_warning {
            lines.push(format!("ISSUE: {}", warning));
        } else {
            let zulip_status = if notif_config.zulip.is_some() {
                "configured"
            } else {
                "not configured"
            };
            lines.push(format!(
                "notifications: OK (desktop={}, zulip={})",
                notif_config.desktop, zulip_status
            ));
        }
    }

    // 3. Check settings file
    let settings_path = settings::ClashSettings::settings_file();
    match settings::ClashSettings::load() {
        Ok(s) => {
            lines.push(format!("settings: OK (engine_mode={:?})", s.engine_mode));
        }
        Err(_) if !settings_path.exists() => {
            lines.push("settings: using defaults (no settings.json)".into());
        }
        Err(e) => {
            lines.push(format!("ISSUE: settings load error: {}", e));
        }
    }

    // 4. Check sandbox support
    let support = sandbox::check_support();
    match support {
        sandbox::SupportLevel::Full => {
            lines.push("sandbox: fully supported".into());
        }
        sandbox::SupportLevel::Partial { ref missing } => {
            lines.push(format!(
                "sandbox: partial (missing: {})",
                missing.join(", ")
            ));
        }
        sandbox::SupportLevel::Unsupported { ref reason } => {
            lines.push(format!("sandbox: unsupported ({})", reason));
        }
    }

    // 5. Session metadata
    if let Some(ref source) = input.source {
        lines.push(format!("session source: {}", source));
    }
    if let Some(ref model) = input.model {
        lines.push(format!("model: {}", model));
    }

    info!(context = %lines.join("; "), "SessionStart validation");

    let context = if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    };

    Ok(HookOutput::session_start(context))
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

    /// Explain which policy rule would match a given tool invocation
    ///
    /// Reads JSON from stdin with tool_name and tool_input fields,
    /// evaluates against the loaded policy, and shows the decision trace.
    Explain {
        /// Output as JSON instead of human-readable text
        #[arg(long)]
        json: bool,
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
        dirs::home_dir()
            .map(|h| h.join(".clash").join("clash.log"))
            .unwrap_or_else(|| std::path::PathBuf::from("clash.log"))
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
                        .with_ansi(true)
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
                        .with_filter(LevelFilter::from_level(Level::WARN)),
                )
                .init();
        }
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
        Commands::Explain { json } => {
            if let Err(e) = run_explain(json) {
                error!("Explain error: {}", e);
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Init { force } => {
            if let Err(e) = run_init(force) {
                error!("Init error: {}", e);
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    }

    Ok(())
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
            let policy: SandboxPolicy =
                serde_json::from_str(&policy).context("failed to parse --policy JSON")?;
            let cwd_path = std::path::Path::new(&cwd);

            // This does not return on success (replaces the process via execvp)
            match sandbox::exec_sandboxed(&policy, cwd_path, &command) {
                Err(e) => anyhow::bail!("sandbox exec failed: {}", e),
                // exec_sandboxed returns Infallible on success, so Ok is unreachable
            }
        }
        SandboxCmd::Test {
            policy,
            cwd,
            command,
        } => {
            let policy: SandboxPolicy =
                serde_json::from_str(&policy).context("failed to parse --policy JSON")?;
            let cwd_path = std::path::Path::new(&cwd);

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
            "SessionStart": [{
                "hooks": [{
                    "type": "command",
                    "command": format!("{} hook session-start", clash_bin_str)
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
/// Reads JSON from stdin: `{"tool_name":"Bash","tool_input":{"command":"git push"}}`
/// Evaluates against the loaded policy and prints the decision trace.
#[instrument(level = Level::TRACE)]
fn run_explain(json_output: bool) -> Result<()> {
    use claude_settings::policy::{EvalContext, Verb};

    // Read input from stdin
    let input: ExplainInput = serde_json::from_reader(std::io::stdin().lock()).context(
        "failed to parse JSON from stdin (expected {\"tool_name\":..., \"tool_input\":...})",
    )?;

    // Load settings and compile policy
    let settings = settings::ClashSettings::load_or_create()?;
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

    // Map tool_name → verb (same logic as permissions.rs)
    let verb = Verb::from_tool_name(&input.tool_name);
    let fallback_verb = Verb::Execute;
    let verb_ref = verb.as_ref().unwrap_or(&fallback_verb);
    let verb_str_owned = if let Some(ref v) = verb {
        v.rule_name().to_string()
    } else {
        input.tool_name.to_lowercase()
    };

    // Extract noun from tool_input (same logic as permissions.rs)
    let noun = match input.tool_name.as_str() {
        "Bash" => input.tool_input["command"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        "Read" | "Write" | "Edit" => input.tool_input["file_path"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        _ => input.tool_input.to_string(),
    };
    let entity = "agent";

    let ctx = EvalContext {
        entity,
        verb: verb_ref,
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

/// Default policy template written by `clash init`.
const DEFAULT_POLICY: &str = r#"# Clash policy — safe defaults for local development.
#
# Evaluation: all matching statements are collected, then precedence applies:
#   deny > ask > allow
# If no statement matches, the default effect is used (ask).

default:
  permission: ask
  profile: main

profiles:
  cwd:
    rules:
      allow * *: 
        fs:
          read + write + execute: subpath($CWD)
  tmp:
    rules:
      allow * *:
        fs:
          read + write + execute: regex(^/tmp)
  
  global:
    rules:
      ask * *:
        fs:
          read: "!subpath($CWD)"
      
  main:
    include: [cwd, global]
    rules:
      # ── Git: deny commit and push ─────────────────────────────
      ask bash git commit*:
      deny bash git push*:
      deny bash git merge*:

      # ── Git: deny destructive operations ──────────────────────
      deny bash git reset --hard*:
      deny bash git clean*:
      deny bash git branch -D*:

      # ── Dangerous commands ─────────────────────────────────────
      deny bash sudo *:
"#;

/// Initialize a new clash policy.yaml with safe defaults.
#[instrument(level = Level::TRACE)]
fn run_init(force: bool) -> Result<()> {
    let path = settings::ClashSettings::policy_file();

    if path.exists() && !force {
        anyhow::bail!(
            "{} already exists. Use --force to overwrite.",
            path.display()
        );
    }

    std::fs::create_dir_all(settings::ClashSettings::settings_dir())?;
    std::fs::write(&path, DEFAULT_POLICY)?;
    println!("Wrote default policy to {}", path.display());
    println!("Edit the file to customize rules for your environment.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_session_start_input() -> SessionStartHookInput {
        SessionStartHookInput {
            session_id: "test-session".into(),
            transcript_path: "/tmp/transcript.jsonl".into(),
            cwd: "/tmp".into(),
            permission_mode: Some("default".into()),
            hook_event_name: "SessionStart".into(),
            source: Some("startup".into()),
            model: Some("claude-sonnet-4-20250514".into()),
        }
    }

    #[test]
    fn test_session_start_reports_sandbox_support() {
        let input = default_session_start_input();
        let output = handle_session_start(&input).unwrap();
        let context = match &output.hook_specific_output {
            Some(HookSpecificOutput::SessionStart(s)) => s.additional_context.as_deref(),
            _ => panic!("expected SessionStart output"),
        };
        let ctx = context.expect("should have context");
        assert!(
            ctx.contains("sandbox:"),
            "should report sandbox status, got: {ctx}"
        );
    }

    #[test]
    fn test_session_start_reports_session_metadata() {
        let input = default_session_start_input();
        let output = handle_session_start(&input).unwrap();
        let context = match &output.hook_specific_output {
            Some(HookSpecificOutput::SessionStart(s)) => s.additional_context.as_deref(),
            _ => panic!("expected SessionStart output"),
        };
        let ctx = context.expect("should have context");
        assert!(ctx.contains("session source: startup"), "got: {ctx}");
        assert!(
            ctx.contains("model: claude-sonnet-4-20250514"),
            "got: {ctx}"
        );
    }

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
