use clap::{Parser, Subcommand};

use crate::cmd::debug::DebugCmd;
use crate::cmd::session::SessionCmd;
use crate::cmd::statusline::StatuslineCmd;
use crate::cmd::trace::TraceCmd;
use crate::sandbox_cmd::SandboxCmd;

#[derive(Parser, Debug)]
#[command(name = "clash")]
#[command(version = crate::version::version_long())]
#[command(about = "Command line agent safety harness")]
pub struct Cli {
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

/// Top-level hook command with shared `--agent` flag.
#[derive(Parser, Debug)]
pub struct HookCmd {
    /// Which coding agent is invoking the hook (default: claude)
    #[arg(long, default_value = "claude")]
    pub agent: crate::agents::AgentKind,

    #[command(subcommand)]
    pub subcommand: HookSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum HookSubcommand {
    /// Handle PreToolUse hook - called before a tool is executed
    #[command(name = "pre-tool-use")]
    PreToolUse,

    /// Handle PostToolUse hook - called after a tool is executed
    #[command(name = "post-tool-use")]
    PostToolUse,

    /// Handle PermissionRequest hook - respond to permission prompts on behalf of user
    #[command(name = "permission-request")]
    PermissionRequest,

    /// Handle SessionStart hook - called when a coding agent session begins
    #[command(name = "session-start")]
    SessionStart,

    /// Handle Stop hook - called when a conversation turn ends without a tool call
    #[command(name = "stop")]
    Stop,
}

#[derive(Subcommand, Debug)]
pub enum PolicyCmd {
    /// List rules in the active policy
    List {
        #[arg(long)]
        json: bool,
    },
    /// Validate policy files and report errors
    Validate {
        /// Path to a specific policy file to validate (default: all active levels)
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Open the interactive policy editor (or $EDITOR with --raw)
    Edit {
        /// Policy scope to edit: "user" or "project" (default: auto-detect)
        #[arg(long)]
        scope: Option<String>,
        /// Open in $EDITOR instead of the interactive TUI
        #[arg(long)]
        raw: bool,
        /// Open with the test console panel visible
        #[arg(long)]
        test: bool,
    },
    /// Add an allow rule for a tool or binary
    ///
    /// Examples:
    ///   clash policy allow "gh pr create"
    ///   clash policy allow --tool Read
    ///   clash policy allow --bin grep --sandbox cwd
    Allow {
        /// Command to allow (e.g. "gh pr create" → bin=gh, args=[pr, create])
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
        /// Tool name (e.g. "Bash", "Read", "Write")
        #[arg(long)]
        tool: Option<String>,
        /// Binary name (implies --tool Bash)
        #[arg(long)]
        bin: Option<String>,
        /// Named sandbox to apply (must be defined in the policy)
        #[arg(long)]
        sandbox: Option<String>,
        /// Policy scope: "user" or "project" (default: auto-detect)
        #[arg(long)]
        scope: Option<String>,
    },
    /// Add a deny rule for a tool or binary
    ///
    /// Examples:
    ///   clash policy deny "rm -rf"
    ///   clash policy deny --tool WebSearch
    Deny {
        /// Command to deny (e.g. "git push" → bin=git, args=[push])
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
        /// Tool name (e.g. "Bash", "Read", "Write")
        #[arg(long)]
        tool: Option<String>,
        /// Binary name (implies --tool Bash)
        #[arg(long)]
        bin: Option<String>,
        /// Policy scope: "user" or "project" (default: auto-detect)
        #[arg(long)]
        scope: Option<String>,
    },
    /// Remove a rule matching a tool or binary
    ///
    /// Examples:
    ///   clash policy remove "gh pr create"
    ///   clash policy remove --tool Read
    Remove {
        /// Command to match (e.g. "gh pr create")
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
        /// Tool name (e.g. "Bash", "Read", "Write")
        #[arg(long)]
        tool: Option<String>,
        /// Binary name (implies --tool Bash)
        #[arg(long)]
        bin: Option<String>,
        /// Policy scope: "user" or "project" (default: auto-detect)
        #[arg(long)]
        scope: Option<String>,
    },
    /// Check policy for multi-agent portability issues
    ///
    /// Scans policy rules and warns about agent-specific tool names
    /// that won't match across all agents. Suggests canonical alternatives.
    Check {
        /// Output as JSON
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
    /// Convert policy.json to policy.star (Starlark format)
    ///
    /// Reads the JSON policy, converts it to idiomatic Starlark, and writes
    /// a .star file alongside it. The original .json is preserved unless
    /// --replace is passed.
    Convert {
        /// Path to the policy.json file (default: auto-detect active policy)
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        /// Delete the .json file after successful conversion
        #[arg(long)]
        replace: bool,
    },
    /// Explain which policy rule would match a given tool invocation
    #[command(hide = true)]
    Explain {
        /// Output as JSON instead of human-readable text
        #[arg(long)]
        json: bool,
        /// Show detailed decision trace with per-condition match details
        #[arg(long)]
        trace: bool,
        /// Tool type: bash, read, write, edit, tool (or full tool name like Bash, Read, etc.)
        tool: Option<String>,
        /// The command, file path, or noun to check (remaining args joined)
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Commands {
    /// Initialize a new clash policy with a safe default configuration
    ///
    /// By default, imports permissions from your coding agent's existing
    /// configuration and generates a matching Clash policy. Use --no-import
    /// to skip policy generation and just install hooks.
    Init {
        /// Generate policy from an observed session trace file.
        /// Pass a path to trace.jsonl or audit.jsonl, or "latest" to auto-detect.
        #[arg(long = "from-trace", value_name = "PATH", conflicts_with = "no_import")]
        from_trace: Option<std::path::PathBuf>,
        /// Skip policy import — just install hooks and print setup instructions
        #[arg(long = "no-import", conflicts_with = "from_trace")]
        no_import: bool,
        /// Which coding agent to set up (prompts if omitted)
        #[arg(long)]
        agent: Option<crate::agents::AgentKind>,
    },

    /// Install the clash plugin/hooks for a coding agent (skip policy setup)
    Install {
        /// Which coding agent to install for (prompts if omitted)
        #[arg(long)]
        agent: Option<crate::agents::AgentKind>,
    },

    /// Remove clash: undo bypass permissions, uninstall plugin, remove config and binary
    Uninstall {
        /// Skip confirmation prompts
        #[arg(long, short = 'y')]
        yes: bool,
    },

    /// Show policy status: layers, rules with shadowing, and potential issues
    Status {
        /// Output as JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },

    /// View and manage policy rules
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

    /// Run a bash-compatible shell with per-command sandbox enforcement
    ///
    /// Every external command is executed through its own sandbox profile,
    /// looked up by binary name (e.g., `sandboxes["git"]`), falling back
    /// to the default sandbox when no command-specific profile exists.
    ///
    /// Modes: interactive REPL (no args), command string (-c), or script file.
    Shell {
        /// Execute a command string and exit (like bash -c)
        #[arg(short = 'c')]
        command: Option<String>,

        /// Working directory for sandbox path resolution
        #[arg(long, default_value = ".")]
        cwd: String,

        /// Default sandbox name from the policy (used when no rule-specific sandbox matches)
        #[arg(long)]
        sandbox: Option<String>,

        /// Print the sandbox policy matched for each command before execution
        #[arg(long)]
        debug: bool,

        /// Script path and arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },

    /// Apply sandbox restrictions and exec commands
    #[command(subcommand, alias = "box")]
    Sandbox(SandboxCmd),

    /// Interactive policy sandbox — write rules and test them against tool invocations
    Playground,

    /// Diagnose common setup issues and report fix instructions
    Doctor {
        /// Run interactive onboarding: diagnose issues and offer to fix them
        #[arg(long)]
        onboard: bool,
        /// Which coding agent to diagnose (default: claude)
        #[arg(long, default_value = "claude")]
        agent: crate::agents::AgentKind,
    },

    /// Debug policy enforcement: view logs, replay commands, inspect sandbox
    #[command(subcommand)]
    Debug(DebugCmd),

    /// View and export session traces
    #[command(subcommand)]
    Trace(TraceCmd),

    /// List, inspect, and locate session directories
    #[command(subcommand)]
    Session(SessionCmd),

    // --- Hidden/internal commands ---
    /// Agent hook callbacks
    #[command(hide = true)]
    Hook(HookCmd),

    /// Launch Claude Code with clash managing hooks and sandbox enforcement
    #[command(hide = true)]
    Launch {
        /// Path to policy file (default: ~/.clash/policy.star)
        #[arg(long)]
        policy: Option<String>,

        /// Arguments to pass through to Claude Code
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Format Starlark policy files using ruff
    Fmt {
        /// Check formatting without modifying files (exit 1 if unformatted)
        #[arg(long)]
        check: bool,

        /// Policy files to format (default: all active policy files)
        #[arg(trailing_var_arg = true)]
        files: Vec<std::path::PathBuf>,
    },

    /// Explain which policy rule would match a given tool invocation
    Explain {
        /// Output as JSON instead of human-readable text
        #[arg(long)]
        json: bool,
        /// Show detailed decision trace with per-condition match details
        #[arg(long)]
        trace: bool,
        /// Tool type: bash, read, write, edit, tool (or full tool name like Bash, Read, etc.)
        tool: String,
        /// The command, file path, or noun to check (remaining args joined)
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Update clash to the latest release (or a specific version)
    Update {
        /// Only check for updates, don't install
        #[arg(long)]
        check: bool,

        /// Skip confirmation prompt
        #[arg(long, short = 'y')]
        yes: bool,

        /// Update to a specific version (e.g., 0.4.0)
        #[arg(long)]
        version: Option<String>,
    },

    /// Display clash status in the Claude Code status line
    #[command(subcommand)]
    Statusline(StatuslineCmd),

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
        /// Include the session toolpath trace in the report
        #[arg(long)]
        include_trace: bool,
    },
}
