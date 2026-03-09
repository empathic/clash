use clap::{Parser, Subcommand};

use crate::cmd::debug::DebugCmd;
use crate::cmd::statusline::StatuslineCmd;
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

#[derive(Subcommand, Debug)]
pub enum HooksCmd {
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
    /// Open the policy file in $EDITOR
    Edit {
        /// Policy scope to edit: "user" or "project" (default: auto-detect)
        #[arg(long)]
        scope: Option<String>,
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
    /// Pass "user" to create a global policy (~/.clash/policy.star) or
    /// "project" to create a repo-scoped policy (.clash/policy.star).
    /// When no scope is given, an interactive prompt lets you choose.
    Init {
        /// Skip setting bypassPermissions in Claude Code settings
        #[arg(long, default_missing_value = "true", num_args = 0..=1)]
        no_bypass: Option<bool>,
        /// Scope to initialize: "user" (global) or "project" (this repo)
        scope: Option<String>,
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

    /// Apply sandbox restrictions and exec commands
    #[command(subcommand)]
    Sandbox(SandboxCmd),

    /// Diagnose common setup issues and report fix instructions
    Doctor,

    /// Debug policy enforcement: view logs, replay commands, inspect sandbox
    #[command(subcommand)]
    Debug(DebugCmd),

    // --- Hidden/internal commands ---
    /// Agent hook callbacks
    #[command(subcommand, hide = true)]
    Hook(HooksCmd),

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
    },
}
