use clap::{Parser, Subcommand};

use crate::cmd::statusline::StatuslineCmd;
use crate::sandbox_cmd::SandboxCmd;

#[derive(Parser, Debug)]
#[command(name = "clash")]
#[command(version)]
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
    /// Validate policy files and report errors
    Validate {
        /// Path to a specific policy file to validate (default: all active levels)
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Transactional policy editor (pipe, interactive, or one-liner)
    Shell {
        /// Print resulting policy without writing to disk
        #[arg(long)]
        dry_run: bool,
        /// Policy level to modify: "user", "project", or "session"
        #[arg(long)]
        scope: Option<String>,
        /// Execute a single statement and exit
        #[arg(short = 'c', long = "command")]
        command: Option<String>,
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
    /// Pass "user" to create a global policy (~/.clash/policy.sexpr) or
    /// "project" to create a repo-scoped policy (.clash/policy.sexpr).
    /// When no scope is given, an interactive prompt lets you choose.
    Init {
        /// Skip setting bypassPermissions in Claude Code settings
        #[arg(long, default_missing_value = "true", num_args = 0..=1)]
        no_bypass: Option<bool>,
        /// Scope to initialize: "user" (global) or "project" (this repo)
        scope: Option<String>,
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

    /// Amend the policy: add and remove multiple rules in one atomic operation
    ///
    /// Each rule is either a full s-expr "(effect (matcher ...))" or a shortcut "effect:verb".
    /// Supports mixing allow/deny/ask rules and removals in a single command.
    ///
    /// Deprecated: prefer `clash policy shell` for a transactional editing experience.
    Amend {
        /// Rules to add: "(allow (exec \"git\" *))" or "allow:bash"
        #[arg(required_unless_present = "remove")]
        rules: Vec<String>,

        /// Rules to remove (Display form, e.g. '(allow (exec "git" *))')
        #[arg(long, num_args = 1)]
        remove: Vec<String>,

        /// Print modified policy without writing
        #[arg(long)]
        dry_run: bool,

        /// Policy level to modify: "user", "project", or "session"
        #[arg(long)]
        scope: Option<String>,
    },

    /// Interactive policy editor
    Edit {
        /// Print modified policy without writing
        #[arg(long)]
        dry_run: bool,

        /// Policy level to modify: "user", "project", or "session"
        #[arg(long)]
        scope: Option<String>,
    },

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
