//! Canonical registry of Claude Code tools and their input schemas.
//!
//! Every well-known tool that Claude Code exposes is defined here with its
//! parameter schema. This is the single source of truth for tool metadata —
//! hook handlers, policy engines, and TUIs should reference these definitions
//! rather than maintaining their own tool lists.

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Parameter schema types
// ---------------------------------------------------------------------------

/// A single parameter in a tool's input schema.
#[derive(Debug, Clone)]
pub struct Param {
    /// Parameter name as it appears in the JSON input.
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// JSON Schema type (e.g. "string", "number", "boolean", "object", "array").
    pub schema_type: &'static str,
    /// Whether this parameter is required.
    pub required: bool,
}

/// Metadata for a well-known Claude Code tool.
#[derive(Debug, Clone)]
pub struct ToolDef {
    /// Tool name as Claude sees it, e.g. "Bash", "Read".
    pub name: &'static str,
    /// Human-readable description of what the tool does.
    pub description: &'static str,
    /// The tool's input parameter schema.
    pub params: &'static [Param],
}

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------

pub const BASH: ToolDef = ToolDef {
    name: "Bash",
    description: "Execute shell commands",
    params: &[
        Param {
            name: "command",
            description: "The shell command to run",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "description",
            description: "Clear, concise description of what the command does",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "timeout",
            description: "Timeout in milliseconds (max 600000)",
            schema_type: "number",
            required: false,
        },
        Param {
            name: "run_in_background",
            description: "Run the command in the background",
            schema_type: "boolean",
            required: false,
        },
    ],
};

pub const READ: ToolDef = ToolDef {
    name: "Read",
    description: "Read files from the filesystem",
    params: &[
        Param {
            name: "file_path",
            description: "Absolute path to the file to read",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "offset",
            description: "Line number to start reading from",
            schema_type: "number",
            required: false,
        },
        Param {
            name: "limit",
            description: "Number of lines to read",
            schema_type: "number",
            required: false,
        },
        Param {
            name: "pages",
            description: "Page range for PDF files (e.g. \"1-5\")",
            schema_type: "string",
            required: false,
        },
    ],
};

pub const WRITE: ToolDef = ToolDef {
    name: "Write",
    description: "Write or create files on the filesystem",
    params: &[
        Param {
            name: "file_path",
            description: "Absolute path to the file to write",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "content",
            description: "Content to write to the file",
            schema_type: "string",
            required: true,
        },
    ],
};

pub const EDIT: ToolDef = ToolDef {
    name: "Edit",
    description: "Edit files with exact string replacements",
    params: &[
        Param {
            name: "file_path",
            description: "Absolute path to the file to modify",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "old_string",
            description: "The text to replace",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "new_string",
            description: "The replacement text",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "replace_all",
            description: "Replace all occurrences (default false)",
            schema_type: "boolean",
            required: false,
        },
    ],
};

pub const MULTI_EDIT: ToolDef = ToolDef {
    name: "MultiEdit",
    description: "Apply multiple edits to a single file",
    params: &[
        Param {
            name: "file_path",
            description: "Absolute path to the file to modify",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "edits",
            description: "Array of {old_string, new_string} edits",
            schema_type: "array",
            required: true,
        },
    ],
};

pub const GLOB: ToolDef = ToolDef {
    name: "Glob",
    description: "Search for files by glob pattern",
    params: &[
        Param {
            name: "pattern",
            description: "Glob pattern to match files against",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "path",
            description: "Directory to search in",
            schema_type: "string",
            required: false,
        },
    ],
};

pub const GREP: ToolDef = ToolDef {
    name: "Grep",
    description: "Search file contents by regex",
    params: &[
        Param {
            name: "pattern",
            description: "Regex pattern to search for",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "path",
            description: "File or directory to search in",
            schema_type: "string",
            required: false,
        },
        Param {
            name: "glob",
            description: "Glob pattern to filter files (e.g. \"*.js\")",
            schema_type: "string",
            required: false,
        },
        Param {
            name: "type",
            description: "File type to search (e.g. \"js\", \"py\", \"rust\")",
            schema_type: "string",
            required: false,
        },
        Param {
            name: "output_mode",
            description: "Output mode: content, files_with_matches, or count",
            schema_type: "string",
            required: false,
        },
        Param {
            name: "head_limit",
            description: "Limit output to first N entries",
            schema_type: "number",
            required: false,
        },
        Param {
            name: "offset",
            description: "Skip first N entries before applying head_limit",
            schema_type: "number",
            required: false,
        },
        Param {
            name: "-i",
            description: "Case insensitive search",
            schema_type: "boolean",
            required: false,
        },
        Param {
            name: "-n",
            description: "Show line numbers in output",
            schema_type: "boolean",
            required: false,
        },
        Param {
            name: "-A",
            description: "Lines to show after each match",
            schema_type: "number",
            required: false,
        },
        Param {
            name: "-B",
            description: "Lines to show before each match",
            schema_type: "number",
            required: false,
        },
        Param {
            name: "-C",
            description: "Lines of context around each match",
            schema_type: "number",
            required: false,
        },
        Param {
            name: "context",
            description: "Alias for -C",
            schema_type: "number",
            required: false,
        },
        Param {
            name: "multiline",
            description: "Enable multiline matching",
            schema_type: "boolean",
            required: false,
        },
    ],
};

pub const WEB_FETCH: ToolDef = ToolDef {
    name: "WebFetch",
    description: "Fetch content from a URL",
    params: &[
        Param {
            name: "url",
            description: "The URL to fetch",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "prompt",
            description: "Prompt to run on fetched content",
            schema_type: "string",
            required: false,
        },
    ],
};

pub const WEB_SEARCH: ToolDef = ToolDef {
    name: "WebSearch",
    description: "Search the web",
    params: &[
        Param {
            name: "query",
            description: "Search query",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "allowed_domains",
            description: "Restrict results to these domains",
            schema_type: "array",
            required: false,
        },
        Param {
            name: "blocked_domains",
            description: "Exclude these domains from results",
            schema_type: "array",
            required: false,
        },
    ],
};

pub const AGENT: ToolDef = ToolDef {
    name: "Agent",
    description: "Spawn a sub-agent for complex tasks",
    params: &[
        Param {
            name: "description",
            description: "Short description of the task (3-5 words)",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "prompt",
            description: "The task for the agent to perform",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "subagent_type",
            description: "Specialized agent type to use",
            schema_type: "string",
            required: false,
        },
        Param {
            name: "model",
            description: "Model override (sonnet, opus, haiku)",
            schema_type: "string",
            required: false,
        },
        Param {
            name: "isolation",
            description: "Isolation mode (\"worktree\" for git worktree)",
            schema_type: "string",
            required: false,
        },
        Param {
            name: "run_in_background",
            description: "Run the agent in the background",
            schema_type: "boolean",
            required: false,
        },
    ],
};

pub const NOTEBOOK_EDIT: ToolDef = ToolDef {
    name: "NotebookEdit",
    description: "Edit Jupyter notebook cells",
    params: &[
        Param {
            name: "notebook_path",
            description: "Path to the notebook file",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "cell_number",
            description: "Cell index (0-based)",
            schema_type: "number",
            required: true,
        },
        Param {
            name: "new_source",
            description: "New cell content",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "cell_type",
            description: "Cell type (code, markdown)",
            schema_type: "string",
            required: false,
        },
    ],
};

pub const SKILL: ToolDef = ToolDef {
    name: "Skill",
    description: "Execute a skill or slash command",
    params: &[
        Param {
            name: "skill",
            description: "The skill name (e.g. \"commit\", \"review-pr\")",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "args",
            description: "Optional arguments for the skill",
            schema_type: "string",
            required: false,
        },
    ],
};

pub const TOOL_SEARCH: ToolDef = ToolDef {
    name: "ToolSearch",
    description: "Fetch schema definitions for deferred tools",
    params: &[
        Param {
            name: "query",
            description: "Query to find deferred tools",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "max_results",
            description: "Maximum number of results to return",
            schema_type: "number",
            required: false,
        },
    ],
};

// -- Interactive / lifecycle tools ------------------------------------------

pub const ASK_USER_QUESTION: ToolDef = ToolDef {
    name: "AskUserQuestion",
    description: "Prompt the user for input",
    params: &[Param {
        name: "question",
        description: "The question to ask",
        schema_type: "string",
        required: true,
    }],
};

pub const ENTER_PLAN_MODE: ToolDef = ToolDef {
    name: "EnterPlanMode",
    description: "Enter plan mode for designing implementation strategy",
    params: &[],
};

pub const EXIT_PLAN_MODE: ToolDef = ToolDef {
    name: "ExitPlanMode",
    description: "Exit plan mode and return to implementation",
    params: &[],
};

pub const ENTER_WORKTREE: ToolDef = ToolDef {
    name: "EnterWorktree",
    description: "Enter an isolated git worktree",
    params: &[],
};

pub const EXIT_WORKTREE: ToolDef = ToolDef {
    name: "ExitWorktree",
    description: "Exit the current git worktree",
    params: &[],
};

// -- Task management tools --------------------------------------------------

pub const TASK_CREATE: ToolDef = ToolDef {
    name: "TaskCreate",
    description: "Create a new task for tracking work",
    params: &[
        Param {
            name: "description",
            description: "Description of the task",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "priority",
            description: "Task priority",
            schema_type: "string",
            required: false,
        },
    ],
};

pub const TASK_GET: ToolDef = ToolDef {
    name: "TaskGet",
    description: "Get details of a specific task",
    params: &[Param {
        name: "task_id",
        description: "The task ID",
        schema_type: "string",
        required: true,
    }],
};

pub const TASK_LIST: ToolDef = ToolDef {
    name: "TaskList",
    description: "List all tasks",
    params: &[],
};

pub const TASK_OUTPUT: ToolDef = ToolDef {
    name: "TaskOutput",
    description: "Read output from a background task",
    params: &[Param {
        name: "task_id",
        description: "The task ID",
        schema_type: "string",
        required: true,
    }],
};

pub const TASK_STOP: ToolDef = ToolDef {
    name: "TaskStop",
    description: "Stop a running task",
    params: &[Param {
        name: "task_id",
        description: "The task ID",
        schema_type: "string",
        required: true,
    }],
};

pub const TASK_UPDATE: ToolDef = ToolDef {
    name: "TaskUpdate",
    description: "Update a task's status or details",
    params: &[
        Param {
            name: "task_id",
            description: "The task ID",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "status",
            description: "New status (in_progress, completed, etc.)",
            schema_type: "string",
            required: false,
        },
    ],
};

// -- Cron tools -------------------------------------------------------------

pub const CRON_CREATE: ToolDef = ToolDef {
    name: "CronCreate",
    description: "Create a recurring scheduled task",
    params: &[
        Param {
            name: "schedule",
            description: "Cron schedule expression",
            schema_type: "string",
            required: true,
        },
        Param {
            name: "command",
            description: "Command to run on schedule",
            schema_type: "string",
            required: true,
        },
    ],
};

pub const CRON_DELETE: ToolDef = ToolDef {
    name: "CronDelete",
    description: "Delete a scheduled task",
    params: &[Param {
        name: "cron_id",
        description: "The cron job ID",
        schema_type: "string",
        required: true,
    }],
};

pub const CRON_LIST: ToolDef = ToolDef {
    name: "CronList",
    description: "List all scheduled tasks",
    params: &[],
};

// ---------------------------------------------------------------------------
// Registry — all known tools in a single slice
// ---------------------------------------------------------------------------

/// All well-known Claude Code tools.
pub const ALL: &[&ToolDef] = &[
    // Core tools
    &BASH,
    &READ,
    &WRITE,
    &EDIT,
    &MULTI_EDIT,
    &GLOB,
    &GREP,
    &WEB_FETCH,
    &WEB_SEARCH,
    &AGENT,
    &NOTEBOOK_EDIT,
    &SKILL,
    &TOOL_SEARCH,
    // Interactive / lifecycle
    &ASK_USER_QUESTION,
    &ENTER_PLAN_MODE,
    &EXIT_PLAN_MODE,
    &ENTER_WORKTREE,
    &EXIT_WORKTREE,
    // Task management
    &TASK_CREATE,
    &TASK_GET,
    &TASK_LIST,
    &TASK_OUTPUT,
    &TASK_STOP,
    &TASK_UPDATE,
    // Cron
    &CRON_CREATE,
    &CRON_DELETE,
    &CRON_LIST,
];

/// Look up a tool by name (case-insensitive). Returns `None` for unknown/MCP tools.
pub fn lookup(name: &str) -> Option<&'static ToolDef> {
    ALL.iter()
        .find(|t| t.name.eq_ignore_ascii_case(name))
        .copied()
}

/// Returns true if the given name matches a well-known tool.
pub fn is_known(name: &str) -> bool {
    lookup(name).is_some()
}

/// Tools that require user interaction via Claude Code's native UI.
/// Auto-approving these would skip the interaction, so non-deny
/// decisions are converted to passthrough.
pub fn is_interactive(name: &str) -> bool {
    matches!(name, "AskUserQuestion" | "EnterPlanMode" | "ExitPlanMode")
}

// ---------------------------------------------------------------------------
// Typed input structs (deserialized from tool_input JSON)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct BashInput {
    pub command: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub run_in_background: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WriteInput {
    pub file_path: String,
    pub content: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EditInput {
    pub file_path: String,
    pub old_string: String,
    pub new_string: String,
    #[serde(default)]
    pub replace_all: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReadInput {
    pub file_path: String,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub limit: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GlobInput {
    pub pattern: String,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GrepInput {
    pub pattern: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub glob: Option<String>,
    #[serde(default, rename = "type")]
    pub file_type: Option<String>,
    #[serde(default)]
    pub output_mode: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebFetchInput {
    pub url: String,
    #[serde(default)]
    pub prompt: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebSearchInput {
    pub query: String,
    #[serde(default)]
    pub allowed_domains: Option<Vec<String>>,
    #[serde(default)]
    pub blocked_domains: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentInput {
    pub description: String,
    pub prompt: String,
    #[serde(default)]
    pub subagent_type: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub isolation: Option<String>,
    #[serde(default)]
    pub run_in_background: Option<bool>,
}

/// Tool-specific input variants, deserialized from `tool_input` JSON.
#[derive(Debug, Clone)]
pub enum ToolInput {
    Bash(BashInput),
    Read(ReadInput),
    Write(WriteInput),
    Edit(EditInput),
    Glob(GlobInput),
    Grep(GrepInput),
    WebFetch(WebFetchInput),
    WebSearch(WebSearchInput),
    Agent(AgentInput),
    /// Any tool we don't have a typed struct for.
    Unknown(serde_json::Value),
}

impl ToolInput {
    /// Parse a `tool_input` JSON value into a typed variant based on tool name.
    pub fn parse(tool_name: &str, value: serde_json::Value) -> Self {
        macro_rules! try_parse {
            ($variant:ident, $val:expr) => {
                serde_json::from_value($val.clone())
                    .map(ToolInput::$variant)
                    .unwrap_or_else(|_| ToolInput::Unknown($val))
            };
        }
        match tool_name {
            "Bash" => try_parse!(Bash, value),
            "Read" => try_parse!(Read, value),
            "Write" => try_parse!(Write, value),
            "Edit" | "MultiEdit" => try_parse!(Edit, value),
            "Glob" => try_parse!(Glob, value),
            "Grep" => try_parse!(Grep, value),
            "WebFetch" => try_parse!(WebFetch, value),
            "WebSearch" => try_parse!(WebSearch, value),
            "Agent" => try_parse!(Agent, value),
            _ => ToolInput::Unknown(value),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_is_case_insensitive() {
        assert!(lookup("bash").is_some());
        assert!(lookup("BASH").is_some());
        assert!(lookup("Bash").is_some());
    }

    #[test]
    fn lookup_returns_none_for_mcp_tools() {
        assert!(lookup("mcp__custom__thing").is_none());
    }

    #[test]
    fn all_tools_have_unique_names() {
        let mut names: Vec<&str> = ALL.iter().map(|t| t.name).collect();
        names.sort();
        let len_before = names.len();
        names.dedup();
        assert_eq!(len_before, names.len(), "duplicate tool names in ALL");
    }

    #[test]
    fn interactive_tools() {
        assert!(is_interactive("AskUserQuestion"));
        assert!(is_interactive("EnterPlanMode"));
        assert!(is_interactive("ExitPlanMode"));
        assert!(!is_interactive("Bash"));
    }

    #[test]
    fn parse_bash_input() {
        let json = serde_json::json!({"command": "ls", "timeout": 5000});
        match ToolInput::parse("Bash", json) {
            ToolInput::Bash(b) => {
                assert_eq!(b.command, "ls");
                assert_eq!(b.timeout, Some(5000));
            }
            other => panic!("expected Bash, got {:?}", other),
        }
    }

    #[test]
    fn parse_unknown_tool_input() {
        let json = serde_json::json!({"foo": "bar"});
        assert!(matches!(
            ToolInput::parse("mcp__something", json),
            ToolInput::Unknown(_)
        ));
    }

    #[test]
    fn required_params_are_marked() {
        let bash = lookup("Bash").unwrap();
        let command_param = bash.params.iter().find(|p| p.name == "command").unwrap();
        assert!(command_param.required);
        let timeout_param = bash.params.iter().find(|p| p.name == "timeout").unwrap();
        assert!(!timeout_param.required);
    }
}
