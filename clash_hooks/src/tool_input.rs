//! Typed tool input structs for well-known Claude Code tools.
//!
//! Each struct models the `tool_input` JSON for a specific tool. Use the
//! typed accessors on [`crate::event::PreToolUse`] (e.g., `.bash()`,
//! `.write()`) to get these, or use [`ToolInput::parse`] directly.

use serde::Deserialize;

/// Typed tool input, parsed from the raw `tool_input` JSON.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ToolInput {
    Bash(BashInput),
    Write(WriteInput),
    Edit(EditInput),
    Read(ReadInput),
    Glob(GlobInput),
    Grep(GrepInput),
    WebFetch(WebFetchInput),
    WebSearch(WebSearchInput),
    NotebookEdit(NotebookEditInput),
    Skill(SkillInput),
    Agent(AgentInput),
    /// Tool not recognized by this library version, or parse failed.
    Unknown(serde_json::Value),
}

impl ToolInput {
    /// Parse a typed tool input from the tool name and raw JSON value.
    pub fn parse(tool_name: &str, raw: &serde_json::Value) -> Self {
        match tool_name {
            "Bash" => try_parse(raw, ToolInput::Bash),
            "Write" => try_parse(raw, ToolInput::Write),
            "Edit" => try_parse(raw, ToolInput::Edit),
            "Read" => try_parse(raw, ToolInput::Read),
            "Glob" => try_parse(raw, ToolInput::Glob),
            "Grep" => try_parse(raw, ToolInput::Grep),
            "WebFetch" => try_parse(raw, ToolInput::WebFetch),
            "WebSearch" => try_parse(raw, ToolInput::WebSearch),
            "NotebookEdit" => try_parse(raw, ToolInput::NotebookEdit),
            "Skill" => try_parse(raw, ToolInput::Skill),
            "Agent" | "Task" => try_parse(raw, ToolInput::Agent),
            _ => ToolInput::Unknown(raw.clone()),
        }
    }
}

fn try_parse<T: for<'de> Deserialize<'de>>(
    raw: &serde_json::Value,
    wrap: fn(T) -> ToolInput,
) -> ToolInput {
    serde_json::from_value(raw.clone())
        .map(wrap)
        .unwrap_or_else(|_| ToolInput::Unknown(raw.clone()))
}

/// Bash tool input.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct BashInput {
    pub command: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub run_in_background: Option<bool>,
    #[serde(default, rename = "dangerouslyDisableSandbox")]
    pub dangerously_disable_sandbox: Option<bool>,
}

/// Write tool input.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct WriteInput {
    pub file_path: String,
    pub content: String,
}

/// Edit tool input.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct EditInput {
    pub file_path: String,
    pub old_string: String,
    pub new_string: String,
    #[serde(default)]
    pub replace_all: Option<bool>,
}

/// Read tool input.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct ReadInput {
    pub file_path: String,
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub limit: Option<u64>,
}

/// Glob tool input.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct GlobInput {
    pub pattern: String,
    #[serde(default)]
    pub path: Option<String>,
}

/// Grep tool input.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct GrepInput {
    pub pattern: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub glob: Option<String>,
    #[serde(default)]
    pub output_mode: Option<String>,
    #[serde(default, rename = "type")]
    pub file_type: Option<String>,
    #[serde(default)]
    pub multiline: Option<bool>,
}

/// WebFetch tool input.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct WebFetchInput {
    pub url: String,
    pub prompt: String,
}

/// WebSearch tool input.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct WebSearchInput {
    pub query: String,
    #[serde(default)]
    pub allowed_domains: Option<Vec<String>>,
    #[serde(default)]
    pub blocked_domains: Option<Vec<String>>,
}

/// NotebookEdit tool input.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct NotebookEditInput {
    pub notebook_path: String,
    pub new_source: String,
    #[serde(default)]
    pub cell_id: Option<String>,
    #[serde(default)]
    pub cell_type: Option<String>,
    #[serde(default)]
    pub edit_mode: Option<String>,
}

/// Skill tool input.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct SkillInput {
    pub skill: String,
    #[serde(default)]
    pub args: Option<String>,
}

/// Agent/Task tool input.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct AgentInput {
    pub prompt: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub subagent_type: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
}
