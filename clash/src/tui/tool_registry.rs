//! Well-known Claude Code tool metadata for the TUI policy editor.
//!
//! Provides contextual hints, effect filtering, and observable relevance
//! based on the tool being configured. Unknown/MCP tools get permissive
//! defaults (all effects allowed, all observables relevant).

/// Which effects are valid for a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectOption {
    Allow,
    Deny,
    Ask,
}

/// Lightweight tag for Observable variants (no inner data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservableTag {
    ToolName,
    HookType,
    AgentName,
    PositionalArg,
    HasArg,
    NamedArg,
    NestedField,
    FsOp,
    FsPath,
    NetDomain,
}

/// Metadata for a well-known Claude Code tool.
pub struct ToolInfo {
    /// Tool name as Claude sees it, e.g. "Bash", "Read".
    pub name: &'static str,
    /// Which effects are valid for rules targeting this tool.
    pub allowed_effects: &'static [EffectOption],
    /// Which observables are useful when adding child conditions.
    pub relevant_observables: &'static [ObservableTag],
    /// Hint shown when this tool is the target of a rule.
    pub description: &'static str,
    /// Named arguments this tool accepts, for autocomplete/hints.
    pub args: &'static [(&'static str, &'static str)], // (name, description)
}

const ALL_EFFECTS: &[EffectOption] = &[EffectOption::Allow, EffectOption::Deny, EffectOption::Ask];
const NO_ASK: &[EffectOption] = &[EffectOption::Allow, EffectOption::Deny];

/// The registry of well-known Claude Code tools.
pub const TOOLS: &[ToolInfo] = &[
    ToolInfo {
        name: "Bash",
        allowed_effects: NO_ASK,
        relevant_observables: &[
            ObservableTag::PositionalArg,
            ObservableTag::HasArg,
            ObservableTag::NamedArg,
        ],
        description: "Execute shell commands",
        args: &[
            ("command", "The shell command to run"),
            ("description", "What the command does"),
            ("timeout", "Timeout in milliseconds"),
        ],
    },
    ToolInfo {
        name: "Read",
        allowed_effects: ALL_EFFECTS,
        relevant_observables: &[ObservableTag::FsPath, ObservableTag::FsOp],
        description: "Read files from the filesystem",
        args: &[
            ("file_path", "Absolute path to the file"),
            ("offset", "Line number to start reading from"),
            ("limit", "Number of lines to read"),
        ],
    },
    ToolInfo {
        name: "Write",
        allowed_effects: ALL_EFFECTS,
        relevant_observables: &[ObservableTag::FsPath, ObservableTag::FsOp],
        description: "Write/create files on the filesystem",
        args: &[
            ("file_path", "Absolute path to the file"),
            ("content", "Content to write"),
        ],
    },
    ToolInfo {
        name: "Edit",
        allowed_effects: ALL_EFFECTS,
        relevant_observables: &[ObservableTag::FsPath, ObservableTag::FsOp],
        description: "Edit files with string replacements",
        args: &[
            ("file_path", "Absolute path to the file"),
            ("old_string", "Text to find"),
            ("new_string", "Replacement text"),
        ],
    },
    ToolInfo {
        name: "MultiEdit",
        allowed_effects: ALL_EFFECTS,
        relevant_observables: &[ObservableTag::FsPath, ObservableTag::FsOp],
        description: "Apply multiple edits to a file",
        args: &[
            ("file_path", "Absolute path to the file"),
            ("edits", "Array of {old_string, new_string} edits"),
        ],
    },
    ToolInfo {
        name: "Glob",
        allowed_effects: ALL_EFFECTS,
        relevant_observables: &[ObservableTag::FsPath, ObservableTag::FsOp],
        description: "Search for files by glob pattern",
        args: &[
            ("pattern", "Glob pattern, e.g. **/*.ts"),
            ("path", "Directory to search in"),
        ],
    },
    ToolInfo {
        name: "Grep",
        allowed_effects: ALL_EFFECTS,
        relevant_observables: &[ObservableTag::FsPath, ObservableTag::FsOp],
        description: "Search file contents by regex",
        args: &[
            ("pattern", "Regex to search for"),
            ("path", "File or directory to search"),
        ],
    },
    ToolInfo {
        name: "WebFetch",
        allowed_effects: ALL_EFFECTS,
        relevant_observables: &[ObservableTag::NetDomain],
        description: "Fetch content from a URL",
        args: &[
            ("url", "The URL to fetch"),
            ("prompt", "Prompt to run on fetched content"),
        ],
    },
    ToolInfo {
        name: "WebSearch",
        allowed_effects: ALL_EFFECTS,
        relevant_observables: &[ObservableTag::NetDomain],
        description: "Search the web",
        args: &[
            ("query", "Search query"),
            ("allowed_domains", "Restrict to these domains"),
            ("blocked_domains", "Exclude these domains"),
        ],
    },
    ToolInfo {
        name: "Agent",
        allowed_effects: ALL_EFFECTS,
        relevant_observables: &[ObservableTag::AgentName, ObservableTag::NamedArg],
        description: "Spawn a sub-agent",
        args: &[
            ("description", "Short description of the task"),
            ("prompt", "The task for the agent"),
        ],
    },
    ToolInfo {
        name: "NotebookEdit",
        allowed_effects: ALL_EFFECTS,
        relevant_observables: &[ObservableTag::FsPath],
        description: "Edit Jupyter notebook cells",
        args: &[
            ("notebook_path", "Path to the notebook"),
            ("cell_number", "Cell index (0-based)"),
            ("new_source", "New cell content"),
        ],
    },
];

/// Look up a tool by name (case-insensitive). Returns None for unknown/MCP tools.
pub fn lookup(name: &str) -> Option<&'static ToolInfo> {
    TOOLS.iter().find(|t| t.name.eq_ignore_ascii_case(name))
}

/// Check whether an effect is allowed for a tool. Unknown tools allow all effects.
pub fn is_effect_allowed(tool_name: &str, effect: EffectOption) -> bool {
    match lookup(tool_name) {
        Some(info) => info.allowed_effects.contains(&effect),
        None => true,
    }
}

/// Check whether an observable is relevant for a tool. Unknown tools allow all.
pub fn is_observable_relevant(tool_name: &str, tag: ObservableTag) -> bool {
    match lookup(tool_name) {
        Some(info) => info.relevant_observables.contains(&tag),
        None => true,
    }
}

/// Build the effect options and hints for a given tool context.
/// Returns (labels, hints) vecs filtered to allowed effects.
pub fn effect_options_for_tool(tool_name: Option<&str>) -> (Vec<String>, Vec<&'static str>) {
    let all = [
        (EffectOption::Allow, "allow (permit)", ""),
        (EffectOption::Deny, "deny (block)", ""),
        (EffectOption::Ask, "ask (prompt)", ""),
    ];
    match tool_name.and_then(lookup) {
        Some(info) => {
            let mut labels = Vec::new();
            let mut hints = Vec::new();
            for &(effect, label, hint) in &all {
                if info.allowed_effects.contains(&effect) {
                    labels.push(label.into());
                    hints.push(hint);
                }
            }
            (labels, hints)
        }
        None => {
            let labels = all.iter().map(|(_, l, _)| l.to_string()).collect();
            let hints = all.iter().map(|(_, _, h)| *h).collect();
            (labels, hints)
        }
    }
}

/// Map a filtered effect index back to the canonical 0/1/2 index
/// (allow=0, deny=1, ask=2) used by apply functions.
pub fn filtered_effect_to_canonical(
    tool_name: Option<&str>,
    filtered_idx: usize,
) -> usize {
    let all = [EffectOption::Allow, EffectOption::Deny, EffectOption::Ask];
    match tool_name.and_then(lookup) {
        Some(info) => {
            let allowed: Vec<usize> = all
                .iter()
                .enumerate()
                .filter(|(_, e)| info.allowed_effects.contains(e))
                .map(|(i, _)| i)
                .collect();
            allowed.get(filtered_idx).copied().unwrap_or(filtered_idx)
        }
        None => filtered_idx,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bash_no_ask() {
        assert!(is_effect_allowed("Bash", EffectOption::Allow));
        assert!(is_effect_allowed("Bash", EffectOption::Deny));
        assert!(!is_effect_allowed("Bash", EffectOption::Ask));
    }

    #[test]
    fn test_case_insensitive_lookup() {
        assert!(lookup("bash").is_some());
        assert!(lookup("BASH").is_some());
        assert!(lookup("Bash").is_some());
    }

    #[test]
    fn test_unknown_tool_permissive() {
        assert!(is_effect_allowed("mcp__custom_tool", EffectOption::Ask));
        assert!(is_observable_relevant("mcp__custom_tool", ObservableTag::FsPath));
    }

    #[test]
    fn test_effect_filtering() {
        let (labels, _) = effect_options_for_tool(Some("Bash"));
        assert_eq!(labels.len(), 2);
        assert!(labels.contains(&"allow (permit)".to_string()));
        assert!(labels.contains(&"deny (block)".to_string()));
        assert!(!labels.contains(&"ask (prompt)".to_string()));
    }

    #[test]
    fn test_filtered_index_mapping() {
        // Bash: [allow, deny] → canonical [0, 1]
        assert_eq!(filtered_effect_to_canonical(Some("Bash"), 0), 0); // allow
        assert_eq!(filtered_effect_to_canonical(Some("Bash"), 1), 1); // deny
        // Unknown: identity
        assert_eq!(filtered_effect_to_canonical(None, 2), 2);
    }

    #[test]
    fn test_observable_relevance() {
        assert!(is_observable_relevant("Bash", ObservableTag::PositionalArg));
        assert!(is_observable_relevant("Bash", ObservableTag::HasArg));
        assert!(!is_observable_relevant("Bash", ObservableTag::FsPath));
        assert!(!is_observable_relevant("Bash", ObservableTag::NetDomain));

        assert!(is_observable_relevant("Read", ObservableTag::FsPath));
        assert!(!is_observable_relevant("Read", ObservableTag::NetDomain));

        assert!(is_observable_relevant("WebSearch", ObservableTag::NetDomain));
        assert!(!is_observable_relevant("WebSearch", ObservableTag::FsPath));
    }
}
