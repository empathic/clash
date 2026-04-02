//! TUI-specific tool metadata for the policy editor.
//!
//! Provides effect filtering and observable relevance on top of the canonical
//! tool definitions in [`crate::claude::tools`]. Unknown/MCP tools get
//! permissive defaults (all effects allowed, all observables relevant).

use crate::claude::tools as ct;

/// Which effects are valid for a tool in policy rules.
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

/// TUI-layer metadata that extends a [`ct::ToolDef`] with effect and
/// observable constraints specific to the policy editor.
pub struct ToolTuiInfo {
    /// Reference to the canonical tool definition.
    pub def: &'static ct::ToolDef,
    /// Which effects are valid for rules targeting this tool.
    pub allowed_effects: &'static [EffectOption],
    /// Which observables are useful when adding child conditions.
    pub relevant_observables: &'static [ObservableTag],
}

const ALL_EFFECTS: &[EffectOption] = &[EffectOption::Allow, EffectOption::Deny, EffectOption::Ask];
const NO_ASK: &[EffectOption] = &[EffectOption::Allow, EffectOption::Deny];

/// TUI metadata for well-known Claude Code tools.
///
/// Tool names, descriptions, and parameter lists come from
/// [`crate::claude::tools`]; this table only adds the TUI-specific
/// effect and observable constraints.
pub const TOOLS: &[ToolTuiInfo] = &[
    ToolTuiInfo {
        def: &ct::BASH,
        allowed_effects: NO_ASK,
        relevant_observables: &[
            ObservableTag::PositionalArg,
            ObservableTag::HasArg,
            ObservableTag::NamedArg,
        ],
    },
    ToolTuiInfo {
        def: &ct::READ,
        allowed_effects: ALL_EFFECTS,
        relevant_observables: &[ObservableTag::FsPath, ObservableTag::FsOp],
    },
    ToolTuiInfo {
        def: &ct::WRITE,
        allowed_effects: ALL_EFFECTS,
        relevant_observables: &[ObservableTag::FsPath, ObservableTag::FsOp],
    },
    ToolTuiInfo {
        def: &ct::EDIT,
        allowed_effects: ALL_EFFECTS,
        relevant_observables: &[ObservableTag::FsPath, ObservableTag::FsOp],
    },
    ToolTuiInfo {
        def: &ct::MULTI_EDIT,
        allowed_effects: ALL_EFFECTS,
        relevant_observables: &[ObservableTag::FsPath, ObservableTag::FsOp],
    },
    ToolTuiInfo {
        def: &ct::GLOB,
        allowed_effects: ALL_EFFECTS,
        relevant_observables: &[ObservableTag::FsPath, ObservableTag::FsOp],
    },
    ToolTuiInfo {
        def: &ct::GREP,
        allowed_effects: ALL_EFFECTS,
        relevant_observables: &[ObservableTag::FsPath, ObservableTag::FsOp],
    },
    ToolTuiInfo {
        def: &ct::WEB_FETCH,
        allowed_effects: ALL_EFFECTS,
        relevant_observables: &[ObservableTag::NetDomain],
    },
    ToolTuiInfo {
        def: &ct::WEB_SEARCH,
        allowed_effects: ALL_EFFECTS,
        relevant_observables: &[ObservableTag::NetDomain],
    },
    ToolTuiInfo {
        def: &ct::AGENT,
        allowed_effects: ALL_EFFECTS,
        relevant_observables: &[ObservableTag::AgentName, ObservableTag::NamedArg],
    },
    ToolTuiInfo {
        def: &ct::NOTEBOOK_EDIT,
        allowed_effects: ALL_EFFECTS,
        relevant_observables: &[ObservableTag::FsPath],
    },
];

/// Look up TUI info by tool name (case-insensitive). Returns `None` for unknown/MCP tools.
pub fn lookup(name: &str) -> Option<&'static ToolTuiInfo> {
    TOOLS.iter().find(|t| t.def.name.eq_ignore_ascii_case(name))
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
pub fn effect_options_for_tool(tool_name: Option<&str>) -> (Vec<String>, Vec<String>) {
    let all = [
        (EffectOption::Allow, "auto allow", ""),
        (EffectOption::Deny, "auto deny", ""),
        (EffectOption::Ask, "ask (prompt)", ""),
    ];
    match tool_name.and_then(lookup) {
        Some(info) => {
            let mut labels = Vec::new();
            let mut hints = Vec::new();
            for &(effect, label, hint) in &all {
                if info.allowed_effects.contains(&effect) {
                    labels.push(label.into());
                    hints.push(hint.into());
                }
            }
            (labels, hints)
        }
        None => {
            let labels = all.iter().map(|(_, l, _)| l.to_string()).collect();
            let hints = all.iter().map(|(_, _, h)| String::from(*h)).collect();
            (labels, hints)
        }
    }
}

/// Map a filtered effect index back to the canonical 0/1/2 index
/// (allow=0, deny=1, ask=2) used by apply functions.
pub fn filtered_effect_to_canonical(tool_name: Option<&str>, filtered_idx: usize) -> usize {
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
        assert!(is_observable_relevant(
            "mcp__custom_tool",
            ObservableTag::FsPath
        ));
    }

    #[test]
    fn test_effect_filtering() {
        let (labels, _) = effect_options_for_tool(Some("Bash"));
        assert_eq!(labels.len(), 2);
        assert!(labels.contains(&"auto allow".to_string()));
        assert!(labels.contains(&"auto deny".to_string()));
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

        assert!(is_observable_relevant(
            "WebSearch",
            ObservableTag::NetDomain
        ));
        assert!(!is_observable_relevant("WebSearch", ObservableTag::FsPath));
    }

    #[test]
    fn tui_tools_reference_canonical_defs() {
        // Verify TUI entries are backed by the canonical registry
        for tui_info in TOOLS {
            assert!(
                ct::lookup(tui_info.def.name).is_some(),
                "TUI tool {:?} not found in canonical registry",
                tui_info.def.name
            );
        }
    }
}
