//! Generate a starter policy from an observed session trace.
//!
//! Reads a `trace.jsonl` (toolpath steps) or `audit.jsonl` file and extracts
//! unique tool invocations to generate a Starlark policy file.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result};

use crate::ui;

/// A single observed tool invocation extracted from a trace/audit file.
#[derive(Debug, Clone)]
struct ToolInvocation {
    tool_name: String,
    /// For Bash tools, the binary name extracted from the command.
    binary: Option<String>,
}

/// Summary of observations from a trace file.
#[derive(Debug)]
pub(crate) struct TraceAnalysis {
    /// Total number of tool invocations observed.
    pub(crate) total_invocations: usize,
    /// Unique tool names (non-Bash) that were used.
    pub(crate) tools: BTreeSet<String>,
    /// Unique binaries invoked via Bash.
    pub(crate) binaries: BTreeSet<String>,
}

/// Read a trace or audit JSONL file and generate a starter Starlark policy.
///
/// Returns the path where the policy was written.
pub fn run(trace_path: &Path) -> Result<std::path::PathBuf> {
    let trace_path = if trace_path.to_string_lossy() == "latest" {
        find_latest_trace()?
    } else {
        trace_path.to_path_buf()
    };

    if !trace_path.exists() {
        anyhow::bail!(
            "trace file not found: {}\n\
             Hint: run a Claude Code session with clash enabled to generate a trace.",
            trace_path.display()
        );
    }

    let content = std::fs::read_to_string(&trace_path)
        .with_context(|| format!("reading {}", trace_path.display()))?;

    let invocations = if is_audit_file(&trace_path, &content) {
        parse_audit_jsonl(&content)?
    } else {
        parse_trace_jsonl(&content)?
    };

    let analysis = analyze(&invocations);

    // Display summary
    println!();
    ui::info("Based on your last session:");
    ui::success(&format!(
        "{} tool invocations observed",
        analysis.total_invocations
    ));

    let mut tool_summary_parts = Vec::new();
    if !analysis.binaries.is_empty() {
        let bins: Vec<&str> = analysis.binaries.iter().map(|s| s.as_str()).collect();
        tool_summary_parts.push(format!("Bash ({})", bins.join(", ")));
    }
    for t in &analysis.tools {
        tool_summary_parts.push(t.clone());
    }
    if !tool_summary_parts.is_empty() {
        ui::info(&format!("  Tools used: {}", tool_summary_parts.join(", ")));
    }

    // Generate and write the policy
    let policy_content = generate_starlark(&analysis);

    let policy_path = crate::settings::ClashSettings::policy_file()
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join(".clash")
                .join("policy.star")
        })
        .with_extension("star");

    if let Some(parent) = policy_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }

    std::fs::write(&policy_path, &policy_content)
        .with_context(|| format!("writing policy to {}", policy_path.display()))?;

    println!();
    ui::success(&format!("Generated policy -> {}", policy_path.display()));

    // Print a summary of what was generated
    for bin in &analysis.binaries {
        ui::info(&format!("  when({{\"Bash\": {{\"{}\": allow()}}}})", bin));
    }
    if !analysis.tools.is_empty() {
        let tool_names: Vec<String> = analysis
            .tools
            .iter()
            .map(|t| format!("\"{}\"", t))
            .collect();
        if tool_names.len() == 1 {
            ui::info(&format!("  when({{{}: allow()}})", tool_names[0]));
        } else {
            ui::info(&format!("  when({{({}): allow()}})", tool_names.join(", ")));
        }
    }
    ui::info("  default = ask");

    Ok(policy_path)
}

/// Mine unique binary names from audit/trace JSONL content.
pub fn mine_binaries_from_content(content: &str) -> std::collections::BTreeSet<String> {
    let mut binaries = std::collections::BTreeSet::new();
    let invocations = if content
        .lines()
        .find(|l| !l.trim().is_empty())
        .is_some_and(|l| {
            l.contains("\"tool_name\"") && l.contains("\"decision\"") && !l.contains("\"step\"")
        }) {
        parse_audit_jsonl(content).unwrap_or_default()
    } else {
        parse_trace_jsonl(content).unwrap_or_default()
    };
    for inv in &invocations {
        if inv.tool_name == "Bash" {
            if let Some(ref bin) = inv.binary {
                binaries.insert(bin.clone());
            }
        }
    }
    binaries
}

/// Mine binaries from all available session traces.
pub fn mine_binaries_from_history() -> std::collections::BTreeSet<String> {
    let mut all_binaries = std::collections::BTreeSet::new();
    let tmp = std::env::temp_dir();
    let readdir = match std::fs::read_dir(&tmp) {
        Ok(r) => r,
        Err(_) => return all_binaries,
    };
    for entry in readdir.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("clash-") {
            continue;
        }
        let audit_path = entry.path().join("audit.jsonl");
        let trace_path = entry.path().join("trace.jsonl");
        let candidate = if audit_path.exists() {
            audit_path
        } else if trace_path.exists() {
            trace_path
        } else {
            continue;
        };
        if let Ok(content) = std::fs::read_to_string(&candidate) {
            all_binaries.extend(mine_binaries_from_content(&content));
        }
    }
    all_binaries
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Detect whether the file is an audit.jsonl (has "tool_name" + "decision" keys)
/// or a trace.jsonl (has "step" + "change" keys).
fn is_audit_file(path: &Path, content: &str) -> bool {
    if path
        .file_name()
        .is_some_and(|n| n.to_string_lossy().contains("audit"))
    {
        return true;
    }
    // Heuristic: check the first non-empty line
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        return line.contains("\"tool_name\"")
            && line.contains("\"decision\"")
            && !line.contains("\"step\"");
    }
    false
}

/// Parse a trace.jsonl file (toolpath v1::Step objects).
///
/// Extracts tool names from policy evaluation steps and conversation steps.
fn parse_trace_jsonl(content: &str) -> Result<Vec<ToolInvocation>> {
    let mut invocations = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let step: serde_json::Value =
            serde_json::from_str(line).context("parsing step from trace.jsonl")?;

        // Check for policy evaluation steps (clash://policy/evaluations)
        if let Some(change) = step.get("change") {
            if let Some(eval) = change.get("clash://policy/evaluations")
                && let Some(structural) = eval.get("structural")
            {
                let tool_name = structural
                    .pointer("/tool_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();

                if !tool_name.is_empty() {
                    invocations.push(ToolInvocation {
                        tool_name: tool_name.to_string(),
                        binary: None,
                    });
                }
            }

            // Also check conversation steps for tool_uses
            for (_key, artifact) in change.as_object().into_iter().flatten() {
                if let Some(structural) = artifact.get("structural")
                    && let Some(tool_uses) = structural.get("tool_uses")
                    && let Some(arr) = tool_uses.as_array()
                {
                    for tool in arr {
                        if let Some(name) = tool.as_str()
                            && !invocations.iter().any(|i| i.tool_name == name)
                        {
                            invocations.push(ToolInvocation {
                                tool_name: name.to_string(),
                                binary: None,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(invocations)
}

/// Parse an audit.jsonl file (richer format with tool_input_summary).
fn parse_audit_jsonl(content: &str) -> Result<Vec<ToolInvocation>> {
    let mut invocations = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let entry: serde_json::Value =
            serde_json::from_str(line).context("parsing entry from audit.jsonl")?;

        // Skip sandbox_violation entries
        if entry.get("decision").and_then(|v| v.as_str()) == Some("sandbox_violation") {
            continue;
        }

        let tool_name = match entry.get("tool_name").and_then(|v| v.as_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };

        let binary = if tool_name == "Bash" {
            entry
                .get("tool_input_summary")
                .and_then(|v| v.as_str())
                .and_then(|summary| extract_binary_from_summary(summary))
                .map(|s| s.to_string())
        } else {
            None
        };

        invocations.push(ToolInvocation { tool_name, binary });
    }

    Ok(invocations)
}

/// Extract the binary name from an audit tool_input_summary or a raw command string.
///
/// The summary for Bash tools is typically the command itself (e.g., "git push origin main").
fn extract_binary_from_summary(summary: &str) -> Option<&str> {
    let summary = summary.trim();
    if summary.is_empty() {
        return None;
    }
    // Take the first word as the binary
    let binary = summary.split_whitespace().next()?;
    // Skip shell built-ins and inline scripts
    if binary.starts_with('{')
        || binary.starts_with('(')
        || binary.contains('/') && binary.len() > 20
    {
        return None;
    }
    // Return just the binary name (strip any path prefix)
    let binary = binary.rsplit('/').next().unwrap_or(binary);
    Some(binary)
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

fn analyze(invocations: &[ToolInvocation]) -> TraceAnalysis {
    let mut tools = BTreeSet::new();
    let mut binaries = BTreeSet::new();

    for inv in invocations {
        if inv.tool_name == "Bash" {
            if let Some(ref bin) = inv.binary {
                binaries.insert(bin.clone());
            }
        } else {
            tools.insert(inv.tool_name.clone());
        }
    }

    // If we saw Bash invocations but couldn't extract any binaries (trace.jsonl
    // doesn't carry command detail), note it by adding a wildcard binary.
    let saw_bash = invocations.iter().any(|i| i.tool_name == "Bash");
    if saw_bash && binaries.is_empty() {
        // We know Bash was used but don't know which binaries. Still list it.
        // We'll generate when({"Bash": allow()}) to cover all commands.
    }

    TraceAnalysis {
        total_invocations: invocations.len(),
        tools,
        binaries,
    }
}

// ---------------------------------------------------------------------------
// Policy generation
// ---------------------------------------------------------------------------

fn generate_starlark(analysis: &TraceAnalysis) -> String {
    use crate::policy_gen::spec::PolicySpec;
    PolicySpec::from_trace(analysis).to_starlark()
}

// ---------------------------------------------------------------------------
// Latest trace discovery
// ---------------------------------------------------------------------------

/// Find the most recent trace.jsonl across all session directories.
fn find_latest_trace() -> Result<std::path::PathBuf> {
    let tmp = std::env::temp_dir();
    let mut best: Option<(std::time::SystemTime, std::path::PathBuf)> = None;

    let readdir = std::fs::read_dir(&tmp).context("reading temp directory")?;
    for entry in readdir.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("clash-") {
            continue;
        }

        // Prefer audit.jsonl for richer data, fall back to trace.jsonl
        let audit_path = entry.path().join("audit.jsonl");
        let trace_path = entry.path().join("trace.jsonl");

        let candidate = if audit_path.exists() {
            audit_path
        } else if trace_path.exists() {
            trace_path
        } else {
            continue;
        };

        if let Ok(meta) = candidate.metadata()
            && let Ok(modified) = meta.modified()
            && meta.len() > 0
            && best.as_ref().is_none_or(|(t, _)| modified > *t)
        {
            best = Some((modified, candidate));
        }
    }

    best.map(|(_, p)| p)
        .ok_or_else(|| anyhow::anyhow!("no session traces found — run a Claude Code session first"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_binary_from_summary() {
        assert_eq!(
            extract_binary_from_summary("git push origin main"),
            Some("git")
        );
        assert_eq!(extract_binary_from_summary("npm install"), Some("npm"));
        assert_eq!(extract_binary_from_summary("cargo test"), Some("cargo"));
        assert_eq!(extract_binary_from_summary(""), None);
        assert_eq!(extract_binary_from_summary("  ls -la  "), Some("ls"));
    }

    #[test]
    fn test_parse_trace_jsonl_policy_steps() {
        let trace = r#"{"step":{"id":"s1","actor":"agent:clash-policy","timestamp":"2025-01-15T10:00:00Z"},"change":{"clash://policy/evaluations":{"structural":{"type":"policy_evaluation","tool_name":"Bash","effect":"allow","tool_use_id":"tu-1"}}},"meta":{"intent":"allow Bash use"}}
{"step":{"id":"s2","actor":"agent:clash-policy","timestamp":"2025-01-15T10:01:00Z"},"change":{"clash://policy/evaluations":{"structural":{"type":"policy_evaluation","tool_name":"Read","effect":"allow","tool_use_id":"tu-2"}}},"meta":{"intent":"allow Read use"}}"#;

        let invocations = parse_trace_jsonl(trace).unwrap();
        assert_eq!(invocations.len(), 2);
        assert_eq!(invocations[0].tool_name, "Bash");
        assert_eq!(invocations[1].tool_name, "Read");
    }

    #[test]
    fn test_parse_trace_jsonl_conversation_steps() {
        // Conversation steps have tool_uses in the structural extra
        let trace = r#"{"step":{"id":"s1","actor":"agent:claude","timestamp":"2025-01-15T10:00:00Z"},"change":{"claude://session1":{"structural":{"type":"conversation.append","role":"assistant","tool_uses":["Bash","Read"]}}}}"#;

        let invocations = parse_trace_jsonl(trace).unwrap();
        assert_eq!(invocations.len(), 2);
        assert_eq!(invocations[0].tool_name, "Bash");
        assert_eq!(invocations[1].tool_name, "Read");
    }

    #[test]
    fn test_parse_audit_jsonl() {
        let audit = r#"{"timestamp":"1706123456.789","session_id":"s1","tool_name":"Bash","tool_input_summary":"git status","decision":"allow","reason":"matched","matched_rules":1,"skipped_rules":0,"resolution":"allow"}
{"timestamp":"1706123457.000","session_id":"s1","tool_name":"Read","tool_input_summary":"/tmp/file.rs","decision":"allow","reason":null,"matched_rules":1,"skipped_rules":0,"resolution":"allow"}
{"timestamp":"1706123458.000","session_id":"s1","tool_name":"Bash","tool_input_summary":"cargo test","decision":"allow","reason":"matched","matched_rules":1,"skipped_rules":0,"resolution":"allow"}"#;

        let invocations = parse_audit_jsonl(audit).unwrap();
        assert_eq!(invocations.len(), 3);
        assert_eq!(invocations[0].tool_name, "Bash");
        assert_eq!(invocations[0].binary.as_deref(), Some("git"));
        assert_eq!(invocations[1].tool_name, "Read");
        assert_eq!(invocations[1].binary, None);
        assert_eq!(invocations[2].tool_name, "Bash");
        assert_eq!(invocations[2].binary.as_deref(), Some("cargo"));
    }

    #[test]
    fn test_analyze() {
        let invocations = vec![
            ToolInvocation {
                tool_name: "Bash".into(),
                binary: Some("git".into()),
            },
            ToolInvocation {
                tool_name: "Bash".into(),
                binary: Some("npm".into()),
            },
            ToolInvocation {
                tool_name: "Bash".into(),
                binary: Some("git".into()),
            },
            ToolInvocation {
                tool_name: "Read".into(),
                binary: None,
            },
            ToolInvocation {
                tool_name: "Write".into(),
                binary: None,
            },
            ToolInvocation {
                tool_name: "Grep".into(),
                binary: None,
            },
        ];

        let analysis = analyze(&invocations);
        assert_eq!(analysis.total_invocations, 6);
        assert_eq!(analysis.binaries.len(), 2); // git, npm (deduplicated)
        assert!(analysis.binaries.contains("git"));
        assert!(analysis.binaries.contains("npm"));
        assert_eq!(analysis.tools.len(), 3); // Read, Write, Grep
        assert!(analysis.tools.contains("Read"));
        assert!(analysis.tools.contains("Write"));
        assert!(analysis.tools.contains("Grep"));
    }

    #[test]
    fn test_generate_starlark_basic() {
        let analysis = TraceAnalysis {
            total_invocations: 5,
            tools: BTreeSet::from(["Read".into(), "Write".into(), "Grep".into()]),
            binaries: BTreeSet::from(["git".into(), "cargo".into()]),
        };

        let policy = generate_starlark(&analysis);

        // Should contain loads
        assert!(policy.contains("load(\"@clash//builtin.star\""));
        assert!(policy.contains("load(\"@clash//sandboxes.star\""));

        // Should contain tool rules
        assert!(policy.contains("(\"Read\", \"Grep\"): allow(sandbox = project_files)"));
        assert!(policy.contains("\"Write\": allow(sandbox = project_files)"));

        // Should contain when rules for binaries
        assert!(policy.contains("\"Bash\":"));
        assert!(policy.contains("allow(sandbox = project)"));

        // Should contain git safety rules
        assert!(policy.contains("\"--force\": deny()"));
        assert!(policy.contains("\"--hard\": deny()"));

        // Should have default = ask
        assert!(policy.contains("default = ask"));

        // Should be valid structure
        assert!(policy.contains("settings("));
        assert!(policy.contains("policy("));
    }

    #[test]
    fn test_generate_starlark_no_binaries() {
        let analysis = TraceAnalysis {
            total_invocations: 3,
            tools: BTreeSet::from(["Read".into(), "Edit".into()]),
            binaries: BTreeSet::new(),
        };

        let policy = generate_starlark(&analysis);
        assert!(policy.contains("\"Read\": allow(sandbox = project_files)"));
        assert!(policy.contains("\"Edit\": allow(sandbox = project_files)"));
        // No binary-specific rules (no "git", "cargo" etc.)
        assert!(!policy.contains("# Observed binaries"));
    }

    #[test]
    fn test_generate_starlark_bash_without_binary_detail() {
        // When we see Bash from trace.jsonl but can't extract binaries
        let analysis = TraceAnalysis {
            total_invocations: 5,
            tools: BTreeSet::from(["Read".into()]),
            binaries: BTreeSet::new(),
        };

        let policy = generate_starlark(&analysis);
        // Should generate a generic Bash when rule since we know bash was used
        // but total_invocations > tools count
        assert!(policy.contains("{\"Bash\": allow(sandbox = project)}"), "expected dict syntax in:\n{policy}");
    }

    #[test]
    fn test_is_audit_file() {
        let audit_content =
            r#"{"timestamp":"1706123456.789","tool_name":"Bash","decision":"allow"}"#;
        let trace_content = r#"{"step":{"id":"s1","actor":"agent:claude","timestamp":"2025-01-15T10:00:00Z"},"change":{}}"#;

        assert!(is_audit_file(Path::new("audit.jsonl"), audit_content));
        assert!(is_audit_file(Path::new("/tmp/clash-abc/audit.jsonl"), "{}"));
        assert!(!is_audit_file(Path::new("trace.jsonl"), trace_content));
    }

    #[test]
    fn test_parse_audit_skips_sandbox_violations() {
        let audit = r#"{"timestamp":"1.0","session_id":"s1","tool_name":"Bash","tool_input_summary":"git status","decision":"allow","matched_rules":1,"skipped_rules":0,"resolution":"allow"}
{"timestamp":"2.0","session_id":"s1","tool_name":"Bash","tool_use_id":"tu-1","decision":"sandbox_violation","tool_input_summary":"rm -rf","violations":[],"suggested_rules":[]}"#;

        let invocations = parse_audit_jsonl(audit).unwrap();
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].binary.as_deref(), Some("git"));
    }

    #[test]
    fn test_mine_observed_binaries() {
        let audit = r#"{"timestamp":"1.0","session_id":"s1","tool_name":"Bash","tool_input_summary":"git status","decision":"allow","matched_rules":1,"skipped_rules":0,"resolution":"allow"}
{"timestamp":"2.0","session_id":"s1","tool_name":"Bash","tool_input_summary":"cargo test","decision":"allow","matched_rules":1,"skipped_rules":0,"resolution":"allow"}
{"timestamp":"3.0","session_id":"s1","tool_name":"Read","tool_input_summary":"/tmp/file","decision":"allow","matched_rules":1,"skipped_rules":0,"resolution":"allow"}"#;
        let binaries = mine_binaries_from_content(audit);
        assert!(binaries.contains("git"));
        assert!(binaries.contains("cargo"));
        assert!(!binaries.contains("Read"));
    }

    #[test]
    fn test_generate_starlark_with_net_tools() {
        let analysis = TraceAnalysis {
            total_invocations: 2,
            tools: BTreeSet::from(["WebFetch".into(), "WebSearch".into()]),
            binaries: BTreeSet::new(),
        };

        let policy = generate_starlark(&analysis);
        // Network tools should use ask(), not allow()
        assert!(policy.contains("(\"WebFetch\", \"WebSearch\"): ask()"));
    }
}
