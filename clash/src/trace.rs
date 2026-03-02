//! Toolpath-based session tracing.
//!
//! Maintains a toolpath trace in the session directory using two files:
//! - `trace.jsonl` — append-only, one `v1::Step` JSON per line
//! - `trace.json` — small metadata: Path identity + PathMeta + TraceState
//!
//! Incrementally updated from the Claude Code conversation JSONL on each
//! hook invocation. Runs alongside the audit subsystem without depending on it.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, bail};
use toolpath::v1;
use toolpath_claude::ConversationReader;
use toolpath_claude::types::{ConversationEntry, MessageRole};

/// A policy decision to record as a trace Step.
pub struct PolicyDecision {
    pub tool_use_id: String,
    pub tool_name: Option<String>,
    /// "allow", "deny", or "ask"
    pub effect: String,
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Session-dir file helpers
// ---------------------------------------------------------------------------

fn session_dir(session_id: &str) -> PathBuf {
    crate::audit::session_dir(session_id)
}

fn trace_path(session_id: &str) -> PathBuf {
    session_dir(session_id).join("trace.json")
}

fn trace_jsonl_path(session_id: &str) -> PathBuf {
    session_dir(session_id).join("trace.jsonl")
}

fn transcript_path_file(session_id: &str) -> PathBuf {
    session_dir(session_id).join("trace_transcript")
}

// ---------------------------------------------------------------------------
// Internal state stored in Path meta.extra["trace"]
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TraceState {
    /// Monotonic step counter for generating step IDs.
    step_counter: u64,
    /// Byte offset into the conversation JSONL for incremental reads.
    convo_byte_offset: u64,
    /// Step ID of the last step (for parent chaining).
    last_step_id: Option<String>,
    /// Map from tool_use_id → step_id for policy annotation lookups.
    tool_use_steps: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize tracing for a new session. Creates the initial trace files
/// and stores the transcript_path for subsequent syncs.
pub fn init_trace(
    session_id: &str,
    transcript_path: &str,
    cwd: &str,
    model: Option<&str>,
    source: Option<&str>,
) -> anyhow::Result<()> {
    let dir = session_dir(session_id);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating session dir: {}", dir.display()))?;

    // Store transcript path for future sync calls.
    std::fs::write(transcript_path_file(session_id), transcript_path)
        .context("writing trace_transcript")?;

    // Build initial (empty) Path — steps live in trace.jsonl, not here.
    let base_uri = format!("file://{cwd}");
    let base = v1::Base {
        uri: base_uri,
        ref_str: None,
    };
    let mut path = v1::Path::new(session_id, Some(base), "head");

    let mut actors = HashMap::new();
    if let Some(m) = model {
        let actor_key = format!("agent:{m}");
        actors.insert(
            actor_key,
            v1::ActorDefinition {
                name: Some(m.to_string()),
                model: Some(m.to_string()),
                provider: Some("anthropic".to_string()),
                ..Default::default()
            },
        );
    }
    actors.insert(
        "human:user".to_string(),
        v1::ActorDefinition {
            name: Some("user".to_string()),
            ..Default::default()
        },
    );
    actors.insert(
        "agent:clash-policy".to_string(),
        v1::ActorDefinition {
            name: Some("clash-policy".to_string()),
            ..Default::default()
        },
    );

    let state = TraceState {
        step_counter: 0,
        convo_byte_offset: 0,
        last_step_id: None,
        tool_use_steps: HashMap::new(),
    };

    let meta = path.meta.get_or_insert_with(v1::PathMeta::default);
    meta.actors = Some(actors);
    if let Some(s) = source {
        meta.source = Some(s.to_string());
    }

    // Create empty trace.jsonl.
    std::fs::write(trace_jsonl_path(session_id), "").context("creating trace.jsonl")?;

    save_state(session_id, &path, &state)?;

    Ok(())
}

/// Read new conversation entries from the JSONL and update the trace.
/// Optionally record a policy decision for a specific tool_use_id.
pub fn sync_trace(session_id: &str, decision: Option<PolicyDecision>) -> anyhow::Result<()> {
    let transcript = std::fs::read_to_string(transcript_path_file(session_id))
        .context("reading trace_transcript")?;
    let transcript = transcript.trim();

    // Load current state (no steps — those are in trace.jsonl).
    let (mut path, mut state) = load_state(session_id)?;

    // Read new entries from conversation JSONL at the stored offset.
    let (entries, new_offset) =
        ConversationReader::read_from_offset(transcript, state.convo_byte_offset)
            .context("reading conversation JSONL")?;

    // Build new steps in memory.
    let mut new_steps: Vec<v1::Step> = Vec::new();
    for entry in &entries {
        if let Some(step) = entry_to_step(&mut state, entry) {
            new_steps.push(step);
        }
    }

    // Create a dedicated policy-evaluation step if we have a decision.
    if let Some(dec) = decision {
        let policy_step = make_policy_step(&mut state, &dec);
        new_steps.push(policy_step);
    }

    // Update head to point to latest step.
    if let Some(ref last) = state.last_step_id {
        path.path.head = last.clone();
    }

    state.convo_byte_offset = new_offset;

    // Append new steps to trace.jsonl, then update state file.
    append_steps(session_id, &new_steps)?;
    save_state(session_id, &path, &state)?;

    Ok(())
}

/// Export the current trace as a toolpath Document.
pub fn export_trace(session_id: &str) -> anyhow::Result<v1::Document> {
    let (mut path, _state) = load_state(session_id)?;

    // Strip internal trace state from exported metadata.
    if let Some(ref mut meta) = path.meta {
        meta.extra.remove("trace");
    }

    // Read steps from trace.jsonl.
    path.steps = load_steps(session_id)?;

    Ok(v1::Document::Path(path))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn load_state(session_id: &str) -> anyhow::Result<(v1::Path, TraceState)> {
    let data = std::fs::read_to_string(trace_path(session_id)).context("reading trace.json")?;
    let doc: v1::Document = serde_json::from_str(&data).context("parsing trace.json")?;
    let v1::Document::Path(mut path) = doc else {
        bail!("trace.json is not a Path document");
    };
    let state_value = path
        .meta
        .as_mut()
        .and_then(|m| m.extra.remove("trace"))
        .context("trace.json missing meta.trace state")?;
    let state: TraceState = serde_json::from_value(state_value).context("parsing meta.trace")?;
    Ok((path, state))
}

fn save_state(session_id: &str, path: &v1::Path, state: &TraceState) -> anyhow::Result<()> {
    // Save Path with state embedded but no steps.
    let mut path = path.clone();
    path.steps.clear();
    let meta = path.meta.get_or_insert_with(v1::PathMeta::default);
    meta.extra.insert(
        "trace".to_string(),
        serde_json::to_value(state).context("serializing trace state")?,
    );
    let doc = v1::Document::Path(path);
    let json = serde_json::to_string_pretty(&doc).context("serializing trace state document")?;

    let out = trace_path(session_id);
    let dir = out.parent().unwrap();
    let tmp = dir.join(".trace.json.tmp");
    std::fs::write(&tmp, &json).context("writing trace state tmp file")?;
    std::fs::rename(&tmp, &out).context("renaming trace tmp to trace.json")?;
    Ok(())
}

fn append_steps(session_id: &str, steps: &[v1::Step]) -> anyhow::Result<()> {
    if steps.is_empty() {
        return Ok(());
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(trace_jsonl_path(session_id))
        .context("opening trace.jsonl for append")?;
    for step in steps {
        let line = serde_json::to_string(step).context("serializing step")?;
        writeln!(f, "{line}").context("appending step to trace.jsonl")?;
    }
    Ok(())
}

fn load_steps(session_id: &str) -> anyhow::Result<Vec<v1::Step>> {
    let data =
        std::fs::read_to_string(trace_jsonl_path(session_id)).context("reading trace.jsonl")?;
    let mut steps = Vec::new();
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let step: v1::Step = serde_json::from_str(line).context("parsing step from trace.jsonl")?;
        steps.push(step);
    }
    Ok(steps)
}

fn now_iso8601() -> String {
    // Simple ISO 8601 from system time.
    let now = std::time::SystemTime::now();
    let dur = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Approximate — good enough for trace timestamps.
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    // Days since epoch to date (simplified, no leap second handling).
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    days += 719468;
    let era = days / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Convert a conversation entry to a Step, returning None for entries that
/// should be skipped (system messages, entries without a role).
fn entry_to_step(state: &mut TraceState, entry: &ConversationEntry) -> Option<v1::Step> {
    let role = entry.role()?;

    let actor = match role {
        MessageRole::User => "human:user".to_string(),
        MessageRole::Assistant => {
            let model = entry.model().unwrap_or("claude");
            format!("agent:{model}")
        }
        MessageRole::System => return None,
    };

    let timestamp = if entry.timestamp.is_empty() {
        now_iso8601()
    } else {
        entry.timestamp.clone()
    };

    state.step_counter += 1;
    let step_id = format!("step-{}", state.step_counter);

    let mut step = v1::Step::new(&step_id, &actor, &timestamp);

    // Chain to previous step.
    if let Some(ref parent) = state.last_step_id {
        step = step.with_parent(parent);
    }

    // Build meta.extra with conversation content.
    let mut extra = HashMap::new();
    extra.insert("role".to_string(), serde_json::json!(role_str(role)));

    let text = entry.text();
    if !text.is_empty() {
        // Truncate long text for the trace.
        let truncated = if text.len() > 2000 {
            format!(
                "{}...",
                &text[..text
                    .char_indices()
                    .take_while(|&(i, _)| i <= 2000)
                    .last()
                    .map(|(i, _)| i)
                    .unwrap_or(0)]
            )
        } else {
            text
        };
        extra.insert("text".to_string(), serde_json::json!(truncated));
    }

    // Record tool uses.
    let tool_uses = entry.tool_uses();
    if !tool_uses.is_empty() {
        let tools: Vec<serde_json::Value> = tool_uses
            .iter()
            .map(|tu| {
                // Map tool_use_id → step_id for later annotation.
                state
                    .tool_use_steps
                    .insert(tu.id.to_string(), step_id.clone());

                serde_json::json!({
                    "tool_use_id": tu.id,
                    "tool_name": tu.name,
                    "tool_input": tu.input,
                })
            })
            .collect();
        extra.insert("tool_uses".to_string(), serde_json::json!(tools));
    }

    // Record tool results from user messages.
    if let Some(ref msg) = entry.message {
        let results = msg.tool_results();
        if !results.is_empty() {
            let result_summaries: Vec<serde_json::Value> = results
                .iter()
                .map(|tr| {
                    serde_json::json!({
                        "tool_use_id": tr.tool_use_id,
                        "is_error": tr.is_error,
                    })
                })
                .collect();
            extra.insert(
                "tool_results".to_string(),
                serde_json::json!(result_summaries),
            );
        }
    }

    let step_meta = step.meta.get_or_insert_with(|| v1::StepMeta {
        intent: None,
        source: None,
        refs: vec![],
        actors: None,
        signatures: vec![],
        extra: HashMap::new(),
    });
    step_meta.extra = extra;

    state.last_step_id = Some(step_id);
    Some(step)
}

/// Create a policy-evaluation step that records the decision as a
/// `StructuralChange` on the virtual artifact `clash://policy/evaluations`.
fn make_policy_step(state: &mut TraceState, decision: &PolicyDecision) -> v1::Step {
    state.step_counter += 1;
    let step_id = format!("step-{}", state.step_counter);

    let mut step = v1::Step::new(&step_id, "agent:clash-policy", now_iso8601());

    // Parent: the tool-use step being evaluated if known, otherwise the last step.
    let parent = state
        .tool_use_steps
        .get(&decision.tool_use_id)
        .or(state.last_step_id.as_ref());
    if let Some(parent_id) = parent {
        step = step.with_parent(parent_id);
    }

    // Build the structural change describing the evaluation.
    let mut extra = HashMap::new();
    extra.insert(
        "tool_use_id".to_string(),
        serde_json::json!(decision.tool_use_id),
    );
    if let Some(ref name) = decision.tool_name {
        extra.insert("tool_name".to_string(), serde_json::json!(name));
    }
    extra.insert("effect".to_string(), serde_json::json!(decision.effect));
    if let Some(ref reason) = decision.reason {
        extra.insert("reason".to_string(), serde_json::json!(reason));
    }

    let change = v1::ArtifactChange {
        raw: None,
        structural: Some(v1::StructuralChange {
            change_type: "policy_evaluation".to_string(),
            extra,
        }),
    };
    step.change
        .insert("clash://policy/evaluations".to_string(), change);

    state.last_step_id = Some(step_id);
    step
}

fn role_str(role: &MessageRole) -> &'static str {
    match role {
        MessageRole::User => "user",
        MessageRole::Assistant => "assistant",
        MessageRole::System => "system",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn write_jsonl(path: &std::path::Path, entries: &[serde_json::Value]) {
        let mut f = std::fs::File::create(path).unwrap();
        for entry in entries {
            writeln!(f, "{}", serde_json::to_string(entry).unwrap()).unwrap();
        }
    }

    fn make_user_entry(uuid: &str, text: &str) -> serde_json::Value {
        serde_json::json!({
            "uuid": uuid,
            "type": "human",
            "timestamp": "2025-01-15T10:00:00Z",
            "message": {
                "role": "user",
                "content": text
            }
        })
    }

    fn make_assistant_entry(uuid: &str, text: &str) -> serde_json::Value {
        serde_json::json!({
            "uuid": uuid,
            "type": "assistant",
            "timestamp": "2025-01-15T10:01:00Z",
            "message": {
                "role": "assistant",
                "model": "claude-sonnet-4-20250514",
                "content": [
                    {"type": "text", "text": text}
                ]
            }
        })
    }

    fn make_tool_use_entry(uuid: &str, tool_use_id: &str, tool_name: &str) -> serde_json::Value {
        serde_json::json!({
            "uuid": uuid,
            "type": "assistant",
            "timestamp": "2025-01-15T10:02:00Z",
            "message": {
                "role": "assistant",
                "model": "claude-sonnet-4-20250514",
                "content": [
                    {
                        "type": "tool_use",
                        "id": tool_use_id,
                        "name": tool_name,
                        "input": {"command": "ls -la"}
                    }
                ]
            }
        })
    }

    #[test]
    fn test_init_trace_creates_valid_path() {
        let session_id = format!("trace-init-{}", std::process::id());
        let dir = session_dir(&session_id);
        let _ = std::fs::remove_dir_all(&dir);

        let transcript = dir.join("fake-transcript.jsonl");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&transcript, "").unwrap();

        init_trace(
            &session_id,
            transcript.to_str().unwrap(),
            "/tmp/project",
            Some("claude-sonnet-4-20250514"),
            Some("startup"),
        )
        .unwrap();

        // Verify both files exist.
        assert!(trace_path(&session_id).exists(), "trace.json should exist");
        assert!(
            trace_jsonl_path(&session_id).exists(),
            "trace.jsonl should exist"
        );

        // Verify export produces valid Path.
        let doc = export_trace(&session_id).unwrap();
        let v1::Document::Path(path) = doc else {
            panic!("expected Path document");
        };
        assert_eq!(path.path.id, session_id);
        assert_eq!(path.path.base.as_ref().unwrap().uri, "file:///tmp/project");

        // Verify actors.
        let actors = path.meta.as_ref().unwrap().actors.as_ref().unwrap();
        assert!(actors.contains_key("agent:claude-sonnet-4-20250514"));
        assert!(actors.contains_key("human:user"));
        assert!(actors.contains_key("agent:clash-policy"));

        // Verify source.
        assert_eq!(
            path.meta.as_ref().unwrap().source.as_deref(),
            Some("startup")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sync_picks_up_new_entries() {
        let session_id = format!("trace-sync-{}", std::process::id());
        let dir = session_dir(&session_id);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let transcript = dir.join("conversation.jsonl");
        write_jsonl(
            &transcript,
            &[
                make_user_entry("u1", "Hello"),
                make_assistant_entry("a1", "Hi there!"),
            ],
        );

        init_trace(
            &session_id,
            transcript.to_str().unwrap(),
            "/tmp",
            None,
            None,
        )
        .unwrap();
        sync_trace(&session_id, None).unwrap();

        let doc = export_trace(&session_id).unwrap();
        let v1::Document::Path(path) = doc else {
            panic!("expected Path");
        };

        assert_eq!(path.steps.len(), 2);

        // Verify first step is user.
        let s0 = &path.steps[0];
        assert_eq!(s0.step.actor, "human:user");
        let text = s0.meta.as_ref().unwrap().extra.get("text").unwrap();
        assert_eq!(text, "Hello");

        // Verify second step is assistant.
        let s1 = &path.steps[1];
        assert!(s1.step.actor.starts_with("agent:"));
        let text = s1.meta.as_ref().unwrap().extra.get("text").unwrap();
        assert_eq!(text, "Hi there!");

        // Verify parent chain.
        assert!(s0.step.parents.is_empty());
        assert_eq!(s1.step.parents, vec![s0.step.id.clone()]);

        // Verify steps were read from trace.jsonl (not stored in trace.json).
        let state_data = std::fs::read_to_string(trace_path(&session_id)).unwrap();
        let state_doc: serde_json::Value = serde_json::from_str(&state_data).unwrap();
        let steps_in_state = state_doc["Path"]["steps"].as_array().unwrap();
        assert!(
            steps_in_state.is_empty(),
            "trace.json should not contain steps"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sync_incremental() {
        let session_id = format!("trace-incr-{}", std::process::id());
        let dir = session_dir(&session_id);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let transcript = dir.join("conversation.jsonl");
        write_jsonl(&transcript, &[make_user_entry("u1", "First")]);

        init_trace(
            &session_id,
            transcript.to_str().unwrap(),
            "/tmp",
            None,
            None,
        )
        .unwrap();
        sync_trace(&session_id, None).unwrap();

        // First sync: 1 step.
        let doc = export_trace(&session_id).unwrap();
        let v1::Document::Path(path) = doc else {
            panic!("expected Path");
        };
        assert_eq!(path.steps.len(), 1);

        // Append more entries to conversation JSONL.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&transcript)
            .unwrap();
        writeln!(
            f,
            "{}",
            serde_json::to_string(&make_assistant_entry("a1", "Second")).unwrap()
        )
        .unwrap();

        sync_trace(&session_id, None).unwrap();

        // Second sync: 2 steps total (not 3).
        let doc = export_trace(&session_id).unwrap();
        let v1::Document::Path(path) = doc else {
            panic!("expected Path");
        };
        assert_eq!(path.steps.len(), 2);
        // New step should chain from previous.
        assert_eq!(path.steps[1].step.parents, vec!["step-1".to_string()]);

        // Verify trace.jsonl has exactly 2 lines.
        let jsonl = std::fs::read_to_string(trace_jsonl_path(&session_id)).unwrap();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2, "trace.jsonl should have 2 step lines");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_policy_decision_creates_step() {
        let session_id = format!("trace-dec-{}", std::process::id());
        let dir = session_dir(&session_id);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let transcript = dir.join("conversation.jsonl");
        write_jsonl(&transcript, &[make_tool_use_entry("a1", "tu-123", "Bash")]);

        init_trace(
            &session_id,
            transcript.to_str().unwrap(),
            "/tmp",
            None,
            None,
        )
        .unwrap();
        sync_trace(
            &session_id,
            Some(PolicyDecision {
                tool_use_id: "tu-123".into(),
                tool_name: Some("Bash".into()),
                effect: "allow".into(),
                reason: Some("matched rule: (allow (exec *))".into()),
            }),
        )
        .unwrap();

        let doc = export_trace(&session_id).unwrap();
        let v1::Document::Path(path) = doc else {
            panic!("expected Path");
        };

        // Tool-use step + policy-evaluation step.
        assert_eq!(path.steps.len(), 2);

        // First step is the tool use from the conversation.
        let tool_step = &path.steps[0];
        assert!(tool_step.step.actor.starts_with("agent:"));

        // Second step is the policy evaluation.
        let policy_step = &path.steps[1];
        assert_eq!(policy_step.step.actor, "agent:clash-policy");
        // Policy step parents the tool-use step.
        assert_eq!(policy_step.step.parents, vec![tool_step.step.id.clone()]);

        // Verify the change field contains the evaluation.
        let change = policy_step
            .change
            .get("clash://policy/evaluations")
            .expect("should have policy evaluation artifact");
        assert!(change.raw.is_none());
        let structural = change.structural.as_ref().expect("should have structural");
        assert_eq!(structural.change_type, "policy_evaluation");
        assert_eq!(structural.extra["tool_use_id"], "tu-123");
        assert_eq!(structural.extra["tool_name"], "Bash");
        assert_eq!(structural.extra["effect"], "allow");
        assert_eq!(structural.extra["reason"], "matched rule: (allow (exec *))");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_policy_step_without_tool_name() {
        let session_id = format!("trace-dec-noname-{}", std::process::id());
        let dir = session_dir(&session_id);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let transcript = dir.join("conversation.jsonl");
        write_jsonl(&transcript, &[make_tool_use_entry("a1", "tu-789", "Read")]);

        init_trace(
            &session_id,
            transcript.to_str().unwrap(),
            "/tmp",
            None,
            None,
        )
        .unwrap();
        sync_trace(
            &session_id,
            Some(PolicyDecision {
                tool_use_id: "tu-789".into(),
                tool_name: None,
                effect: "deny".into(),
                reason: None,
            }),
        )
        .unwrap();

        let doc = export_trace(&session_id).unwrap();
        let v1::Document::Path(path) = doc else {
            panic!("expected Path");
        };

        assert_eq!(path.steps.len(), 2);
        let policy_step = &path.steps[1];
        let structural = policy_step
            .change
            .get("clash://policy/evaluations")
            .unwrap()
            .structural
            .as_ref()
            .unwrap();
        assert_eq!(structural.extra["effect"], "deny");
        // tool_name and reason should be absent when not provided.
        assert!(!structural.extra.contains_key("tool_name"));
        assert!(!structural.extra.contains_key("reason"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tool_use_step_has_tool_metadata() {
        let session_id = format!("trace-tool-{}", std::process::id());
        let dir = session_dir(&session_id);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let transcript = dir.join("conversation.jsonl");
        write_jsonl(&transcript, &[make_tool_use_entry("a1", "tu-456", "Read")]);

        init_trace(
            &session_id,
            transcript.to_str().unwrap(),
            "/tmp",
            None,
            None,
        )
        .unwrap();
        sync_trace(&session_id, None).unwrap();

        let doc = export_trace(&session_id).unwrap();
        let v1::Document::Path(path) = doc else {
            panic!("expected Path");
        };

        let step = &path.steps[0];
        let tool_uses = step.meta.as_ref().unwrap().extra.get("tool_uses").unwrap();
        let tools = tool_uses.as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["tool_name"], "Read");
        assert_eq!(tools[0]["tool_use_id"], "tu-456");
        assert!(tools[0]["tool_input"].is_object());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_export_returns_clean_document() {
        let session_id = format!("trace-export-{}", std::process::id());
        let dir = session_dir(&session_id);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let transcript = dir.join("conversation.jsonl");
        write_jsonl(&transcript, &[make_user_entry("u1", "test")]);

        init_trace(
            &session_id,
            transcript.to_str().unwrap(),
            "/tmp",
            None,
            None,
        )
        .unwrap();
        sync_trace(&session_id, None).unwrap();

        let doc = export_trace(&session_id).unwrap();

        // Verify it round-trips through JSON.
        let json = doc.to_json().unwrap();
        let reparsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(reparsed.is_object(), "should serialize to a JSON object");

        // Verify the internal "trace" bookkeeping is NOT present anywhere in
        // the serialized output.
        let json_str = serde_json::to_string(&reparsed).unwrap();
        assert!(
            !json_str.contains("\"trace\":{\"version\""),
            "internal trace state should not leak into export: {json_str}"
        );

        // Verify steps were assembled from trace.jsonl.
        let v1::Document::Path(ref path) = doc else {
            panic!("expected Path");
        };
        assert_eq!(path.steps.len(), 1, "should have 1 step from trace.jsonl");

        // Verify it deserializes back to a valid Document.
        let round_tripped = v1::Document::from_json(&json).unwrap();
        assert!(matches!(round_tripped, v1::Document::Path(_)));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
