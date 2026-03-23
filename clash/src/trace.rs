//! Toolpath-based session tracing.
//!
//! Tracks a Claude Code session as a toolpath document by tailing the conversation JSONL that
//! Claude Code writes. On each hook invocation, `sync_trace` reads new conversation entries
//! (via `ConversationReader::read_from_offset`), derives proper toolpath Steps from them
//! (via `toolpath_claude::derive::derive_path`), and appends those Steps to `trace.jsonl`.
//! Policy decisions are also written as real Steps, interleaved in order.
//!
//! `export_trace` simply reads all Steps from `trace.jsonl` and wraps them in a Path document.
//! No re-deriving — the jsonl is the source of truth.
//!
//! Session directory layout:
//! - `trace.json`  — session metadata + byte offset + last step ID
//! - `trace.jsonl` — append-only toolpath Steps (conversation + policy)

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;
use toolpath::v1;
use toolpath_claude::ConversationReader;
use toolpath_claude::derive::{DeriveConfig, derive_path};
use toolpath_claude::types::ContentPart;

/// A policy decision to record as a trace Step.
pub struct PolicyDecision {
    pub tool_use_id: String,
    pub tool_name: Option<String>,
    pub effect: crate::policy::Effect,
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Session-dir file helpers
// ---------------------------------------------------------------------------

fn session_dir(session_id: &str) -> PathBuf {
    crate::session_dir::SessionDir::new(session_id)
        .root()
        .to_path_buf()
}

fn trace_meta_path(session_id: &str) -> PathBuf {
    crate::session_dir::SessionDir::new(session_id).trace_meta()
}

fn steps_path(session_id: &str) -> PathBuf {
    crate::session_dir::SessionDir::new(session_id).trace_steps()
}

// ---------------------------------------------------------------------------
// Persistent metadata + incremental state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TraceMeta {
    session_id: String,
    transcript_path: String,
    cwd: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    /// Git commit hash at session start, for anchoring `path.base.ref`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    git_ref: Option<String>,
    /// Actors accumulated from derive_path output across syncs.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    actors: HashMap<String, v1::ActorDefinition>,
    state: TraceState,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TraceState {
    /// Byte offset into the conversation JSONL for incremental reads.
    convo_byte_offset: u64,
    /// ID of the last step written, for parent chaining across syncs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_step_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialize tracing for a new session.
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

    let meta = TraceMeta {
        session_id: session_id.to_string(),
        transcript_path: transcript_path.to_string(),
        cwd: cwd.to_string(),
        model: model.map(|s| s.to_string()),
        source: source.map(|s| s.to_string()),
        git_ref: git_head_ref(Path::new(cwd)),
        actors: HashMap::new(),
        state: TraceState {
            convo_byte_offset: 0,
            last_step_id: None,
        },
    };

    std::fs::write(steps_path(session_id), "").context("creating trace.jsonl")?;
    save_meta(session_id, &meta)?;
    Ok(())
}

/// Read new conversation entries, derive toolpath Steps, and append them to the trace.
/// Optionally record a policy decision as an additional Step.
pub fn sync_trace(session_id: &str, decision: Option<PolicyDecision>) -> anyhow::Result<()> {
    let mut meta = load_meta(session_id)?;

    let (entries, new_offset) =
        ConversationReader::read_from_offset(&meta.transcript_path, meta.state.convo_byte_offset)
            .context("reading conversation JSONL")?;

    meta.state.convo_byte_offset = new_offset;

    // Map tool_use_id → derived step_id for parenting policy decisions.
    let mut tool_use_step_map = HashMap::new();
    // For denied tool uses: the parent of the tool_use step, so we can rewind
    // last_step_id to make the tool_use itself part of the dead end.
    let mut denied_tool_use_parent: Option<String> = None;

    if !entries.is_empty() {
        // Build a temporary conversation from the new entries and derive Steps.
        let mut conversation = toolpath_claude::Conversation::new(meta.session_id.clone());
        for entry in entries {
            conversation.add_entry(entry);
        }

        // Collect tool_use_id → step_id mapping.
        //
        // derive_path generates step IDs as `step-{uuid_prefix}` from entry UUIDs.
        // This is stable public behavior of toolpath_claude — if the scheme ever
        // changes it would be a breaking change to the crate.
        let tool_use_step_ids: std::collections::HashSet<String> = conversation
            .tool_uses()
            .into_iter()
            .filter_map(|(entry, part)| {
                if let ContentPart::ToolUse { id, .. } = part {
                    let prefix: String = entry.uuid.chars().take(8).collect();
                    let step_id = format!("step-{prefix}");
                    tool_use_step_map.insert(id.clone(), step_id.clone());
                    Some(step_id)
                } else {
                    None
                }
            })
            .collect();

        let config = DeriveConfig {
            project_path: Some(meta.cwd.clone()),
            ..Default::default()
        };
        let derived = derive_path(&conversation, &config);

        // Merge actors from derive output.
        if let Some(ref path_meta) = derived.meta
            && let Some(ref actors) = path_meta.actors
        {
            meta.actors.extend(actors.clone());
        }

        // Append derived steps, chaining the first to the previous sync's last step.
        for (i, mut step) in derived.steps.into_iter().enumerate() {
            if i == 0
                && let Some(ref last_id) = meta.state.last_step_id
                && step.step.parents.is_empty()
            {
                step.step.parents.push(last_id.clone());
            }
            if tool_use_step_ids.contains(&step.step.id) {
                denied_tool_use_parent = meta.state.last_step_id.clone();
            }
            meta.state.last_step_id = Some(step.step.id.clone());
            append_step(session_id, &step)?;
        }
    }

    // Record policy decision as a real Step.
    if let Some(dec) = decision {
        let parent_id = tool_use_step_map
            .get(&dec.tool_use_id)
            .or(meta.state.last_step_id.as_ref())
            .cloned();

        let step_id = format!("clash-{}", dec.tool_use_id);
        let timestamp = now_iso8601();

        let tool_label = dec.tool_name.as_deref().unwrap_or("tool");
        let intent = format!("{} {} use", dec.effect, tool_label);

        let mut step =
            v1::Step::new(&step_id, "agent:clash-policy", &timestamp).with_intent(&intent);
        if let Some(ref pid) = parent_id {
            step = step.with_parent(pid);
        }

        let mut extra = HashMap::new();
        extra.insert(
            "tool_use_id".to_string(),
            serde_json::json!(dec.tool_use_id),
        );
        if let Some(ref name) = dec.tool_name {
            extra.insert("tool_name".to_string(), serde_json::json!(name));
        }
        extra.insert(
            "effect".to_string(),
            serde_json::json!(dec.effect.to_string()),
        );
        if let Some(ref reason) = dec.reason {
            extra.insert("reason".to_string(), serde_json::json!(reason));
        }

        step.change.insert(
            "clash://policy/evaluations".to_string(),
            v1::ArtifactChange {
                raw: None,
                structural: Some(v1::StructuralChange {
                    change_type: "policy_evaluation".to_string(),
                    extra,
                }),
            },
        );

        if dec.effect == crate::policy::Effect::Deny {
            // Denials are dead ends: rewind last_step_id to the tool_use step's
            // parent so both the tool_use and denial sit on a dead-end branch.
            meta.state.last_step_id = denied_tool_use_parent.clone();
        } else {
            meta.state.last_step_id = Some(step.step.id.clone());
        }
        append_step(session_id, &step)?;
    }

    save_meta(session_id, &meta)?;
    Ok(())
}

/// Export the trace as a toolpath Document.
///
/// Reads all Steps from `trace.jsonl` and wraps them in a Path.
pub fn export_trace(session_id: &str) -> anyhow::Result<v1::Document> {
    let meta = load_meta(session_id)?;
    let steps = load_steps(session_id)?;

    let head = steps
        .last()
        .map(|s| s.step.id.clone())
        .unwrap_or_else(|| "empty".to_string());

    let mut actors = meta.actors.clone();
    actors.insert(
        "agent:clash-policy".to_string(),
        v1::ActorDefinition {
            name: Some("Clash Policy Engine".to_string()),
            provider: Some("empathic".to_string()),
            identities: vec![v1::Identity {
                system: "crates.io".to_string(),
                id: format!("clash/{}", crate::version::version_long()),
            }],
            ..Default::default()
        },
    );

    let path = v1::Path {
        path: v1::PathIdentity {
            id: meta.session_id.clone(),
            base: Some(v1::Base {
                uri: format!("file://{}", meta.cwd),
                ref_str: meta.git_ref.clone(),
            }),
            head,
        },
        steps,
        meta: Some(v1::PathMeta {
            title: Some(format!("Clash session: {}", meta.session_id)),
            source: meta.source.clone(),
            actors: if actors.is_empty() {
                None
            } else {
                Some(actors)
            },
            ..Default::default()
        }),
    };

    Ok(v1::Document::Path(path))
}

/// Extract the most recent user message from a session's trace.jsonl.
///
/// Returns the first line of the message, truncated to 120 chars.
pub fn last_user_message(session_id: &str) -> Option<String> {
    use std::io::BufRead;

    let trace_path = steps_path(session_id);
    let file = std::fs::File::open(&trace_path).ok()?;
    let reader = std::io::BufReader::new(file);

    let mut last_line = None;
    for line in reader.lines() {
        let line = line.ok()?;
        if line.contains("\"human:user\"") {
            last_line = Some(line);
        }
    }

    let entry: serde_json::Value = serde_json::from_str(&last_line?).ok()?;
    let changes = entry.get("change")?.as_object()?;
    for val in changes.values() {
        if let Some(text) = val.pointer("/structural/text").and_then(|v| v.as_str()) {
            let first_line = text.lines().next().unwrap_or(text);
            let max_len = 120;
            return Some(if first_line.len() > max_len {
                let truncated = &first_line[..first_line.floor_char_boundary(max_len)];
                format!("{truncated}...")
            } else {
                first_line.to_string()
            });
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn load_meta(session_id: &str) -> anyhow::Result<TraceMeta> {
    let data =
        std::fs::read_to_string(trace_meta_path(session_id)).context("reading trace.json")?;
    serde_json::from_str(&data).context("parsing trace.json")
}

fn save_meta(session_id: &str, meta: &TraceMeta) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(meta).context("serializing trace metadata")?;
    let out = trace_meta_path(session_id);
    let dir = out
        .parent()
        .context("trace meta path has no parent directory")?;
    let tmp = dir.join(".trace.json.tmp");
    std::fs::write(&tmp, &json).context("writing trace meta tmp file")?;
    std::fs::rename(&tmp, &out).context("renaming trace tmp to trace.json")?;
    Ok(())
}

fn append_step(session_id: &str, step: &v1::Step) -> anyhow::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(steps_path(session_id))
        .context("opening trace.jsonl for append")?;
    let line = serde_json::to_string(step).context("serializing step")?;
    writeln!(f, "{line}").context("appending step to trace.jsonl")?;
    Ok(())
}

fn load_steps(session_id: &str) -> anyhow::Result<Vec<v1::Step>> {
    let data = std::fs::read_to_string(steps_path(session_id)).context("reading trace.jsonl")?;
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
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Resolve the current git HEAD commit hash in `cwd`, if available.
fn git_head_ref(cwd: &Path) -> Option<String> {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
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

    fn convo_artifact(session_id: &str) -> String {
        format!("claude://{session_id}")
    }

    #[test]
    fn test_init_trace_creates_files() {
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

        assert!(trace_meta_path(&session_id).exists());
        assert!(steps_path(&session_id).exists());

        let meta = load_meta(&session_id).unwrap();
        assert_eq!(meta.session_id, session_id);
        assert_eq!(meta.cwd, "/tmp/project");
        assert_eq!(meta.model.as_deref(), Some("claude-sonnet-4-20250514"));
        assert_eq!(meta.source.as_deref(), Some("startup"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sync_writes_real_steps() {
        let session_id = format!("trace-sync-{}", std::process::id());
        let dir = session_dir(&session_id);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let transcript = dir.join("conversation.jsonl");
        write_jsonl(
            &transcript,
            &[
                make_user_entry("u1aaaaaa", "Hello"),
                make_assistant_entry("a1bbbbbb", "Hi there!"),
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

        // trace.jsonl should contain real v1::Step objects.
        let steps = load_steps(&session_id).unwrap();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].step.actor, "human:user");
        assert!(steps[1].step.actor.starts_with("agent:"));

        // Conversation data should be in step.change.
        let artifact_key = convo_artifact(&session_id);
        let structural = steps[0].change[&artifact_key].structural.as_ref().unwrap();
        assert_eq!(structural.change_type, "conversation.append");
        assert_eq!(structural.extra["role"], "user");
        assert_eq!(structural.extra["text"], "Hello");

        // No meta on conversation steps.
        assert!(steps[0].meta.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_export_reads_steps_from_jsonl() {
        let session_id = format!("trace-export-{}", std::process::id());
        let dir = session_dir(&session_id);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let transcript = dir.join("conversation.jsonl");
        write_jsonl(
            &transcript,
            &[
                make_user_entry("u1aaaaaa", "Hello"),
                make_assistant_entry("a1bbbbbb", "Hi there!"),
            ],
        );

        init_trace(
            &session_id,
            transcript.to_str().unwrap(),
            "/tmp",
            None,
            Some("startup"),
        )
        .unwrap();
        sync_trace(&session_id, None).unwrap();

        let doc = export_trace(&session_id).unwrap();
        let v1::Document::Path(ref path) = doc else {
            panic!("expected Path");
        };

        assert_eq!(path.path.id, session_id);
        assert_eq!(path.steps.len(), 2);
        assert_eq!(path.path.base.as_ref().unwrap().uri, "file:///tmp");
        assert_eq!(
            path.meta.as_ref().unwrap().source.as_deref(),
            Some("startup")
        );

        // Round-trips through JSON.
        let json = doc.to_json().unwrap();
        let round_tripped = v1::Document::from_json(&json).unwrap();
        assert!(matches!(round_tripped, v1::Document::Path(_)));

        // No internal state leaks.
        assert!(!json.contains("convo_byte_offset"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sync_incremental() {
        let session_id = format!("trace-incr-{}", std::process::id());
        let dir = session_dir(&session_id);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let transcript = dir.join("conversation.jsonl");
        write_jsonl(&transcript, &[make_user_entry("u1aaaaaa", "First")]);

        init_trace(
            &session_id,
            transcript.to_str().unwrap(),
            "/tmp",
            None,
            None,
        )
        .unwrap();
        sync_trace(&session_id, None).unwrap();

        assert_eq!(load_steps(&session_id).unwrap().len(), 1);

        // Append more entries and sync again.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&transcript)
            .unwrap();
        writeln!(
            f,
            "{}",
            serde_json::to_string(&make_assistant_entry("a1bbbbbb", "Second")).unwrap()
        )
        .unwrap();

        sync_trace(&session_id, None).unwrap();

        let steps = load_steps(&session_id).unwrap();
        assert_eq!(steps.len(), 2);

        // Second sync's first step should parent to the first sync's last step.
        assert_eq!(steps[1].step.parents, vec![steps[0].step.id.clone()]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_policy_decision_interleaved() {
        let session_id = format!("trace-dec-{}", std::process::id());
        let dir = session_dir(&session_id);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let transcript = dir.join("conversation.jsonl");
        write_jsonl(
            &transcript,
            &[make_tool_use_entry("a1bbbbbb", "tu-123", "Bash")],
        );

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
                effect: crate::policy::Effect::Allow,
                reason: Some("matched rule: exe(\"*\").allow()".into()),
            }),
        )
        .unwrap();

        let steps = load_steps(&session_id).unwrap();
        // Conversation step + policy step, interleaved.
        assert_eq!(steps.len(), 2);

        let convo_step = &steps[0];
        assert!(convo_step.step.actor.starts_with("agent:"));

        let policy_step = &steps[1];
        assert_eq!(policy_step.step.actor, "agent:clash-policy");
        assert_eq!(policy_step.step.parents, vec![convo_step.step.id.clone()]);

        let change = policy_step
            .change
            .get("clash://policy/evaluations")
            .expect("should have policy evaluation");
        let structural = change.structural.as_ref().unwrap();
        assert_eq!(structural.change_type, "policy_evaluation");
        assert_eq!(structural.extra["tool_use_id"], "tu-123");
        assert_eq!(structural.extra["tool_name"], "Bash");
        assert_eq!(structural.extra["effect"], "allow");

        // Policy steps should have intent metadata.
        let intent = policy_step.meta.as_ref().unwrap().intent.as_ref().unwrap();
        assert_eq!(intent, "allow Bash use");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_policy_step_without_tool_name() {
        let session_id = format!("trace-noname-{}", std::process::id());
        let dir = session_dir(&session_id);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let transcript = dir.join("conversation.jsonl");
        write_jsonl(
            &transcript,
            &[make_tool_use_entry("a1bbbbbb", "tu-789", "Read")],
        );

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
                effect: crate::policy::Effect::Deny,
                reason: None,
            }),
        )
        .unwrap();

        let steps = load_steps(&session_id).unwrap();
        assert_eq!(steps.len(), 2);
        let structural = steps[1]
            .change
            .get("clash://policy/evaluations")
            .unwrap()
            .structural
            .as_ref()
            .unwrap();
        assert_eq!(structural.extra["effect"], "deny");
        assert!(!structural.extra.contains_key("tool_name"));
        assert!(!structural.extra.contains_key("reason"));

        // Intent falls back to "tool" when tool_name is None.
        let intent = steps[1].meta.as_ref().unwrap().intent.as_ref().unwrap();
        assert_eq!(intent, "deny tool use");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tool_use_in_change_not_meta() {
        let session_id = format!("trace-tool-{}", std::process::id());
        let dir = session_dir(&session_id);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let transcript = dir.join("conversation.jsonl");
        write_jsonl(
            &transcript,
            &[make_tool_use_entry("a1bbbbbb", "tu-456", "Read")],
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

        let steps = load_steps(&session_id).unwrap();
        let step = &steps[0];

        let artifact_key = convo_artifact(&session_id);
        let structural = step.change[&artifact_key].structural.as_ref().unwrap();
        assert_eq!(structural.change_type, "conversation.append");
        let tools = structural.extra["tool_uses"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0], "Read");

        assert!(step.meta.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Denied tool uses are dead ends in the path DAG:
    ///
    ///   user_msg → tool_use → deny (dead end branch)
    ///            → next_step (continues from user_msg)
    ///
    /// Both the tool_use and the denial sit on the dead-end branch.
    #[test]
    fn test_denial_is_dead_end() {
        let session_id = format!("trace-deadend-{}", std::process::id());
        let dir = session_dir(&session_id);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let transcript = dir.join("conversation.jsonl");

        // Turn 1: user message, then assistant tries a tool use.
        write_jsonl(
            &transcript,
            &[
                make_user_entry("u1aaaaaa", "do something"),
                make_tool_use_entry("a1bbbbbb", "tu-denied", "Bash"),
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

        // Policy denies the tool use.
        sync_trace(
            &session_id,
            Some(PolicyDecision {
                tool_use_id: "tu-denied".into(),
                tool_name: Some("Bash".into()),
                effect: crate::policy::Effect::Deny,
                reason: Some("not allowed".into()),
            }),
        )
        .unwrap();

        // Turn 2: assistant responds with text (continues after denial).
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&transcript)
                .unwrap();
            writeln!(
                f,
                "{}",
                serde_json::to_string(&make_assistant_entry("a2cccccc", "OK, I won't do that."))
                    .unwrap()
            )
            .unwrap();
        }
        sync_trace(&session_id, None).unwrap();

        let steps = load_steps(&session_id).unwrap();
        // 4 steps: user_msg, tool_use, denial, assistant response
        assert_eq!(steps.len(), 4);

        let user_step = &steps[0];
        let tool_use_step = &steps[1];
        let denial_step = &steps[2];
        let continue_step = &steps[3];

        // tool_use parents to user_step.
        assert_eq!(tool_use_step.step.parents, vec![user_step.step.id.clone()]);
        // Denial parents to the tool_use step.
        assert_eq!(
            denial_step.step.parents,
            vec![tool_use_step.step.id.clone()]
        );
        // The continuation parents to the user_step (not tool_use or denial).
        // Both tool_use and denial are on a dead-end branch.
        assert_eq!(
            continue_step.step.parents,
            vec![user_step.step.id.clone()],
            "continuation should branch from user_step, not from denied tool_use"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn make_tool_result_entry(uuid: &str, tool_use_id: &str, output: &str) -> serde_json::Value {
        serde_json::json!({
            "uuid": uuid,
            "type": "human",
            "timestamp": "2025-01-15T10:03:00Z",
            "message": {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": output
                    }
                ]
            }
        })
    }

    /// Simulates a realistic multi-turn session:
    ///   1. User sends a message
    ///   2. Assistant calls a tool (Bash)
    ///   3. Policy evaluates the tool use (allow)
    ///   4. Tool result comes back
    ///   5. Assistant calls another tool (Read)
    ///   6. Policy evaluates (allow)
    ///   7. Tool result comes back
    ///   8. Assistant responds with text
    ///
    /// Each sync is incremental (new entries appended between syncs),
    /// mimicking how hooks actually fire. Then asserts the full exported
    /// trace has correct step ordering, parent chains, and structure.
    #[test]
    fn test_realistic_multi_turn_trace() {
        let session_id = format!("trace-realistic-{}", std::process::id());
        let dir = session_dir(&session_id);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let transcript = dir.join("conversation.jsonl");
        let artifact_key = convo_artifact(&session_id);

        // --- Turn 1: user sends a message ---
        write_jsonl(
            &transcript,
            &[make_user_entry("u1aaaaaa", "List files and read README")],
        );
        init_trace(
            &session_id,
            transcript.to_str().unwrap(),
            "/tmp/project",
            Some("claude-sonnet-4-20250514"),
            Some("startup"),
        )
        .unwrap();
        sync_trace(&session_id, None).unwrap();

        // --- Turn 2: assistant calls Bash tool ---
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&transcript)
                .unwrap();
            writeln!(
                f,
                "{}",
                serde_json::to_string(&make_tool_use_entry("a1bbbbbb", "tu-bash-1", "Bash"))
                    .unwrap()
            )
            .unwrap();
        }
        // Policy evaluates the tool use.
        sync_trace(
            &session_id,
            Some(PolicyDecision {
                tool_use_id: "tu-bash-1".into(),
                tool_name: Some("Bash".into()),
                effect: crate::policy::Effect::Allow,
                reason: Some("matched rule: exe(\"*\").allow()".into()),
            }),
        )
        .unwrap();

        // --- Turn 3: tool result comes back ---
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&transcript)
                .unwrap();
            writeln!(
                f,
                "{}",
                serde_json::to_string(&make_tool_result_entry(
                    "u2cccccc",
                    "tu-bash-1",
                    "README.md\nsrc/"
                ))
                .unwrap()
            )
            .unwrap();
        }
        sync_trace(&session_id, None).unwrap();

        // --- Turn 4: assistant calls Read tool ---
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&transcript)
                .unwrap();
            writeln!(
                f,
                "{}",
                serde_json::to_string(&make_tool_use_entry("a2dddddd", "tu-read-1", "Read"))
                    .unwrap()
            )
            .unwrap();
        }
        sync_trace(
            &session_id,
            Some(PolicyDecision {
                tool_use_id: "tu-read-1".into(),
                tool_name: Some("Read".into()),
                effect: crate::policy::Effect::Allow,
                reason: None,
            }),
        )
        .unwrap();

        // --- Turn 5: tool result, then assistant final response ---
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&transcript)
                .unwrap();
            writeln!(
                f,
                "{}",
                serde_json::to_string(&make_tool_result_entry(
                    "u3eeeeee",
                    "tu-read-1",
                    "# My Project\nA cool project."
                ))
                .unwrap()
            )
            .unwrap();
            writeln!(
                f,
                "{}",
                serde_json::to_string(&make_assistant_entry(
                    "a3ffffff",
                    "Here are your files and the README content."
                ))
                .unwrap()
            )
            .unwrap();
        }
        sync_trace(&session_id, None).unwrap();

        // === Now export and verify the full trace ===
        let doc = export_trace(&session_id).unwrap();
        let v1::Document::Path(ref path) = doc else {
            panic!("expected Path document");
        };

        // 4 conversation steps + 2 policy steps = 6 total.
        // (tool_result entries don't produce derive steps — they're plumbing.)
        assert_eq!(
            path.steps.len(),
            6,
            "expected 6 steps (4 convo + 2 policy), got {}:\n{}",
            path.steps.len(),
            path.steps
                .iter()
                .map(|s| format!("  {} ({})", s.step.id, s.step.actor))
                .collect::<Vec<_>>()
                .join("\n")
        );

        // Step 0: user message
        assert_eq!(path.steps[0].step.actor, "human:user");
        let s0 = &path.steps[0].change[&artifact_key]
            .structural
            .as_ref()
            .unwrap();
        assert_eq!(s0.change_type, "conversation.append");
        assert_eq!(s0.extra["text"], "List files and read README");

        // Step 1: assistant tool_use (Bash)
        assert!(path.steps[1].step.actor.starts_with("agent:"));
        let s1 = &path.steps[1].change[&artifact_key]
            .structural
            .as_ref()
            .unwrap();
        assert_eq!(s1.extra["tool_uses"][0], "Bash");

        // Step 2: policy evaluation for Bash — interleaved right after the tool use
        assert_eq!(path.steps[2].step.actor, "agent:clash-policy");
        let policy1 = path.steps[2]
            .change
            .get("clash://policy/evaluations")
            .unwrap()
            .structural
            .as_ref()
            .unwrap();
        assert_eq!(policy1.extra["tool_use_id"], "tu-bash-1");
        assert_eq!(policy1.extra["tool_name"], "Bash");
        assert_eq!(policy1.extra["effect"], "allow");

        // Step 3: assistant tool_use (Read)
        assert!(path.steps[3].step.actor.starts_with("agent:"));
        let s3 = &path.steps[3].change[&artifact_key]
            .structural
            .as_ref()
            .unwrap();
        assert_eq!(s3.extra["tool_uses"][0], "Read");

        // Step 4: policy evaluation for Read
        assert_eq!(path.steps[4].step.actor, "agent:clash-policy");
        let policy2 = path.steps[4]
            .change
            .get("clash://policy/evaluations")
            .unwrap()
            .structural
            .as_ref()
            .unwrap();
        assert_eq!(policy2.extra["tool_use_id"], "tu-read-1");
        assert_eq!(policy2.extra["tool_name"], "Read");
        assert_eq!(policy2.extra["effect"], "allow");

        // Step 5: final assistant response
        assert!(path.steps[5].step.actor.starts_with("agent:"));
        let s5 = &path.steps[5].change[&artifact_key]
            .structural
            .as_ref()
            .unwrap();
        assert_eq!(
            s5.extra["text"],
            "Here are your files and the README content."
        );

        // Verify parent chains.
        // Step 0: no parent (first step of first sync).
        assert!(path.steps[0].step.parents.is_empty());
        // Step 1: parents to step 0 (within same derive batch).
        assert_eq!(
            path.steps[1].step.parents,
            vec![path.steps[0].step.id.clone()]
        );
        // Step 2 (policy): parents to step 1 (the tool_use it evaluated).
        assert_eq!(
            path.steps[2].step.parents,
            vec![path.steps[1].step.id.clone()]
        );
        // Step 3: from a later sync, chains to the previous sync's last step (policy step 2).
        assert_eq!(
            path.steps[3].step.parents,
            vec![path.steps[2].step.id.clone()]
        );
        // Step 4 (policy): parents to step 3 (the tool_use it evaluated).
        assert_eq!(
            path.steps[4].step.parents,
            vec![path.steps[3].step.id.clone()]
        );

        // Verify round-trip through JSON.
        let json = doc.to_json().unwrap();
        assert!(
            !json.contains("convo_byte_offset"),
            "no internal state leaked"
        );
        let rt = v1::Document::from_json(&json).unwrap();
        assert!(matches!(rt, v1::Document::Path(_)));

        // All step IDs must be unique.
        let mut ids = std::collections::HashSet::new();
        for step in &path.steps {
            assert!(
                ids.insert(&step.step.id),
                "duplicate step ID: {}",
                step.step.id
            );
        }

        // Path head points to the last step.
        assert_eq!(path.path.head, path.steps[5].step.id);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_export_has_source_and_base() {
        let session_id = format!("trace-meta-{}", std::process::id());
        let dir = session_dir(&session_id);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let transcript = dir.join("conversation.jsonl");
        write_jsonl(&transcript, &[make_user_entry("u1aaaaaa", "Hello")]);

        init_trace(
            &session_id,
            transcript.to_str().unwrap(),
            "/tmp/project",
            Some("claude-sonnet-4-20250514"),
            Some("startup"),
        )
        .unwrap();
        sync_trace(&session_id, None).unwrap();

        let doc = export_trace(&session_id).unwrap();
        let v1::Document::Path(path) = doc else {
            panic!("expected Path");
        };

        assert_eq!(path.path.base.as_ref().unwrap().uri, "file:///tmp/project");
        assert_eq!(
            path.meta.as_ref().unwrap().source.as_deref(),
            Some("startup")
        );

        // Exported path should have a title.
        assert_eq!(
            path.meta.as_ref().unwrap().title.as_deref(),
            Some(&format!("Clash session: {session_id}") as &str)
        );

        // Actors should include both conversation actors and clash-policy.
        let actors = path.meta.as_ref().unwrap().actors.as_ref().unwrap();
        assert!(actors.contains_key("human:user"));
        assert!(actors.contains_key("agent:clash-policy"));

        // clash-policy actor should have rich identity.
        let clash_actor = &actors["agent:clash-policy"];
        assert_eq!(clash_actor.name.as_deref(), Some("Clash Policy Engine"));
        assert_eq!(clash_actor.provider.as_deref(), Some("empathic"));
        assert!(!clash_actor.identities.is_empty());
        assert_eq!(clash_actor.identities[0].system, "crates.io");
        assert!(clash_actor.identities[0].id.starts_with("clash/"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_last_user_message() {
        let sid = format!("trace-lastmsg-{}", std::process::id());
        let dir = session_dir(&sid);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let transcript = dir.join("conversation.jsonl");
        write_jsonl(
            &transcript,
            &[
                make_user_entry("u1aaaaaa", "first message"),
                make_assistant_entry("a1bbbbbb", "response"),
                make_user_entry("u2cccccc", "second message"),
            ],
        );

        init_trace(&sid, transcript.to_str().unwrap(), "/tmp", None, None).unwrap();
        sync_trace(&sid, None).unwrap();

        assert_eq!(last_user_message(&sid).as_deref(), Some("second message"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_last_user_message_truncates() {
        let sid = format!("trace-lastmsg-trunc-{}", std::process::id());
        let dir = session_dir(&sid);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let long_msg = "a".repeat(200);
        let transcript = dir.join("conversation.jsonl");
        write_jsonl(&transcript, &[make_user_entry("u1aaaaaa", &long_msg)]);

        init_trace(&sid, transcript.to_str().unwrap(), "/tmp", None, None).unwrap();
        sync_trace(&sid, None).unwrap();

        let result = last_user_message(&sid).unwrap();
        assert!(result.len() <= 124);
        assert!(result.ends_with("..."));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_last_user_message_empty_trace() {
        let sid = format!("trace-lastmsg-empty-{}", std::process::id());
        let dir = session_dir(&sid);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(steps_path(&sid), "").unwrap();
        assert!(last_user_message(&sid).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_last_user_message_no_trace() {
        let sid = format!("trace-lastmsg-none-{}", std::process::id());
        let dir = session_dir(&sid);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(last_user_message(&sid).is_none());
    }
}
