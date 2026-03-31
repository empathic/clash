//! Fixture-based integration tests for clash_hooks.
//!
//! Each test loads a real-world JSON fixture, parses it with `recv_from()`,
//! verifies the event fields, builds a response, serializes with `send_to()`,
//! and asserts the wire JSON matches Claude Code expectations.

use clash_hooks::{HookEvent, HookEventCommon, ToolEvent, recv_from, send_to};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read fixture {path}: {e}"))
}

fn response_json(response: &clash_hooks::Response) -> serde_json::Value {
    let mut buf = Vec::new();
    send_to(response, &mut buf).unwrap();
    serde_json::from_slice(&buf).unwrap()
}

// ═══════════════════════════════════════════════════════════════════════
// Round-trip tests per event type
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_roundtrip_pre_tool_use_bash() {
    let event = recv_from(fixture("pre_tool_use_bash.json").as_slice()).unwrap();
    match event {
        HookEvent::PreToolUse(ref e) => {
            assert_eq!(e.session_id(), "sess_abc123");
            assert_eq!(e.cwd(), "/home/user/project");
            assert_eq!(e.permission_mode(), Some("default"));
            assert_eq!(e.tool_name(), "Bash");
            assert_eq!(e.tool_use_id(), Some("toolu_01ABCdef"));
            let bash = e.bash().unwrap();
            assert_eq!(bash.command, "git status");
            assert_eq!(bash.timeout, Some(120000));

            let json = response_json(&e.allow());
            assert_eq!(json["continue"], true);
            assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "allow");
        }
        other => panic!("expected PreToolUse, got {other:?}"),
    }
}

#[test]
fn test_roundtrip_pre_tool_use_write() {
    let event = recv_from(fixture("pre_tool_use_write.json").as_slice()).unwrap();
    match event {
        HookEvent::PreToolUse(ref e) => {
            assert_eq!(e.tool_name(), "Write");
            let write = e.write().unwrap();
            assert_eq!(write.file_path, "/home/user/project/src/main.rs");
            assert_eq!(write.content, "fn main() {}");

            let json = response_json(&e.deny("not allowed"));
            assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
            assert_eq!(
                json["hookSpecificOutput"]["permissionDecisionReason"],
                "not allowed"
            );
        }
        other => panic!("expected PreToolUse, got {other:?}"),
    }
}

#[test]
fn test_roundtrip_post_tool_use() {
    let event = recv_from(fixture("post_tool_use.json").as_slice()).unwrap();
    match event {
        HookEvent::PostToolUse(ref e) => {
            assert_eq!(e.tool_name(), "Bash");
            assert!(e.tool_response().is_some());
            let resp = e.tool_response().unwrap();
            assert_eq!(resp["stdout"], "test result: ok. 5 passed");

            let json = response_json(&e.context("tests passed"));
            assert_eq!(
                json["hookSpecificOutput"]["additionalContext"],
                "tests passed"
            );
        }
        other => panic!("expected PostToolUse, got {other:?}"),
    }
}

#[test]
fn test_roundtrip_post_tool_use_failure() {
    let event = recv_from(fixture("post_tool_use_failure.json").as_slice()).unwrap();
    match event {
        HookEvent::PostToolUseFailure(ref e) => {
            assert_eq!(e.tool_name(), "Bash");
            assert_eq!(e.error(), Some("Command execution failed"));
            assert!(!e.is_interrupt());

            let json = response_json(&e.context("command failed"));
            assert_eq!(
                json["hookSpecificOutput"]["hookEventName"],
                "PostToolUseFailure"
            );
        }
        other => panic!("expected PostToolUseFailure, got {other:?}"),
    }
}

#[test]
fn test_roundtrip_permission_request() {
    let event = recv_from(fixture("permission_request.json").as_slice()).unwrap();
    match event {
        HookEvent::PermissionRequest(ref e) => {
            assert_eq!(e.tool_name(), "Bash");
            let bash = e.bash().unwrap();
            assert_eq!(bash.command, "npm install express");

            // Test approve
            let json = response_json(&e.approve());
            assert_eq!(
                json["hookSpecificOutput"]["hookEventName"],
                "PermissionRequest"
            );
            assert_eq!(json["hookSpecificOutput"]["decision"]["behavior"], "allow");

            // Test deny
            let json = response_json(&e.deny("denied by policy"));
            assert_eq!(json["hookSpecificOutput"]["decision"]["behavior"], "deny");
            assert_eq!(
                json["hookSpecificOutput"]["decision"]["message"],
                "denied by policy"
            );
        }
        other => panic!("expected PermissionRequest, got {other:?}"),
    }
}

#[test]
fn test_roundtrip_session_start() {
    let event = recv_from(fixture("session_start.json").as_slice()).unwrap();
    match event {
        HookEvent::SessionStart(ref e) => {
            assert_eq!(e.session_id(), "sess_abc123");
            assert_eq!(e.source(), Some("startup"));
            assert_eq!(e.model(), Some("claude-sonnet-4-20250514"));

            let json = response_json(&e.context("clash is active"));
            assert_eq!(json["hookSpecificOutput"]["hookEventName"], "SessionStart");
            assert_eq!(
                json["hookSpecificOutput"]["additionalContext"],
                "clash is active"
            );
        }
        other => panic!("expected SessionStart, got {other:?}"),
    }
}

#[test]
fn test_roundtrip_session_end() {
    let event = recv_from(fixture("session_end.json").as_slice()).unwrap();
    match event {
        HookEvent::SessionEnd(ref e) => {
            assert_eq!(e.reason(), Some("user_exit"));

            let json = response_json(&e.pass());
            assert_eq!(json["continue"], true);
        }
        other => panic!("expected SessionEnd, got {other:?}"),
    }
}

#[test]
fn test_roundtrip_user_prompt_submit() {
    let event = recv_from(fixture("user_prompt_submit.json").as_slice()).unwrap();
    match event {
        HookEvent::UserPromptSubmit(ref e) => {
            assert_eq!(e.prompt(), Some("Please fix the bug in src/main.rs"));

            let json = response_json(&e.block("blocked by policy"));
            assert_eq!(json["decision"], "block");
            assert_eq!(json["reason"], "blocked by policy");
        }
        other => panic!("expected UserPromptSubmit, got {other:?}"),
    }
}

#[test]
fn test_roundtrip_stop() {
    let event = recv_from(fixture("stop.json").as_slice()).unwrap();
    match event {
        HookEvent::Stop(ref e) => {
            assert!(!e.stop_hook_active());
            assert_eq!(
                e.last_assistant_message(),
                Some("I've fixed the bug. The test suite passes now.")
            );

            let json = response_json(&e.pass());
            assert_eq!(json["continue"], true);
        }
        other => panic!("expected Stop, got {other:?}"),
    }
}

#[test]
fn test_roundtrip_stop_failure() {
    let event = recv_from(fixture("stop_failure.json").as_slice()).unwrap();
    match event {
        HookEvent::StopFailure(ref e) => {
            assert_eq!(e.error(), Some("rate_limit"));
            assert!(e.error_details().is_some());
            assert_eq!(e.last_assistant_message(), Some("I was working on..."));
        }
        other => panic!("expected StopFailure, got {other:?}"),
    }
}

#[test]
fn test_roundtrip_subagent_start() {
    let event = recv_from(fixture("subagent_start.json").as_slice()).unwrap();
    match event {
        HookEvent::SubagentStart(ref e) => {
            assert_eq!(e.agent_id(), Some("agent_001"));
            assert_eq!(e.agent_type(), Some("Explore"));

            let json = response_json(&e.context("subagent launched"));
            assert_eq!(json["hookSpecificOutput"]["hookEventName"], "SubagentStart");
        }
        other => panic!("expected SubagentStart, got {other:?}"),
    }
}

#[test]
fn test_roundtrip_subagent_stop() {
    let event = recv_from(fixture("subagent_stop.json").as_slice()).unwrap();
    match event {
        HookEvent::SubagentStop(ref e) => {
            assert_eq!(e.agent_id(), Some("agent_001"));
            assert_eq!(e.agent_type(), Some("Explore"));
            assert!(e.agent_transcript_path().is_some());
            assert_eq!(e.last_assistant_message(), Some("Found 3 matching files."));
        }
        other => panic!("expected SubagentStop, got {other:?}"),
    }
}

#[test]
fn test_roundtrip_elicitation() {
    let event = recv_from(fixture("elicitation.json").as_slice()).unwrap();
    match event {
        HookEvent::Elicitation(ref e) => {
            assert_eq!(e.mcp_server_name(), Some("github-mcp"));
            assert_eq!(e.message(), Some("Enter your GitHub API token"));
            assert_eq!(e.elicitation_id(), Some("elic_01ABC"));
            assert!(e.requested_schema().is_some());

            // Test accept
            let json = response_json(&e.accept(serde_json::json!({"token": "ghp_xxx"})));
            assert_eq!(json["continue"], true);
            assert_eq!(json["action"], "accept");
            assert_eq!(json["content"]["token"], "ghp_xxx");

            // Test decline
            let json = response_json(&e.decline());
            assert_eq!(json["action"], "decline");

            // Test cancel
            let json = response_json(&e.cancel());
            assert_eq!(json["action"], "cancel");
        }
        other => panic!("expected Elicitation, got {other:?}"),
    }
}

#[test]
fn test_roundtrip_notification() {
    let event = recv_from(fixture("notification.json").as_slice()).unwrap();
    match event {
        HookEvent::Notification(ref e) => {
            assert_eq!(e.message(), Some("Task completed successfully"));
            assert_eq!(e.title(), Some("Claude Code"));
            assert_eq!(e.notification_type(), Some("info"));
        }
        other => panic!("expected Notification, got {other:?}"),
    }
}

#[test]
fn test_roundtrip_config_change() {
    let event = recv_from(fixture("config_change.json").as_slice()).unwrap();
    match event {
        HookEvent::ConfigChange(ref e) => {
            assert_eq!(e.source(), Some("project_settings"));
            assert_eq!(
                e.file_path(),
                Some("/home/user/project/.claude/settings.json")
            );

            let json = response_json(&e.block("config change blocked"));
            assert_eq!(json["decision"], "block");
        }
        other => panic!("expected ConfigChange, got {other:?}"),
    }
}

#[test]
fn test_roundtrip_pre_compact() {
    let event = recv_from(fixture("pre_compact.json").as_slice()).unwrap();
    match event {
        HookEvent::PreCompact(ref e) => {
            assert_eq!(e.trigger(), Some("auto"));
            assert_eq!(
                e.custom_instructions(),
                Some("Keep the test plan in context")
            );
        }
        other => panic!("expected PreCompact, got {other:?}"),
    }
}

#[test]
fn test_roundtrip_post_compact() {
    let event = recv_from(fixture("post_compact.json").as_slice()).unwrap();
    match event {
        HookEvent::PostCompact(ref e) => {
            assert_eq!(e.trigger(), Some("auto"));
            assert_eq!(
                e.compact_summary(),
                Some("Summarized 50 messages into 5 key points")
            );
        }
        other => panic!("expected PostCompact, got {other:?}"),
    }
}

#[test]
fn test_roundtrip_worktree_create() {
    let event = recv_from(fixture("worktree_create.json").as_slice()).unwrap();
    match event {
        HookEvent::WorktreeCreate(ref e) => {
            assert_eq!(e.name(), Some("feature/new-auth"));
        }
        other => panic!("expected WorktreeCreate, got {other:?}"),
    }
}

#[test]
fn test_roundtrip_unknown_future() {
    let event = recv_from(fixture("unknown_future.json").as_slice()).unwrap();
    match event {
        HookEvent::Unknown(ref e) => {
            assert_eq!(e.hook_event_name(), "FutureEventV99");
            assert_eq!(e.session_id(), "sess_abc123");
            // Extra fields are preserved
            let extra = e.extra();
            assert_eq!(
                extra.get("new_field_1").and_then(|v| v.as_str()),
                Some("some_value")
            );
            assert_eq!(extra.get("new_field_2").and_then(|v| v.as_i64()), Some(42));
        }
        other => panic!("expected Unknown, got {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Forward compatibility
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_forward_compat_unknown_fields() {
    // A PreToolUse with extra fields that don't exist in the current schema
    let json = r#"{
        "session_id": "s", "transcript_path": "t", "cwd": "c",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
        "tool_use_id": "toolu_01",
        "future_field": "hello",
        "another_future": [1, 2, 3]
    }"#;
    let event = recv_from(json.as_bytes()).unwrap();
    match event {
        HookEvent::PreToolUse(ref e) => {
            assert_eq!(e.tool_name(), "Bash");
            // Should parse fine despite unknown fields
            let bash = e.bash().unwrap();
            assert_eq!(bash.command, "ls");
        }
        other => panic!("expected PreToolUse, got {other:?}"),
    }
}

#[test]
fn test_forward_compat_unknown_event_type() {
    let json = r#"{
        "session_id": "s", "transcript_path": "t", "cwd": "c",
        "hook_event_name": "NewFeatureEvent",
        "feature_id": "feat_123",
        "metadata": {"version": 2}
    }"#;
    let event = recv_from(json.as_bytes()).unwrap();
    assert!(matches!(event, HookEvent::Unknown(_)));
    assert_eq!(event.session_id(), "s");
    assert_eq!(event.hook_event_name(), "NewFeatureEvent");
}

// ═══════════════════════════════════════════════════════════════════════
// All tool accessors
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_all_tool_accessors() {
    // Bash
    let event = recv_from(fixture("pre_tool_use_bash.json").as_slice()).unwrap();
    if let HookEvent::PreToolUse(ref e) = event {
        assert!(e.bash().is_some());
        assert!(e.write().is_none());
        assert!(e.edit().is_none());
        assert!(e.read().is_none());
        assert!(e.glob().is_none());
        assert!(e.grep().is_none());
        assert!(e.web_fetch().is_none());
        assert!(e.web_search().is_none());
        assert!(e.notebook_edit().is_none());
        assert!(e.skill().is_none());
        assert!(e.agent().is_none());
    }

    // Write
    let event = recv_from(fixture("pre_tool_use_write.json").as_slice()).unwrap();
    if let HookEvent::PreToolUse(ref e) = event {
        assert!(e.bash().is_none());
        assert!(e.write().is_some());
    }

    // Edit
    let json = r#"{
        "session_id": "s", "transcript_path": "t", "cwd": "c",
        "hook_event_name": "PreToolUse",
        "tool_name": "Edit",
        "tool_input": {"file_path": "/tmp/f.rs", "old_string": "a", "new_string": "b"}
    }"#;
    let event = recv_from(json.as_bytes()).unwrap();
    if let HookEvent::PreToolUse(ref e) = event {
        let edit = e.edit().unwrap();
        assert_eq!(edit.file_path, "/tmp/f.rs");
        assert_eq!(edit.old_string, "a");
        assert_eq!(edit.new_string, "b");
    }

    // Read
    let json = r#"{
        "session_id": "s", "transcript_path": "t", "cwd": "c",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "/tmp/f.rs"}
    }"#;
    let event = recv_from(json.as_bytes()).unwrap();
    if let HookEvent::PreToolUse(ref e) = event {
        let read = e.read().unwrap();
        assert_eq!(read.file_path, "/tmp/f.rs");
    }

    // Glob
    let json = r#"{
        "session_id": "s", "transcript_path": "t", "cwd": "c",
        "hook_event_name": "PreToolUse",
        "tool_name": "Glob",
        "tool_input": {"pattern": "**/*.rs"}
    }"#;
    let event = recv_from(json.as_bytes()).unwrap();
    if let HookEvent::PreToolUse(ref e) = event {
        let glob = e.glob().unwrap();
        assert_eq!(glob.pattern, "**/*.rs");
    }

    // Grep
    let json = r#"{
        "session_id": "s", "transcript_path": "t", "cwd": "c",
        "hook_event_name": "PreToolUse",
        "tool_name": "Grep",
        "tool_input": {"pattern": "fn main"}
    }"#;
    let event = recv_from(json.as_bytes()).unwrap();
    if let HookEvent::PreToolUse(ref e) = event {
        let grep = e.grep().unwrap();
        assert_eq!(grep.pattern, "fn main");
    }

    // WebFetch
    let json = r#"{
        "session_id": "s", "transcript_path": "t", "cwd": "c",
        "hook_event_name": "PreToolUse",
        "tool_name": "WebFetch",
        "tool_input": {"url": "https://example.com", "prompt": "get page"}
    }"#;
    let event = recv_from(json.as_bytes()).unwrap();
    if let HookEvent::PreToolUse(ref e) = event {
        let wf = e.web_fetch().unwrap();
        assert_eq!(wf.url, "https://example.com");
    }

    // WebSearch
    let json = r#"{
        "session_id": "s", "transcript_path": "t", "cwd": "c",
        "hook_event_name": "PreToolUse",
        "tool_name": "WebSearch",
        "tool_input": {"query": "rust async"}
    }"#;
    let event = recv_from(json.as_bytes()).unwrap();
    if let HookEvent::PreToolUse(ref e) = event {
        let ws = e.web_search().unwrap();
        assert_eq!(ws.query, "rust async");
    }

    // Skill
    let json = r#"{
        "session_id": "s", "transcript_path": "t", "cwd": "c",
        "hook_event_name": "PreToolUse",
        "tool_name": "Skill",
        "tool_input": {"skill": "commit"}
    }"#;
    let event = recv_from(json.as_bytes()).unwrap();
    if let HookEvent::PreToolUse(ref e) = event {
        let skill = e.skill().unwrap();
        assert_eq!(skill.skill, "commit");
    }

    // Agent/Task
    let json = r#"{
        "session_id": "s", "transcript_path": "t", "cwd": "c",
        "hook_event_name": "PreToolUse",
        "tool_name": "Task",
        "tool_input": {"prompt": "find files", "subagent_type": "Explore"}
    }"#;
    let event = recv_from(json.as_bytes()).unwrap();
    if let HookEvent::PreToolUse(ref e) = event {
        let agent = e.agent().unwrap();
        assert_eq!(agent.prompt, "find files");
        assert_eq!(agent.subagent_type.as_deref(), Some("Explore"));
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Caching verification
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_typed_tool_input_is_cached() {
    let event = recv_from(fixture("pre_tool_use_bash.json").as_slice()).unwrap();
    if let HookEvent::PreToolUse(ref e) = event {
        // Call typed_tool_input twice — the second should return the cached ref.
        let first = e.typed_tool_input() as *const _;
        let second = e.typed_tool_input() as *const _;
        assert_eq!(
            first, second,
            "typed_tool_input should return same cached reference"
        );
    }
}
