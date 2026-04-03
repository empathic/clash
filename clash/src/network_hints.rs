//! Detect network errors in sandboxed Bash output and provide actionable hints.
//!
//! When a Bash command runs inside a clash sandbox with `NetworkPolicy::Deny`
//! (the default), network calls fail at the OS level with cryptic errors.
//! This module detects those errors in PostToolUse responses and returns
//! advisory context so Claude can explain the cause and suggest fixes.

use tracing::{Level, info, instrument};

use crate::hooks::ToolUseHookInput;
use crate::policy::sandbox_types::{NetworkPolicy, ViolationAction};
use crate::settings::ClashSettings;

/// Network error patterns that indicate a sandboxed process tried to access the network.
///
/// These are substrings matched case-insensitively against the tool response text.
const NETWORK_ERROR_PATTERNS: &[&str] = &[
    // DNS resolution failures
    "could not resolve host",
    "name or service not known",
    "temporary failure in name resolution",
    "nodename nor servname provided",
    "failed to lookup address",
    "getaddrinfo",
    // Connection failures
    "network is unreachable",
    "network unreachable",
    // curl exit codes
    "curl: (6)",  // DNS
    "curl: (7)",  // connection
    "curl: (56)", // network recv failure
    // wget
    "unable to resolve host address",
    // cargo/rustup
    "failed to resolve address",
    "error trying to connect",
    // npm/yarn
    "getaddrinfo enotfound",
    "err_socket_not_connected",
    // pip
    "could not find a version that satisfies",
    "max retries exceeded with url",
    // go
    "dial tcp: lookup",
    // general socket errors
    "enetunreach",
    "socket: operation not permitted",
    "network access denied",
];

/// Check if a PostToolUse Bash response contains network errors likely caused
/// by sandbox network restrictions. Returns advisory context if so.
#[instrument(level = Level::TRACE, skip(input, settings))]
pub fn check_for_sandbox_network_hint(
    input: &ToolUseHookInput,
    settings: &ClashSettings,
) -> Option<String> {
    // Only check Bash tool responses
    if input.tool_name != "Bash" {
        return None;
    }

    // Extract text from tool_response
    let response_text = extract_response_text(input.tool_response.as_ref()?)?;

    // Check for network error patterns
    if !contains_network_error(&response_text) {
        return None;
    }

    // Re-evaluate the policy to check if this command would run under
    // a sandbox with NetworkPolicy::Deny
    let tree = settings.policy_tree()?;
    let decision = tree.evaluate(&input.tool_name, &input.tool_input);

    let network_policy = decision.sandbox.as_ref().map(|s| &s.network);

    let network_denied = matches!(network_policy, Some(NetworkPolicy::Deny));
    let network_domain_filtered = matches!(network_policy, Some(NetworkPolicy::AllowDomains(_)));

    if !network_denied && !network_domain_filtered {
        return None;
    }

    info!(
        tool = "Bash",
        domain_filtered = network_domain_filtered,
        "Detected network error in sandboxed command output"
    );

    let sandbox_name = decision.sandbox_name
        .map(|r| r.0)
        .unwrap_or_else(|| "unnamed".to_string());

    let action = tree.on_sandbox_violation;

    Some(build_network_hint(&sandbox_name, action))
}

/// Extract readable text from a tool_response JSON value.
///
/// Claude Code tool responses can be structured in various ways — this handles
/// common shapes (string, object with content/stdout/stderr fields, arrays).
pub(crate) fn extract_response_text(response: &serde_json::Value) -> Option<String> {
    match response {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(obj) => {
            let mut parts = Vec::new();
            for key in ["content", "stdout", "stderr", "output", "error", "result"] {
                if let Some(serde_json::Value::String(s)) = obj.get(key) {
                    parts.push(s.as_str());
                }
            }
            if parts.is_empty() {
                // Fall back to the full JSON stringified
                Some(serde_json::to_string(response).ok()?)
            } else {
                Some(parts.join("\n"))
            }
        }
        serde_json::Value::Array(arr) => {
            let texts: Vec<String> = arr.iter().filter_map(extract_response_text).collect();
            if texts.is_empty() {
                None
            } else {
                Some(texts.join("\n"))
            }
        }
        _ => None,
    }
}

/// Check if text contains any network error patterns (case-insensitive).
fn contains_network_error(text: &str) -> bool {
    let lower = text.to_lowercase();
    NETWORK_ERROR_PATTERNS
        .iter()
        .any(|pattern| lower.contains(pattern))
}

/// Build advisory context for Claude when a sandbox blocks network access.
fn build_network_hint(sandbox_name: &str, action: ViolationAction) -> String {
    let directive = crate::sandbox_hints::formatter::directive_text(action);
    [
        &format!("SANDBOX VIOLATION: sandbox \"{sandbox_name}\" blocked network access (policy: deny)."),
        "",
        "To fix:",
        &format!("  clash sandbox add-rule --name {sandbox_name} --net allow"),
        "",
        directive,
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::sandbox_types::ViolationAction;
    use serde_json::json;

    #[test]
    fn test_contains_network_error_dns() {
        assert!(contains_network_error(
            "curl: (6) Could not resolve host: example.com"
        ));
    }

    #[test]
    fn test_contains_network_error_unreachable() {
        assert!(contains_network_error("Network is unreachable"));
    }

    #[test]
    fn test_contains_network_error_case_insensitive() {
        assert!(contains_network_error("COULD NOT RESOLVE HOST: foo.com"));
    }

    #[test]
    fn test_contains_network_error_no_match() {
        assert!(!contains_network_error("file not found: /tmp/test.txt"));
    }

    #[test]
    fn test_contains_network_error_cargo() {
        assert!(contains_network_error(
            "error: failed to resolve address for github.com: Name or service not known"
        ));
    }

    #[test]
    fn test_contains_network_error_npm() {
        assert!(contains_network_error(
            "npm ERR! getaddrinfo ENOTFOUND registry.npmjs.org"
        ));
    }

    #[test]
    fn test_extract_response_text_string() {
        let val = json!("some output text");
        assert_eq!(extract_response_text(&val), Some("some output text".into()));
    }

    #[test]
    fn test_extract_response_text_object_with_content() {
        let val = json!({"content": "error: network unreachable"});
        let text = extract_response_text(&val).unwrap();
        assert!(text.contains("error: network unreachable"));
    }

    #[test]
    fn test_extract_response_text_object_with_stderr() {
        let val = json!({"stdout": "", "stderr": "curl: (6) Could not resolve host"});
        let text = extract_response_text(&val).unwrap();
        assert!(text.contains("Could not resolve host"));
    }

    #[test]
    fn test_extract_response_text_null() {
        assert_eq!(extract_response_text(&json!(null)), None);
    }

    #[test]
    fn test_extract_response_text_array() {
        let val = json!(["line 1", "Could not resolve host"]);
        let text = extract_response_text(&val).unwrap();
        assert!(text.contains("Could not resolve host"));
    }

    #[test]
    fn test_build_network_hint_contains_key_info() {
        let hint = build_network_hint("restricted", ViolationAction::Stop);
        assert!(hint.contains("SANDBOX VIOLATION"));
        assert!(hint.contains("\"restricted\""));
        assert!(hint.contains("net allow"));
        assert!(hint.contains("Do NOT retry"));
    }

    #[test]
    fn test_build_network_hint_workaround() {
        let hint = build_network_hint("mybox", ViolationAction::Workaround);
        assert!(hint.contains("\"mybox\""));
        assert!(hint.contains("Try an alternative approach"));
    }

    #[test]
    fn test_build_network_hint_smart() {
        let hint = build_network_hint("mybox", ViolationAction::Smart);
        assert!(hint.contains("Assess"));
    }

    #[test]
    fn test_check_returns_none_for_non_bash() {
        let input = ToolUseHookInput {
            tool_name: "Read".into(),
            tool_response: Some(json!("Could not resolve host")),
            ..Default::default()
        };
        let settings = ClashSettings::default();
        assert!(check_for_sandbox_network_hint(&input, &settings).is_none());
    }

    #[test]
    fn test_check_returns_none_without_response() {
        let input = ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_response: None,
            ..Default::default()
        };
        let settings = ClashSettings::default();
        assert!(check_for_sandbox_network_hint(&input, &settings).is_none());
    }

    #[test]
    fn test_check_returns_none_for_non_network_error() {
        let input = ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_response: Some(json!("file not found")),
            ..Default::default()
        };
        let settings = ClashSettings::default();
        assert!(check_for_sandbox_network_hint(&input, &settings).is_none());
    }

    #[test]
    fn test_check_returns_none_without_policy() {
        // No compiled policy → no decision tree → returns None
        let settings = ClashSettings::default();
        assert!(settings.decision_tree().is_none());
        let input = ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_input: json!({"command": "curl example.com"}),
            tool_response: Some(json!("Could not resolve host")),
            ..Default::default()
        };
        assert!(check_for_sandbox_network_hint(&input, &settings).is_none());
    }

    #[test]
    fn test_check_returns_hint_with_implicit_sandbox() {
        // V5: allow Bash with a sandbox that denies network
        let mut settings = ClashSettings::default();
        settings.set_policy_source(
            r#"{"schema_version":5,"default_effect":"deny",
  "sandboxes":{"restricted":{"default":["read","execute"],"rules":[],"network":"deny"}},
  "tree":[
    {"condition":{"observe":"tool_name","pattern":{"literal":{"literal":"Bash"}},"children":[
      {"decision":{"allow":"restricted"}}
    ]}}
  ]}"#,
        );
        let input = ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_input: json!({"command": "curl example.com"}),
            tool_response: Some(json!("curl: (6) Could not resolve host: example.com")),
            cwd: "/tmp".into(),
            ..Default::default()
        };
        let result = check_for_sandbox_network_hint(&input, &settings);
        assert!(
            result.is_some(),
            "should return hint for sandboxed network error"
        );
        let hint = result.unwrap();
        assert!(hint.contains("SANDBOX VIOLATION"));
    }

    #[test]
    fn test_check_returns_hint_with_explicit_sandbox_network_deny() {
        // Explicit sandbox with network=deny
        let mut settings = ClashSettings::default();
        settings.set_policy_source(
            r#"{"schema_version":5,"default_effect":"deny",
  "sandboxes":{"restricted":{"default":["read","execute"],"rules":[],"network":"deny"}},
  "tree":[
    {"condition":{"observe":"tool_name","pattern":{"literal":{"literal":"Bash"}},"children":[
      {"condition":{"observe":{"positional_arg":0},"pattern":{"literal":{"literal":"curl"}},"children":[
        {"decision":{"allow":"restricted"}}
      ]}}
    ]}}
  ]}"#,
        );
        let input = ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_input: json!({"command": "curl example.com"}),
            tool_response: Some(json!("curl: (6) Could not resolve host: example.com")),
            cwd: "/tmp".into(),
            ..Default::default()
        };
        let result = check_for_sandbox_network_hint(&input, &settings);
        assert!(
            result.is_some(),
            "should return hint for sandboxed network error"
        );
        let hint = result.unwrap();
        assert!(hint.contains("SANDBOX VIOLATION"));
    }

    #[test]
    fn test_check_returns_none_with_sandbox_network_allow() {
        // Sandbox with network=allow → network errors aren't from sandbox
        let mut settings = ClashSettings::default();
        settings.set_policy_source(
            r#"{"schema_version":5,"default_effect":"deny",
  "sandboxes":{"with-net":{"default":["read","execute"],"rules":[],"network":"allow"}},
  "tree":[
    {"condition":{"observe":"tool_name","pattern":{"literal":{"literal":"Bash"}},"children":[
      {"condition":{"observe":{"positional_arg":0},"pattern":{"literal":{"literal":"curl"}},"children":[
        {"decision":{"allow":"with-net"}}
      ]}}
    ]}}
  ]}"#,
        );
        let input = ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_input: json!({"command": "curl example.com"}),
            tool_response: Some(json!("Could not resolve host")),
            cwd: "/tmp".into(),
            ..Default::default()
        };
        assert!(check_for_sandbox_network_hint(&input, &settings).is_none());
    }

    #[test]
    fn test_check_returns_hint_with_domain_specific_net_rule() {
        // Domain-specific net allow → NetworkPolicy::AllowDomains → hint fires
        let mut settings = ClashSettings::default();
        settings.set_policy_source(
            r#"{"schema_version":5,"default_effect":"deny",
  "sandboxes":{"with-net":{"default":["read","execute"],"rules":[],"network":{"allow_domains":["example.com"]}}},
  "tree":[
    {"condition":{"observe":"tool_name","pattern":{"literal":{"literal":"Bash"}},"children":[
      {"condition":{"observe":{"positional_arg":0},"pattern":{"literal":{"literal":"curl"}},"children":[
        {"decision":{"allow":"with-net"}}
      ]}}
    ]}}
  ]}"#,
        );
        let input = ToolUseHookInput {
            tool_name: "Bash".into(),
            tool_input: json!({"command": "curl example.com"}),
            tool_response: Some(json!("Could not resolve host")),
            cwd: "/tmp".into(),
            ..Default::default()
        };
        assert!(check_for_sandbox_network_hint(&input, &settings).is_some());
    }
}
