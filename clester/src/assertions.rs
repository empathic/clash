//! Assertion engine for clester.
//!
//! Validates hook results against expected outcomes defined in test scripts.

use crate::runner::HookResult;
use crate::script::Expectation;

/// Result of checking assertions for a single step.
#[derive(Debug)]
pub struct AssertionResult {
    pub passed: bool,
    pub failures: Vec<String>,
}

/// Check all assertions for a step against the actual hook result.
pub fn check(expect: &Expectation, result: &HookResult) -> AssertionResult {
    let mut failures = Vec::new();

    // Check exit code
    if let Some(expected_code) = expect.exit_code
        && result.exit_code != expected_code
    {
        failures.push(format!(
            "exit code: expected {}, got {}",
            expected_code, result.exit_code
        ));
    }

    // Check permission decision
    if let Some(ref expected_decision) = expect.decision {
        match &result.output {
            Some(output) => {
                let actual_decision = extract_decision(output);
                match actual_decision {
                    Some(actual) if actual == *expected_decision => {}
                    Some(actual) => {
                        failures.push(format!(
                            "decision: expected \"{}\", got \"{}\"",
                            expected_decision, actual
                        ));
                    }
                    None => {
                        failures.push(format!(
                            "decision: expected \"{}\", but no decision found in output: {}",
                            expected_decision,
                            serde_json::to_string_pretty(output).unwrap_or_default()
                        ));
                    }
                }
            }
            None => {
                failures.push(format!(
                    "decision: expected \"{}\", but stdout was not valid JSON: {}",
                    expected_decision, result.stdout
                ));
            }
        }
    }

    // Check no_decision (continue_execution with no hookSpecificOutput)
    if expect.no_decision == Some(true) {
        match &result.output {
            Some(output) => {
                if output.get("hookSpecificOutput").is_some()
                    && !output["hookSpecificOutput"].is_null()
                {
                    failures.push(format!(
                        "no_decision: expected no hook-specific output, but got: {}",
                        serde_json::to_string_pretty(output).unwrap_or_default()
                    ));
                }
            }
            None => {
                failures.push(format!(
                    "no_decision: expected JSON output, but stdout was not valid JSON: {}",
                    result.stdout
                ));
            }
        }
    }

    // Check reason_contains
    if let Some(ref expected_substr) = expect.reason_contains {
        match &result.output {
            Some(output) => {
                let reason = extract_reason(output).unwrap_or_default();
                if !reason.contains(expected_substr.as_str()) {
                    failures.push(format!(
                        "reason_contains: expected reason to contain \"{}\", got \"{}\"",
                        expected_substr, reason
                    ));
                }
            }
            None => {
                failures.push(format!(
                    "reason_contains: expected JSON output, but stdout was not valid JSON: {}",
                    result.stdout
                ));
            }
        }
    }

    // Check stdout_contains
    if let Some(ref expected_substr) = expect.stdout_contains
        && !result.stdout.contains(expected_substr.as_str())
    {
        failures.push(format!(
            "stdout_contains: expected stdout to contain \"{}\", got:\n{}",
            expected_substr,
            result
                .stdout
                .lines()
                .take(20)
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }

    // Check stderr_contains
    if let Some(ref expected_substr) = expect.stderr_contains
        && !result.stderr.contains(expected_substr.as_str())
    {
        failures.push(format!(
            "stderr_contains: expected stderr to contain \"{}\", got:\n{}",
            expected_substr,
            result
                .stderr
                .lines()
                .take(20)
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }

    AssertionResult {
        passed: failures.is_empty(),
        failures,
    }
}

/// Extract the permission decision from hook output JSON.
///
/// Handles both PreToolUse format (permissionDecision field)
/// and PermissionRequest format (decision.behavior field).
fn extract_decision(output: &serde_json::Value) -> Option<String> {
    // PreToolUse: {"hookSpecificOutput": {"permissionDecision": "allow"}}
    if let Some(decision) = output
        .get("hookSpecificOutput")
        .and_then(|h| h.get("permissionDecision"))
        .and_then(|d| d.as_str())
    {
        return Some(decision.to_string());
    }

    // PermissionRequest: {"hookSpecificOutput": {"decision": {"behavior": "allow"}}}
    if let Some(behavior) = output
        .get("hookSpecificOutput")
        .and_then(|h| h.get("decision"))
        .and_then(|d| d.get("behavior"))
        .and_then(|b| b.as_str())
    {
        return Some(behavior.to_string());
    }

    None
}

/// Extract the permission decision reason from hook output JSON.
fn extract_reason(output: &serde_json::Value) -> Option<String> {
    output
        .get("hookSpecificOutput")
        .and_then(|h| h.get("permissionDecisionReason"))
        .and_then(|r| r.as_str())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_allow_output() -> serde_json::Value {
        serde_json::json!({
            "continue": true,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": "explicitly allowed"
            }
        })
    }

    fn make_deny_output() -> serde_json::Value {
        serde_json::json!({
            "continue": true,
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "explicitly denied"
            }
        })
    }

    fn make_continue_output() -> serde_json::Value {
        serde_json::json!({
            "continue": true
        })
    }

    #[test]
    fn test_check_allow_pass() {
        let expect = Expectation {
            decision: Some("allow".into()),
            exit_code: Some(0),
            no_decision: None,
            reason_contains: None,
            stdout_contains: None,
            stderr_contains: None,
        };
        let result = HookResult {
            exit_code: 0,
            output: Some(make_allow_output()),
            stdout: String::new(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result);
        assert!(assertion.passed, "failures: {:?}", assertion.failures);
    }

    #[test]
    fn test_check_decision_mismatch() {
        let expect = Expectation {
            decision: Some("allow".into()),
            exit_code: None,
            no_decision: None,
            reason_contains: None,
            stdout_contains: None,
            stderr_contains: None,
        };
        let result = HookResult {
            exit_code: 0,
            output: Some(make_deny_output()),
            stdout: String::new(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result);
        assert!(!assertion.passed);
        assert!(assertion.failures[0].contains("expected \"allow\""));
    }

    #[test]
    fn test_check_no_decision_pass() {
        let expect = Expectation {
            decision: None,
            exit_code: None,
            no_decision: Some(true),
            reason_contains: None,
            stdout_contains: None,
            stderr_contains: None,
        };
        let result = HookResult {
            exit_code: 0,
            output: Some(make_continue_output()),
            stdout: String::new(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result);
        assert!(assertion.passed, "failures: {:?}", assertion.failures);
    }

    #[test]
    fn test_check_reason_contains() {
        let expect = Expectation {
            decision: None,
            exit_code: None,
            no_decision: None,
            reason_contains: Some("explicitly".into()),
            stdout_contains: None,
            stderr_contains: None,
        };
        let result = HookResult {
            exit_code: 0,
            output: Some(make_allow_output()),
            stdout: String::new(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result);
        assert!(assertion.passed, "failures: {:?}", assertion.failures);
    }

    #[test]
    fn test_check_exit_code_mismatch() {
        let expect = Expectation {
            decision: None,
            exit_code: Some(0),
            no_decision: None,
            reason_contains: None,
            stdout_contains: None,
            stderr_contains: None,
        };
        let result = HookResult {
            exit_code: 2,
            output: None,
            stdout: String::new(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result);
        assert!(!assertion.passed);
        assert!(assertion.failures[0].contains("exit code"));
    }

    #[test]
    fn test_check_stdout_contains_pass() {
        let expect = Expectation {
            decision: None,
            exit_code: None,
            no_decision: None,
            reason_contains: None,
            stdout_contains: Some("(allow".into()),
            stderr_contains: None,
        };
        let result = HookResult {
            exit_code: 0,
            output: None,
            stdout: "(allow (exec \"git\" *))".into(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result);
        assert!(assertion.passed, "failures: {:?}", assertion.failures);
    }

    #[test]
    fn test_check_stdout_contains_fail() {
        let expect = Expectation {
            decision: None,
            exit_code: None,
            no_decision: None,
            reason_contains: None,
            stdout_contains: Some("(allow".into()),
            stderr_contains: None,
        };
        let result = HookResult {
            exit_code: 0,
            output: None,
            stdout: "(deny (exec \"git\" *))".into(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result);
        assert!(!assertion.passed);
        assert!(assertion.failures[0].contains("stdout_contains"));
    }

    #[test]
    fn test_check_stderr_contains() {
        let expect = Expectation {
            decision: None,
            exit_code: None,
            no_decision: None,
            reason_contains: None,
            stdout_contains: None,
            stderr_contains: Some("warning".into()),
        };
        let result = HookResult {
            exit_code: 0,
            output: None,
            stdout: String::new(),
            stderr: "warning: policy modified".into(),
        };

        let assertion = check(&expect, &result);
        assert!(assertion.passed, "failures: {:?}", assertion.failures);
    }
}
