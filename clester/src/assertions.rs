//! Assertion engine for clester.
//!
//! Validates hook results against expected outcomes defined in test scripts.

use std::path::Path;

use regex::Regex;

use crate::runner::HookResult;
use crate::script::Expectation;

/// Result of checking assertions for a single step.
#[derive(Debug)]
pub struct AssertionResult {
    pub passed: bool,
    pub failures: Vec<String>,
}

/// Check all assertions for a step against the actual hook result.
///
/// Handles combinators (all_of, any_of, not) and delegates leaf checks to `check_leaf`.
pub fn check(
    expect: &Expectation,
    result: &HookResult,
    home_dir: &Path,
    project_dir: &Path,
) -> AssertionResult {
    let mut failures = Vec::new();

    // Check leaf assertions (exit_code, decision, contains, regex, files)
    let leaf = check_leaf(expect, result, home_dir, project_dir);
    failures.extend(leaf.failures);

    // all_of: every child must pass
    if let Some(ref children) = expect.all_of {
        for (i, child) in children.iter().enumerate() {
            let child_result = check(child, result, home_dir, project_dir);
            if !child_result.passed {
                for f in child_result.failures {
                    failures.push(format!("all_of[{}]: {}", i, f));
                }
            }
        }
    }

    // any_of: at least one child must pass
    if let Some(ref children) = expect.any_of {
        let mut any_passed = false;
        let mut child_failures = Vec::new();
        for (i, child) in children.iter().enumerate() {
            let child_result = check(child, result, home_dir, project_dir);
            if child_result.passed {
                any_passed = true;
                break;
            }
            for f in child_result.failures {
                child_failures.push(format!("any_of[{}]: {}", i, f));
            }
        }
        if !any_passed {
            failures.push("any_of: no alternative passed".into());
            failures.extend(child_failures);
        }
    }

    // not: child must fail
    if let Some(ref child) = expect.not {
        let child_result = check(child, result, home_dir, project_dir);
        if child_result.passed {
            failures.push("not: expected child assertion to fail, but it passed".into());
        }
    }

    AssertionResult {
        passed: failures.is_empty(),
        failures,
    }
}

/// Check leaf assertions (non-combinator) for a step.
fn check_leaf(
    expect: &Expectation,
    result: &HookResult,
    home_dir: &Path,
    project_dir: &Path,
) -> AssertionResult {
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

    // Check reason_regex
    if let Some(ref pattern) = expect.reason_regex {
        match Regex::new(pattern) {
            Ok(re) => match &result.output {
                Some(output) => {
                    let reason = extract_reason(output).unwrap_or_default();
                    if !re.is_match(&reason) {
                        failures.push(format!(
                            "reason_regex: expected reason to match /{}/, got \"{}\"",
                            pattern, reason
                        ));
                    }
                }
                None => {
                    failures.push(format!(
                        "reason_regex: expected JSON output, but stdout was not valid JSON: {}",
                        result.stdout
                    ));
                }
            },
            Err(e) => {
                failures.push(format!("reason_regex: invalid regex /{}/ — {}", pattern, e));
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

    // Check stdout_regex
    if let Some(ref pattern) = expect.stdout_regex {
        match Regex::new(pattern) {
            Ok(re) => {
                if !re.is_match(&result.stdout) {
                    failures.push(format!(
                        "stdout_regex: expected stdout to match /{}/, got:\n{}",
                        pattern,
                        result
                            .stdout
                            .lines()
                            .take(20)
                            .collect::<Vec<_>>()
                            .join("\n")
                    ));
                }
            }
            Err(e) => {
                failures.push(format!(
                    "stdout_regex: invalid regex /{}/ — {}",
                    pattern, e
                ));
            }
        }
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

    // Check stderr_regex
    if let Some(ref pattern) = expect.stderr_regex {
        match Regex::new(pattern) {
            Ok(re) => {
                if !re.is_match(&result.stderr) {
                    failures.push(format!(
                        "stderr_regex: expected stderr to match /{}/, got:\n{}",
                        pattern,
                        result
                            .stderr
                            .lines()
                            .take(20)
                            .collect::<Vec<_>>()
                            .join("\n")
                    ));
                }
            }
            Err(e) => {
                failures.push(format!(
                    "stderr_regex: invalid regex /{}/ — {}",
                    pattern, e
                ));
            }
        }
    }

    // Check file assertions
    if let Some(ref file_assertions) = expect.files {
        for fa in file_assertions {
            let base = match fa.root.as_str() {
                "project" => project_dir,
                _ => home_dir,
            };
            let full_path = base.join(&fa.path);

            if let Some(should_exist) = fa.exists {
                let does_exist = full_path.exists();
                if should_exist && !does_exist {
                    failures.push(format!(
                        "files: expected {} to exist (root={}), but it does not",
                        fa.path, fa.root
                    ));
                    continue;
                }
                if !should_exist && does_exist {
                    failures.push(format!(
                        "files: expected {} to NOT exist (root={}), but it does",
                        fa.path, fa.root
                    ));
                    continue;
                }
                if !should_exist {
                    // File correctly doesn't exist, skip content checks
                    continue;
                }
            }

            // Content checks require the file to exist
            if fa.contains.is_some() || fa.regex.is_some() {
                match std::fs::read_to_string(&full_path) {
                    Ok(contents) => {
                        if let Some(ref substr) = fa.contains {
                            if !contents.contains(substr.as_str()) {
                                failures.push(format!(
                                    "files: expected {} to contain \"{}\", but it did not",
                                    fa.path, substr
                                ));
                            }
                        }
                        if let Some(ref pattern) = fa.regex {
                            match Regex::new(pattern) {
                                Ok(re) => {
                                    if !re.is_match(&contents) {
                                        failures.push(format!(
                                            "files: expected {} to match /{}/, but it did not",
                                            fa.path, pattern
                                        ));
                                    }
                                }
                                Err(e) => {
                                    failures.push(format!(
                                        "files: invalid regex /{}/ for {} — {}",
                                        pattern, fa.path, e
                                    ));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        failures.push(format!(
                            "files: could not read {} (root={}) — {}",
                            fa.path, fa.root, e
                        ));
                    }
                }
            }
        }
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
    use std::path::PathBuf;

    use super::*;
    use tempfile::TempDir;

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

    fn temp_dirs() -> (TempDir, PathBuf, PathBuf) {
        let tmp = TempDir::new().unwrap();
        let home = tmp.path().join("home");
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        (tmp, home, project)
    }

    #[test]
    fn test_check_allow_pass() {
        let (_tmp, home, project) = temp_dirs();
        let expect = Expectation {
            decision: Some("allow".into()),
            exit_code: Some(0),
            ..Default::default()
        };
        let result = HookResult {
            exit_code: 0,
            output: Some(make_allow_output()),
            stdout: String::new(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result, &home, &project);
        assert!(assertion.passed, "failures: {:?}", assertion.failures);
    }

    #[test]
    fn test_check_decision_mismatch() {
        let (_tmp, home, project) = temp_dirs();
        let expect = Expectation {
            decision: Some("allow".into()),
            ..Default::default()
        };
        let result = HookResult {
            exit_code: 0,
            output: Some(make_deny_output()),
            stdout: String::new(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result, &home, &project);
        assert!(!assertion.passed);
        assert!(assertion.failures[0].contains("expected \"allow\""));
    }

    #[test]
    fn test_check_no_decision_pass() {
        let (_tmp, home, project) = temp_dirs();
        let expect = Expectation {
            no_decision: Some(true),
            ..Default::default()
        };
        let result = HookResult {
            exit_code: 0,
            output: Some(make_continue_output()),
            stdout: String::new(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result, &home, &project);
        assert!(assertion.passed, "failures: {:?}", assertion.failures);
    }

    #[test]
    fn test_check_reason_contains() {
        let (_tmp, home, project) = temp_dirs();
        let expect = Expectation {
            reason_contains: Some("explicitly".into()),
            ..Default::default()
        };
        let result = HookResult {
            exit_code: 0,
            output: Some(make_allow_output()),
            stdout: String::new(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result, &home, &project);
        assert!(assertion.passed, "failures: {:?}", assertion.failures);
    }

    #[test]
    fn test_check_exit_code_mismatch() {
        let (_tmp, home, project) = temp_dirs();
        let expect = Expectation {
            exit_code: Some(0),
            ..Default::default()
        };
        let result = HookResult {
            exit_code: 2,
            output: None,
            stdout: String::new(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result, &home, &project);
        assert!(!assertion.passed);
        assert!(assertion.failures[0].contains("exit code"));
    }

    #[test]
    fn test_check_stdout_contains_pass() {
        let (_tmp, home, project) = temp_dirs();
        let expect = Expectation {
            stdout_contains: Some("allow".into()),
            ..Default::default()
        };
        let result = HookResult {
            exit_code: 0,
            output: None,
            stdout: "exe(\"git\").allow()".into(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result, &home, &project);
        assert!(assertion.passed, "failures: {:?}", assertion.failures);
    }

    #[test]
    fn test_check_stdout_contains_fail() {
        let (_tmp, home, project) = temp_dirs();
        let expect = Expectation {
            stdout_contains: Some("allow".into()),
            ..Default::default()
        };
        let result = HookResult {
            exit_code: 0,
            output: None,
            stdout: "exe(\"git\").deny()".into(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result, &home, &project);
        assert!(!assertion.passed);
        assert!(assertion.failures[0].contains("stdout_contains"));
    }

    #[test]
    fn test_check_stderr_contains() {
        let (_tmp, home, project) = temp_dirs();
        let expect = Expectation {
            stderr_contains: Some("warning".into()),
            ..Default::default()
        };
        let result = HookResult {
            exit_code: 0,
            output: None,
            stdout: String::new(),
            stderr: "warning: policy modified".into(),
        };

        let assertion = check(&expect, &result, &home, &project);
        assert!(assertion.passed, "failures: {:?}", assertion.failures);
    }

    #[test]
    fn test_check_stdout_regex_pass() {
        let (_tmp, home, project) = temp_dirs();
        let expect = Expectation {
            stdout_regex: Some(r"exe\(.*\)\.allow\(\)".into()),
            ..Default::default()
        };
        let result = HookResult {
            exit_code: 0,
            output: None,
            stdout: "exe(\"git\").allow()".into(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result, &home, &project);
        assert!(assertion.passed, "failures: {:?}", assertion.failures);
    }

    #[test]
    fn test_check_stdout_regex_fail() {
        let (_tmp, home, project) = temp_dirs();
        let expect = Expectation {
            stdout_regex: Some(r"^allow$".into()),
            ..Default::default()
        };
        let result = HookResult {
            exit_code: 0,
            output: None,
            stdout: "exe(\"git\").allow()".into(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result, &home, &project);
        assert!(!assertion.passed);
        assert!(assertion.failures[0].contains("stdout_regex"));
    }

    #[test]
    fn test_check_reason_regex_pass() {
        let (_tmp, home, project) = temp_dirs();
        let expect = Expectation {
            reason_regex: Some(r"explicitly\s+allowed".into()),
            ..Default::default()
        };
        let result = HookResult {
            exit_code: 0,
            output: Some(make_allow_output()),
            stdout: String::new(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result, &home, &project);
        assert!(assertion.passed, "failures: {:?}", assertion.failures);
    }

    #[test]
    fn test_check_file_exists() {
        let (_tmp, home, project) = temp_dirs();
        std::fs::write(home.join("test.txt"), "hello world").unwrap();

        let expect = Expectation {
            files: Some(vec![crate::script::FileAssertion {
                path: "test.txt".into(),
                root: "home".into(),
                exists: Some(true),
                contains: Some("hello".into()),
                regex: None,
            }]),
            ..Default::default()
        };
        let result = HookResult {
            exit_code: 0,
            output: None,
            stdout: String::new(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result, &home, &project);
        assert!(assertion.passed, "failures: {:?}", assertion.failures);
    }

    #[test]
    fn test_check_file_not_exists() {
        let (_tmp, home, project) = temp_dirs();

        let expect = Expectation {
            files: Some(vec![crate::script::FileAssertion {
                path: "missing.txt".into(),
                root: "home".into(),
                exists: Some(false),
                contains: None,
                regex: None,
            }]),
            ..Default::default()
        };
        let result = HookResult {
            exit_code: 0,
            output: None,
            stdout: String::new(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result, &home, &project);
        assert!(assertion.passed, "failures: {:?}", assertion.failures);
    }

    #[test]
    fn test_check_all_of() {
        let (_tmp, home, project) = temp_dirs();
        let expect = Expectation {
            all_of: Some(vec![
                Expectation {
                    exit_code: Some(0),
                    ..Default::default()
                },
                Expectation {
                    stdout_contains: Some("hello".into()),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        };
        let result = HookResult {
            exit_code: 0,
            output: None,
            stdout: "hello world".into(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result, &home, &project);
        assert!(assertion.passed, "failures: {:?}", assertion.failures);
    }

    #[test]
    fn test_check_any_of() {
        let (_tmp, home, project) = temp_dirs();
        let expect = Expectation {
            any_of: Some(vec![
                Expectation {
                    stdout_contains: Some("foo".into()),
                    ..Default::default()
                },
                Expectation {
                    stdout_contains: Some("hello".into()),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        };
        let result = HookResult {
            exit_code: 0,
            output: None,
            stdout: "hello world".into(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result, &home, &project);
        assert!(assertion.passed, "failures: {:?}", assertion.failures);
    }

    #[test]
    fn test_check_not() {
        let (_tmp, home, project) = temp_dirs();
        let expect = Expectation {
            not: Some(Box::new(Expectation {
                stdout_contains: Some("secret".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        let result = HookResult {
            exit_code: 0,
            output: None,
            stdout: "hello world".into(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result, &home, &project);
        assert!(assertion.passed, "failures: {:?}", assertion.failures);
    }

    #[test]
    fn test_check_not_fails_when_child_passes() {
        let (_tmp, home, project) = temp_dirs();
        let expect = Expectation {
            not: Some(Box::new(Expectation {
                stdout_contains: Some("hello".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        let result = HookResult {
            exit_code: 0,
            output: None,
            stdout: "hello world".into(),
            stderr: String::new(),
        };

        let assertion = check(&expect, &result, &home, &project);
        assert!(!assertion.passed);
        assert!(assertion.failures[0].contains("not:"));
    }
}
