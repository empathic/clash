//! Evaluation: DecisionTree × tool request → PolicyDecision.
//!
//! Maps Claude Code tool invocations to capability-level queries, then walks
//! the compiled rule lists to find the first matching rule.

use std::path::PathBuf;

use tracing::{debug, trace};

use crate::policy::ir::{DecisionTrace, PolicyDecision, RuleMatch, RuleSkip};
use crate::policy::v2::ast::FsOp;
use crate::policy::v2::ir::{CompiledMatcher, CompiledRule, DecisionTree};

/// A capability-level query derived from a tool invocation.
#[derive(Debug)]
pub enum CapQuery {
    Exec { bin: String, args: Vec<String> },
    Fs { op: FsOp, path: String },
    Net { domain: String },
}

/// Map a tool invocation to capability queries.
///
/// Each tool maps to one or more capability domains (exec/fs/net).
/// Unknown tools produce an empty query list, falling through to the default.
pub fn tool_to_queries(
    tool_name: &str,
    tool_input: &serde_json::Value,
    cwd: &str,
) -> Vec<CapQuery> {
    match tool_name {
        "Bash" => {
            let command = tool_input
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let parts: Vec<&str> = command.split_whitespace().collect();
            let (bin, args) = match parts.split_first() {
                Some((b, rest)) => (b.to_string(), rest.iter().map(|s| s.to_string()).collect()),
                None => (String::new(), vec![]),
            };
            vec![CapQuery::Exec { bin, args }]
        }
        "Read" => {
            let path = tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            vec![CapQuery::Fs {
                op: FsOp::Read,
                path: resolve_path(path, cwd),
            }]
        }
        "Write" => {
            let path = tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            vec![CapQuery::Fs {
                op: FsOp::Write,
                path: resolve_path(path, cwd),
            }]
        }
        "Edit" => {
            let path = tool_input
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            vec![CapQuery::Fs {
                op: FsOp::Write,
                path: resolve_path(path, cwd),
            }]
        }
        "WebFetch" => {
            let url = tool_input.get("url").and_then(|v| v.as_str()).unwrap_or("");
            let domain = extract_domain(url);
            vec![CapQuery::Net { domain }]
        }
        "WebSearch" => {
            // WebSearch can hit any domain — match as wildcard.
            vec![CapQuery::Net {
                domain: "*".to_string(),
            }]
        }
        "Glob" | "Grep" => {
            // Use the `path` field, falling back to `pattern` for Glob.
            let path = tool_input
                .get("path")
                .and_then(|v| v.as_str())
                .or_else(|| tool_input.get("pattern").and_then(|v| v.as_str()))
                .unwrap_or("");
            vec![CapQuery::Fs {
                op: FsOp::Read,
                path: resolve_path(path, cwd),
            }]
        }
        _ => {
            debug!(
                tool_name,
                "unknown tool — no capability query, using default"
            );
            vec![]
        }
    }
}

/// Resolve a possibly-relative path against cwd.
fn resolve_path(path: &str, cwd: &str) -> String {
    if path.is_empty() {
        return cwd.to_string();
    }
    let p = PathBuf::from(path);
    if p.is_absolute() {
        path.to_string()
    } else {
        let mut base = PathBuf::from(cwd);
        base.push(path);
        base.to_string_lossy().to_string()
    }
}

/// Extract the domain from a URL string.
///
/// Simple extraction: strip scheme, take host portion before first `/` or `:`.
fn extract_domain(url: &str) -> String {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    without_scheme
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string()
}

impl DecisionTree {
    /// Evaluate a tool request against this decision tree.
    ///
    /// Returns a `PolicyDecision` with the effect (allow/deny/ask), a reason,
    /// a decision trace, and no sandbox (v2 sandbox is a future PR).
    pub fn evaluate(
        &self,
        tool_name: &str,
        tool_input: &serde_json::Value,
        cwd: &str,
    ) -> PolicyDecision {
        let queries = tool_to_queries(tool_name, tool_input, cwd);
        debug!(
            tool_name,
            query_count = queries.len(),
            "evaluating tool request"
        );

        let mut matched_rules = Vec::new();
        let mut skipped_rules = Vec::new();

        // No queries means unknown tool — skip straight to default.
        if queries.is_empty() {
            return PolicyDecision {
                effect: self.default,
                reason: None,
                trace: DecisionTrace {
                    matched_rules: vec![],
                    skipped_rules: vec![],
                    final_resolution: format!(
                        "no capability query for tool '{}', default: {}",
                        tool_name, self.default
                    ),
                },
                sandbox: None,
            };
        }

        for query in &queries {
            let rules: &[CompiledRule] = match query {
                CapQuery::Exec { .. } => &self.exec_rules,
                CapQuery::Fs { .. } => &self.fs_rules,
                CapQuery::Net { .. } => &self.net_rules,
            };

            for (idx, rule) in rules.iter().enumerate() {
                let matches = match (&rule.matcher, query) {
                    (CompiledMatcher::Exec(m), CapQuery::Exec { bin, args }) => {
                        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                        m.matches(bin, &arg_refs)
                    }
                    (CompiledMatcher::Fs(m), CapQuery::Fs { op, path }) => m.matches(*op, path),
                    (CompiledMatcher::Net(m), CapQuery::Net { domain }) => m.matches(domain),
                    _ => false,
                };

                let description = rule.source.to_string();
                if matches {
                    trace!(idx, %description, effect = %rule.effect, "rule matched");
                    matched_rules.push(RuleMatch {
                        rule_index: idx,
                        description,
                        effect: rule.effect,
                        has_active_constraints: false,
                    });
                    // First match wins within a capability domain (rules are
                    // sorted by specificity, most specific first).
                    break;
                } else {
                    skipped_rules.push(RuleSkip {
                        rule_index: idx,
                        description,
                        reason: "pattern mismatch".to_string(),
                    });
                }
            }
        }

        // Determine final effect.
        if matched_rules.is_empty() {
            return PolicyDecision {
                effect: self.default,
                reason: None,
                trace: DecisionTrace {
                    matched_rules,
                    skipped_rules,
                    final_resolution: format!("no rules matched, default: {}", self.default),
                },
                sandbox: None,
            };
        }

        // Use deny-overrides: deny > ask > allow.
        let effect = matched_rules
            .iter()
            .map(|m| m.effect)
            .reduce(|acc, e| match (acc, e) {
                (crate::policy::Effect::Deny, _) | (_, crate::policy::Effect::Deny) => {
                    crate::policy::Effect::Deny
                }
                (crate::policy::Effect::Ask, _) | (_, crate::policy::Effect::Ask) => {
                    crate::policy::Effect::Ask
                }
                _ => crate::policy::Effect::Allow,
            })
            .unwrap_or(self.default);

        let reason =
            if effect == crate::policy::Effect::Deny || effect == crate::policy::Effect::Ask {
                matched_rules
                    .iter()
                    .find(|m| m.effect == effect)
                    .map(|m| m.description.clone())
            } else {
                None
            };

        let final_resolution = if matched_rules.len() == 1 {
            format!("result: {}", effect)
        } else {
            let effects: Vec<String> = matched_rules.iter().map(|m| m.effect.to_string()).collect();
            format!("resolved {} from [{}]", effect, effects.join(", "))
        };

        PolicyDecision {
            effect,
            reason,
            trace: DecisionTrace {
                matched_rules,
                skipped_rules,
                final_resolution,
            },
            sandbox: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use crate::policy::Effect;
    use crate::policy::v2::compile::{EnvResolver, compile_policy_with_env};

    /// Test env resolver with fixed values.
    struct TestEnv(HashMap<String, String>);

    impl TestEnv {
        fn new(pairs: &[(&str, &str)]) -> Self {
            Self(
                pairs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            )
        }
    }

    impl EnvResolver for TestEnv {
        fn resolve(&self, name: &str) -> anyhow::Result<String> {
            self.0
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("not set: {name}"))
        }
    }

    fn compile(source: &str) -> crate::policy::v2::ir::DecisionTree {
        let env = TestEnv::new(&[("CWD", "/home/user/project")]);
        compile_policy_with_env(source, &env).unwrap()
    }

    #[test]
    fn bash_git_push_denied() {
        let tree = compile(
            r#"
(default deny main)
(policy main
  (deny  (exec "git" "push" *))
  (allow (exec "git" *)))
"#,
        );

        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "git push origin main"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn bash_git_status_allowed() {
        let tree = compile(
            r#"
(default deny main)
(policy main
  (deny  (exec "git" "push" *))
  (allow (exec "git" *)))
"#,
        );

        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "git status"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Allow);
    }

    #[test]
    fn read_under_cwd_allowed() {
        let tree = compile(
            r#"
(default deny main)
(policy main
  (allow (fs read (subpath (env CWD)))))
"#,
        );

        let decision = tree.evaluate(
            "Read",
            &json!({"file_path": "/home/user/project/src/main.rs"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Allow);
    }

    #[test]
    fn read_outside_cwd_default_deny() {
        let tree = compile(
            r#"
(default deny main)
(policy main
  (allow (fs read (subpath (env CWD)))))
"#,
        );

        let decision = tree.evaluate(
            "Read",
            &json!({"file_path": "/etc/passwd"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn webfetch_allowed_domain() {
        let tree = compile(
            r#"
(default deny main)
(policy main
  (allow (net (or "github.com" "crates.io")))
  (deny  (net /.*\.evil\.com/)))
"#,
        );

        let decision = tree.evaluate(
            "WebFetch",
            &json!({"url": "https://github.com/foo/bar"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Allow);
    }

    #[test]
    fn webfetch_evil_domain_denied() {
        let tree = compile(
            r#"
(default deny main)
(policy main
  (allow (net (or "github.com" "crates.io")))
  (deny  (net /.*\.evil\.com/)))
"#,
        );

        let decision = tree.evaluate(
            "WebFetch",
            &json!({"url": "https://malware.evil.com/payload"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn unknown_tool_uses_default() {
        let tree = compile(
            r#"
(default ask main)
(policy main
  (allow (exec "git" *)))
"#,
        );

        let decision = tree.evaluate(
            "SomeUnknownTool",
            &json!({"foo": "bar"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Ask);
    }

    #[test]
    fn decision_trace_contains_matched_rule() {
        let tree = compile(
            r#"
(default deny main)
(policy main
  (deny  (exec "git" "push" *))
  (allow (exec "git" *)))
"#,
        );

        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "git status"}),
            "/home/user/project",
        );
        assert_eq!(decision.trace.matched_rules.len(), 1);
        assert!(decision.trace.matched_rules[0].description.contains("git"));
    }

    #[test]
    fn write_tool_maps_to_fs_write() {
        let tree = compile(
            r#"
(default deny main)
(policy main
  (allow (fs write (subpath (env CWD)))))
"#,
        );

        let decision = tree.evaluate(
            "Write",
            &json!({"file_path": "/home/user/project/output.txt"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Allow);
    }

    #[test]
    fn edit_tool_maps_to_fs_write() {
        let tree = compile(
            r#"
(default deny main)
(policy main
  (allow (fs write (subpath (env CWD)))))
"#,
        );

        let decision = tree.evaluate(
            "Edit",
            &json!({"file_path": "/home/user/project/src/lib.rs"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Allow);
    }

    #[test]
    fn relative_path_resolved_against_cwd() {
        let tree = compile(
            r#"
(default deny main)
(policy main
  (allow (fs read (subpath (env CWD)))))
"#,
        );

        let decision = tree.evaluate(
            "Read",
            &json!({"file_path": "src/main.rs"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Allow);
    }

    #[test]
    fn full_pipeline_integration() {
        let tree = compile(
            r#"
(default deny main)

(policy cwd-access
  (allow (fs read (subpath (env CWD)))))

(policy main
  (include cwd-access)

  (deny  (exec "git" "push" *))
  (deny  (exec "git" "reset" *))
  (ask   (exec "git" "commit" *))
  (allow (exec "git" *))

  (allow (fs (or read write) (subpath (env CWD))))
  (deny  (fs write ".env"))

  (allow (net (or "github.com" "crates.io")))
  (deny  (net /.*\.evil\.com/)))
"#,
        );

        // git push → deny
        assert_eq!(
            tree.evaluate(
                "Bash",
                &json!({"command": "git push origin main"}),
                "/home/user/project"
            )
            .effect,
            Effect::Deny
        );
        // git status → allow
        assert_eq!(
            tree.evaluate(
                "Bash",
                &json!({"command": "git status"}),
                "/home/user/project"
            )
            .effect,
            Effect::Allow
        );
        // git commit → ask
        assert_eq!(
            tree.evaluate(
                "Bash",
                &json!({"command": "git commit -m fix"}),
                "/home/user/project"
            )
            .effect,
            Effect::Ask
        );
        // Read in CWD → allow
        assert_eq!(
            tree.evaluate(
                "Read",
                &json!({"file_path": "/home/user/project/Cargo.toml"}),
                "/home/user/project"
            )
            .effect,
            Effect::Allow
        );
        // Read outside CWD → deny
        assert_eq!(
            tree.evaluate(
                "Read",
                &json!({"file_path": "/etc/shadow"}),
                "/home/user/project"
            )
            .effect,
            Effect::Deny
        );
        // WebFetch github.com → allow
        assert_eq!(
            tree.evaluate(
                "WebFetch",
                &json!({"url": "https://github.com/foo"}),
                "/home/user/project"
            )
            .effect,
            Effect::Allow
        );
        // WebFetch evil.com → deny
        assert_eq!(
            tree.evaluate(
                "WebFetch",
                &json!({"url": "https://x.evil.com/bad"}),
                "/home/user/project"
            )
            .effect,
            Effect::Deny
        );
        // Unknown tool → default deny
        assert_eq!(
            tree.evaluate("MagicTool", &json!({}), "/home/user/project")
                .effect,
            Effect::Deny
        );
    }
}
