//! Evaluation: DecisionTree × tool request → PolicyDecision.
//!
//! Maps Claude Code tool invocations to capability-level queries, then walks
//! the compiled rule lists to find the first matching rule.

use std::path::PathBuf;

use tracing::{debug, trace};

use crate::policy::ast::FsOp;
use crate::policy::decision_tree::{CompiledMatcher, CompiledRule, DecisionTree};
use crate::policy::ir::{DecisionTrace, PolicyDecision, RuleMatch, RuleSkip};

/// A capability-level query derived from a tool invocation.
#[derive(Debug)]
pub enum CapQuery {
    Exec { bin: String, args: Vec<String> },
    Fs { op: FsOp, path: String },
    Net { domain: String },
    Tool { name: String },
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
            let (bin, args) = parse_bash_bin_args(&parts);
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
            debug!(tool_name, "tool — using tool capability query");
            vec![CapQuery::Tool {
                name: tool_name.to_string(),
            }]
        }
    }
}

/// Resolve a possibly-relative path against cwd.
pub(crate) fn resolve_path(path: &str, cwd: &str) -> String {
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
pub(crate) fn extract_domain(url: &str) -> String {
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

/// Check whether a token looks like a shell environment variable assignment (`KEY=value`).
///
/// Matches the POSIX pattern: a name (letter/underscore followed by letters, digits, or
/// underscores) immediately followed by `=` and an optional value.
fn is_env_assignment(token: &str) -> bool {
    match token.find('=') {
        Some(0) | None => false,
        Some(pos) => {
            let name = &token[..pos];
            let mut chars = name.chars();
            match chars.next() {
                Some(c) if c.is_ascii_alphabetic() || c == '_' => {
                    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
                }
                _ => false,
            }
        }
    }
}

/// Extract the binary name and arguments from whitespace-split Bash command tokens,
/// skipping leading environment variable assignments (`VAR=value ...`), the `env`
/// utility, and transparent prefix commands (`time`, `nice`, etc.).
///
/// Transparent prefix commands are wrapper utilities that don't change the semantics
/// of the wrapped command (e.g. `time`, `nice`, `nohup`, `timeout`, `command`).
/// They are stripped so that policy rules evaluate against the real command:
///   `time git push origin main` → bin="git", args=["push", "origin", "main"]
///
/// Prefixes can be chained: `time nice -n 19 env FOO=bar cargo build` → bin="cargo".
///
/// Note: `env` flags (e.g. `env -i`, `env -u VAR`) are not handled — the flag would be
/// treated as the binary name, which fails safe to the default policy.
fn parse_bash_bin_args(parts: &[&str]) -> (String, Vec<String>) {
    let mut i = 0;

    loop {
        // Skip leading VAR=value assignments.
        while i < parts.len() && is_env_assignment(parts[i]) {
            i += 1;
        }

        // If the next token is "env", skip it and any further assignments.
        if i < parts.len() && parts[i] == "env" {
            i += 1;
            while i < parts.len() && is_env_assignment(parts[i]) {
                i += 1;
            }
            continue;
        }

        // Check for transparent prefix commands (time, nice, nohup, etc.).
        if i < parts.len()
            && let Some(skip) = transparent_prefix_skip(parts[i], parts.get(i + 1..).unwrap_or(&[]))
        {
            i += 1 + skip;
            continue;
        }

        break;
    }

    match parts.get(i) {
        Some(bin) => (
            bin.to_string(),
            parts[i + 1..].iter().map(|s| s.to_string()).collect(),
        ),
        None => (String::new(), vec![]),
    }
}

/// Check if `cmd` is a transparent prefix command and return how many tokens
/// after the command name to skip (its flags and required positional args).
///
/// Returns `None` if `cmd` is not a recognized transparent prefix.
fn transparent_prefix_skip(cmd: &str, rest: &[&str]) -> Option<usize> {
    match cmd {
        // time [-p] command — bash builtin / POSIX time
        // GNU time has -f, -o flags that take values; handled explicitly.
        "time" => Some(skip_flags(rest, &["-f", "-o"])),

        // command [-p] command — bash builtin, bypasses functions
        // -v and -V are query modes (print path/description), not execution.
        "command" => {
            if rest.first().is_some_and(|f| *f == "-v" || *f == "-V") {
                None
            } else {
                Some(skip_flags(rest, &[]))
            }
        }

        // nice [-n ADJUSTMENT] command
        "nice" => Some(skip_flags(rest, &["-n"])),

        // nohup command — no flags
        "nohup" => Some(0),

        // timeout [OPTIONS] DURATION command
        // -s/-k/--signal/--kill-after take value args, then a mandatory DURATION positional.
        "timeout" => {
            let flags = skip_flags(rest, &["-s", "-k", "--signal", "--kill-after"]);
            // Skip the mandatory DURATION positional argument after flags.
            if flags < rest.len() {
                Some(flags + 1)
            } else {
                Some(flags)
            }
        }

        _ => None,
    }
}

/// Skip flag tokens and their value arguments. Returns the number of tokens consumed.
///
/// Flags are tokens starting with `-`. Long flags with `=` (e.g. `--format=FMT`) are
/// self-contained (one token). Short flags listed in `value_flags` consume the next
/// token as their value (e.g. `-f FMT` → 2 tokens).
fn skip_flags(tokens: &[&str], value_flags: &[&str]) -> usize {
    let mut i = 0;
    while i < tokens.len() && tokens[i].starts_with('-') {
        let flag = tokens[i];
        i += 1;
        // Self-contained long flag (--flag=value): already consumed.
        if flag.contains('=') {
            continue;
        }
        // Check if this flag takes a separate value argument.
        if value_flags.contains(&flag) && i < tokens.len() {
            i += 1;
        }
    }
    i
}

impl DecisionTree {
    /// Evaluate a tool request against this decision tree.
    ///
    /// Returns a `PolicyDecision` with the effect (allow/deny/ask), a reason,
    /// a decision trace, and an optional sandbox policy.
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

        let mut sandbox_name: Option<String> = None;

        for query in &queries {
            let rules: &[CompiledRule] = match query {
                CapQuery::Exec { .. } => &self.exec_rules,
                CapQuery::Fs { .. } => &self.fs_rules,
                CapQuery::Net { .. } => &self.net_rules,
                CapQuery::Tool { .. } => &self.tool_rules,
            };

            for (idx, rule) in rules.iter().enumerate() {
                let matches = match (&rule.matcher, query) {
                    (CompiledMatcher::Exec(m), CapQuery::Exec { bin, args }) => {
                        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                        m.matches(bin, &arg_refs)
                    }
                    (CompiledMatcher::Fs(m), CapQuery::Fs { op, path }) => m.matches(*op, path),
                    (CompiledMatcher::Net(m), CapQuery::Net { domain }) => m.matches(domain),
                    (CompiledMatcher::Tool(m), CapQuery::Tool { name }) => m.matches(name),
                    _ => false,
                };

                let mut description = rule.source.to_string();
                if let Some(ref sb_name) = rule.sandbox {
                    description.push_str(&format!(" [sandbox: {sb_name}]"));
                }
                if matches {
                    trace!(idx, %description, effect = %rule.effect, "rule matched");
                    // Capture sandbox reference from matching exec rule.
                    if rule.sandbox.is_some() && sandbox_name.is_none() {
                        sandbox_name.clone_from(&rule.sandbox);
                    }
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

        // Build sandbox policy if the final effect is Allow.
        // 1. If the matching exec rule references an explicit `:sandbox`, use it.
        // 2. Otherwise, build an implicit sandbox from the policy's own fs/net
        //    rules — ensuring bash commands respect the same filesystem
        //    restrictions as tool-level operations.
        let sandbox = if effect == crate::policy::Effect::Allow {
            sandbox_name
                .and_then(|name| self.build_sandbox_policy(&name, cwd))
                .or_else(|| self.build_implicit_sandbox())
        } else {
            None
        };

        PolicyDecision {
            effect,
            reason,
            trace: DecisionTrace {
                matched_rules,
                skipped_rules,
                final_resolution,
            },
            sandbox,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use crate::policy::Effect;
    use crate::policy::compile::{EnvResolver, compile_policy_with_env};
    use crate::policy::sandbox_types::NetworkPolicy;

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

    fn compile(source: &str) -> crate::policy::decision_tree::DecisionTree {
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        compile_policy_with_env(source, &env).unwrap()
    }

    #[test]
    fn bash_git_push_denied() {
        let tree = compile(
            r#"
(default deny "main")
(policy "main"
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
(default deny "main")
(policy "main"
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
(default deny "main")
(policy "main"
  (allow (fs read (subpath (env PWD)))))
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
(default deny "main")
(policy "main"
  (allow (fs read (subpath (env PWD)))))
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
(default deny "main")
(policy "main"
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
(default deny "main")
(policy "main"
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
(default ask "main")
(policy "main"
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
(default deny "main")
(policy "main"
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
(default deny "main")
(policy "main"
  (allow (fs write (subpath (env PWD)))))
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
(default deny "main")
(policy "main"
  (allow (fs write (subpath (env PWD)))))
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
(default deny "main")
(policy "main"
  (allow (fs read (subpath (env PWD)))))
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
(default deny "main")

(policy "cwd-access"
  (allow (fs read (subpath (env PWD)))))

(policy "main"
  (include "cwd-access")

  (deny  (exec "git" "push" *))
  (deny  (exec "git" "reset" *))
  (ask   (exec "git" "commit" *))
  (allow (exec "git" *))

  (allow (fs (or read write) (subpath (env PWD))))
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
        // Read in PWD → allow
        assert_eq!(
            tree.evaluate(
                "Read",
                &json!({"file_path": "/home/user/project/Cargo.toml"}),
                "/home/user/project"
            )
            .effect,
            Effect::Allow
        );
        // Read outside PWD → deny
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

    #[test]
    fn exec_with_sandbox_trace() {
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_policy_with_env(
            r#"
(default deny "main")
(policy "cargo-env"
  (allow (fs read (subpath (env PWD)))))
(policy "main"
  (allow (exec "cargo" *) :sandbox "cargo-env"))
"#,
            &env,
        )
        .unwrap();

        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "cargo build"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Allow);
        assert!(
            decision.trace.matched_rules[0]
                .description
                .contains("[sandbox: cargo-env]"),
            "trace should mention sandbox: {}",
            decision.trace.matched_rules[0].description
        );
    }

    #[test]
    fn exec_with_sandbox_produces_sandbox_policy() {
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_policy_with_env(
            r#"
(default deny "main")
(policy "cargo-env"
  (allow (fs read (subpath (env PWD)))))
(policy "main"
  (allow (exec "cargo" *) :sandbox "cargo-env"))
"#,
            &env,
        )
        .unwrap();

        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "cargo build"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Allow);
        let sandbox = decision.sandbox.expect("sandbox should be present");
        let auto_count = crate::policy::decision_tree::DecisionTree::temp_directory_paths().len()
            + crate::policy::decision_tree::DecisionTree::git_worktree_paths().len();
        assert_eq!(sandbox.rules.len(), 1 + auto_count);
        assert_eq!(sandbox.rules[0].path, "/home/user/project");
        assert_eq!(
            sandbox.rules[0].path_match,
            crate::policy::sandbox_types::PathMatch::Subpath
        );
        assert_eq!(
            sandbox.rules[0].caps,
            crate::policy::sandbox_types::Cap::READ
        );
        assert_eq!(
            sandbox.rules[0].effect,
            crate::policy::sandbox_types::RuleEffect::Allow
        );
    }

    #[test]
    fn sandbox_network_defaults_to_deny() {
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_policy_with_env(
            r#"
(default deny "main")
(policy "restricted"
  (allow (fs read (subpath (env PWD)))))
(policy "main"
  (allow (exec "cargo" *) :sandbox "restricted"))
"#,
            &env,
        )
        .unwrap();

        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "cargo build"}),
            "/home/user/project",
        );
        let sandbox = decision.sandbox.expect("sandbox should be present");
        assert_eq!(
            sandbox.network,
            crate::policy::sandbox_types::NetworkPolicy::Deny
        );
    }

    #[test]
    fn sandbox_with_domain_specific_net_denies_network() {
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_policy_with_env(
            r#"
(default deny "main")
(policy "with-net"
  (allow (fs read (subpath (env PWD))))
  (allow (net "crates.io")))
(policy "main"
  (allow (exec "cargo" *) :sandbox "with-net"))
"#,
            &env,
        )
        .unwrap();

        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "cargo build"}),
            "/home/user/project",
        );
        let sandbox = decision.sandbox.expect("sandbox should be present");
        // Domain-specific net rules produce AllowDomains for proxy-based filtering
        assert_eq!(
            sandbox.network,
            crate::policy::sandbox_types::NetworkPolicy::AllowDomains(vec!["crates.io".into()])
        );
    }

    #[test]
    fn sandbox_net_only_domain_specific_denies_network() {
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_policy_with_env(
            r#"
(default deny "main")
(policy "net-only"
  (allow (net "crates.io")))
(policy "main"
  (allow (exec "cargo" *) :sandbox "net-only"))
"#,
            &env,
        )
        .unwrap();

        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "cargo build"}),
            "/home/user/project",
        );
        let sandbox = decision
            .sandbox
            .expect("net-only sandbox should be present");
        // Domain-specific net rules produce AllowDomains for proxy-based filtering
        assert_eq!(
            sandbox.network,
            NetworkPolicy::AllowDomains(vec!["crates.io".into()])
        );
        // Only temp directory rules (no explicit fs rules in this sandbox)
        let auto_count = crate::policy::decision_tree::DecisionTree::temp_directory_paths().len()
            + crate::policy::decision_tree::DecisionTree::git_worktree_paths().len();
        assert_eq!(sandbox.rules.len(), auto_count);
    }

    #[test]
    fn inline_sandbox_produces_sandbox_policy() {
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_policy_with_env(
            r#"
(default deny "main")
(policy "main"
  (allow (exec "clash" "bug" *) :sandbox (allow (net *))))
"#,
            &env,
        )
        .unwrap();

        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "clash bug test"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Allow);
        let sandbox = decision
            .sandbox
            .expect("inline sandbox should produce SandboxPolicy");
        assert_eq!(sandbox.network, NetworkPolicy::Allow);
        // Only temp directory rules (no explicit fs rules in this sandbox)
        let auto_count = crate::policy::decision_tree::DecisionTree::temp_directory_paths().len()
            + crate::policy::decision_tree::DecisionTree::git_worktree_paths().len();
        assert_eq!(sandbox.rules.len(), auto_count);
    }

    #[test]
    fn sandbox_denied_exec_has_no_sandbox() {
        let env = TestEnv::new(&[("PWD", "/home/user/project")]);
        let tree = compile_policy_with_env(
            r#"
(default deny "main")
(policy "cargo-env"
  (allow (fs read (subpath (env PWD)))))
(policy "main"
  (deny  (exec "cargo" "publish" *))
  (allow (exec "cargo" *) :sandbox "cargo-env"))
"#,
            &env,
        )
        .unwrap();

        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "cargo publish"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Deny);
        assert!(
            decision.sandbox.is_none(),
            "denied exec should not produce sandbox"
        );
    }

    #[test]
    fn is_env_assignment_valid() {
        assert!(super::is_env_assignment("FOO=bar"));
        assert!(super::is_env_assignment("_VAR=123"));
        assert!(super::is_env_assignment("A="));
        assert!(super::is_env_assignment("MY_VAR_2=some=value"));
    }

    #[test]
    fn is_env_assignment_invalid() {
        assert!(!super::is_env_assignment("cargo"));
        assert!(!super::is_env_assignment("=foo"));
        assert!(!super::is_env_assignment("123=bar"));
        assert!(!super::is_env_assignment(""));
        assert!(!super::is_env_assignment("git"));
    }

    #[test]
    fn parse_bash_bin_args_no_env() {
        let parts = vec!["cargo", "build", "--release"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "cargo");
        assert_eq!(args, vec!["build", "--release"]);
    }

    #[test]
    fn parse_bash_bin_args_single_env() {
        let parts = vec!["SOME_ENV=foo", "cargo", "check"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "cargo");
        assert_eq!(args, vec!["check"]);
    }

    #[test]
    fn parse_bash_bin_args_multiple_env() {
        let parts = vec!["A=1", "B=2", "C=3", "cargo", "build"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "cargo");
        assert_eq!(args, vec!["build"]);
    }

    #[test]
    fn parse_bash_bin_args_env_utility() {
        let parts = vec!["env", "FOO=bar", "cargo", "test"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "cargo");
        assert_eq!(args, vec!["test"]);
    }

    #[test]
    fn parse_bash_bin_args_env_utility_no_vars() {
        let parts = vec!["env", "cargo", "test"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "cargo");
        assert_eq!(args, vec!["test"]);
    }

    #[test]
    fn parse_bash_bin_args_only_env_vars() {
        let parts = vec!["FOO=bar", "BAZ=qux"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "");
        assert!(args.is_empty());
    }

    #[test]
    fn parse_bash_bin_args_empty() {
        let parts: Vec<&str> = vec![];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "");
        assert!(args.is_empty());
    }

    #[test]
    fn bash_env_var_prefix_recognized() {
        let tree = compile(
            r#"
(default deny "main")
(policy "main"
  (allow (exec "cargo" *)))
"#,
        );

        // Single env var prefix
        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "SOME_ENV=foo cargo check"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Allow);
    }

    #[test]
    fn bash_multiple_env_var_prefixes() {
        let tree = compile(
            r#"
(default deny "main")
(policy "main"
  (allow (exec "cargo" *)))
"#,
        );

        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "RUST_LOG=debug TERM=xterm cargo build"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Allow);
    }

    #[test]
    fn bash_env_utility_prefix() {
        let tree = compile(
            r#"
(default deny "main")
(policy "main"
  (allow (exec "cargo" *)))
"#,
        );

        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "env RUST_BACKTRACE=1 cargo test"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Allow);
    }

    #[test]
    fn bash_env_prefix_deny_still_works() {
        let tree = compile(
            r#"
(default deny "main")
(policy "main"
  (deny  (exec "git" "push" *))
  (allow (exec "git" *)))
"#,
        );

        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "GIT_SSH_COMMAND=ssh git push origin main"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Deny);
    }

    // ── Transparent prefix: unit tests ────────────────────────────────

    #[test]
    fn transparent_time_no_flags() {
        let parts = vec!["time", "cargo", "build"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "cargo");
        assert_eq!(args, vec!["build"]);
    }

    #[test]
    fn transparent_time_with_flag() {
        let parts = vec!["time", "-p", "cargo", "build"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "cargo");
        assert_eq!(args, vec!["build"]);
    }

    #[test]
    fn transparent_time_with_value_flag() {
        // GNU time: -o takes a filename argument
        let parts = vec!["time", "-o", "/tmp/timing.txt", "cargo", "build"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "cargo");
        assert_eq!(args, vec!["build"]);
    }

    #[test]
    fn transparent_command_no_flags() {
        let parts = vec!["command", "git", "status"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "git");
        assert_eq!(args, vec!["status"]);
    }

    #[test]
    fn transparent_command_with_p_flag() {
        let parts = vec!["command", "-p", "git", "status"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "git");
        assert_eq!(args, vec!["status"]);
    }

    #[test]
    fn transparent_command_v_is_not_prefix() {
        // command -v is a query mode, not execution — should NOT be stripped
        let parts = vec!["command", "-v", "git"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "command");
        assert_eq!(args, vec!["-v", "git"]);
    }

    #[test]
    fn transparent_command_capital_v_is_not_prefix() {
        let parts = vec!["command", "-V", "git"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "command");
        assert_eq!(args, vec!["-V", "git"]);
    }

    #[test]
    fn transparent_nice_with_n_flag() {
        let parts = vec!["nice", "-n", "10", "cargo", "build"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "cargo");
        assert_eq!(args, vec!["build"]);
    }

    #[test]
    fn transparent_nice_no_flags() {
        let parts = vec!["nice", "cargo", "build"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "cargo");
        assert_eq!(args, vec!["build"]);
    }

    #[test]
    fn transparent_nohup() {
        let parts = vec!["nohup", "./script.sh", "&"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "./script.sh");
        assert_eq!(args, vec!["&"]);
    }

    #[test]
    fn transparent_timeout_simple() {
        let parts = vec!["timeout", "30s", "cargo", "build"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "cargo");
        assert_eq!(args, vec!["build"]);
    }

    #[test]
    fn transparent_timeout_with_signal_flag() {
        let parts = vec!["timeout", "-s", "KILL", "30s", "cargo", "build"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "cargo");
        assert_eq!(args, vec!["build"]);
    }

    #[test]
    fn transparent_timeout_with_multiple_flags() {
        let parts = vec![
            "timeout",
            "--preserve-status",
            "-k",
            "5s",
            "30s",
            "cargo",
            "build",
        ];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "cargo");
        assert_eq!(args, vec!["build"]);
    }

    // ── Transparent prefix: chaining ──────────────────────────────────

    #[test]
    fn transparent_chained_time_nice() {
        let parts = vec!["time", "nice", "-n", "19", "cargo", "build"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "cargo");
        assert_eq!(args, vec!["build"]);
    }

    #[test]
    fn transparent_chained_with_env() {
        let parts = vec!["time", "env", "FOO=bar", "cargo", "build"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "cargo");
        assert_eq!(args, vec!["build"]);
    }

    #[test]
    fn transparent_chained_env_time() {
        // env vars → env utility → time → real command
        let parts = vec!["RUST_LOG=debug", "env", "FOO=bar", "time", "cargo", "test"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "cargo");
        assert_eq!(args, vec!["test"]);
    }

    #[test]
    fn transparent_chained_time_nohup() {
        let parts = vec!["time", "nohup", "cargo", "build"];
        let (bin, args) = super::parse_bash_bin_args(&parts);
        assert_eq!(bin, "cargo");
        assert_eq!(args, vec!["build"]);
    }

    // ── Transparent prefix: policy integration ────────────────────────

    #[test]
    fn transparent_time_preserves_deny() {
        let tree = compile(
            r#"
(default deny "main")
(policy "main"
  (deny  (exec "git" "push" *))
  (allow (exec "git" *)))
"#,
        );

        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "time git push origin main"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn transparent_time_preserves_allow() {
        let tree = compile(
            r#"
(default deny "main")
(policy "main"
  (deny  (exec "git" "push" *))
  (allow (exec "git" *)))
"#,
        );

        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "time git status"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Allow);
    }

    #[test]
    fn transparent_nice_preserves_deny() {
        let tree = compile(
            r#"
(default deny "main")
(policy "main"
  (deny  (exec "git" "push" *))
  (allow (exec "git" *)))
"#,
        );

        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "nice -n 10 git push origin main"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn transparent_nohup_preserves_deny() {
        let tree = compile(
            r#"
(default deny "main")
(policy "main"
  (deny  (exec "git" "push" *))
  (allow (exec "git" *)))
"#,
        );

        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "nohup git push origin main"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn transparent_timeout_preserves_deny() {
        let tree = compile(
            r#"
(default deny "main")
(policy "main"
  (deny  (exec "git" "push" *))
  (allow (exec "git" *)))
"#,
        );

        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "timeout 30 git push origin main"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn transparent_chained_preserves_deny() {
        let tree = compile(
            r#"
(default deny "main")
(policy "main"
  (deny  (exec "git" "push" *))
  (allow (exec "git" *)))
"#,
        );

        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "time nice -n 19 git push origin main"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn transparent_prefix_with_env_preserves_deny() {
        let tree = compile(
            r#"
(default deny "main")
(policy "main"
  (deny  (exec "git" "push" *))
  (allow (exec "git" *)))
"#,
        );

        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "time env GIT_SSH=ssh git push origin main"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Deny);
    }

    #[test]
    fn transparent_command_v_falls_through_to_default() {
        let tree = compile(
            r#"
(default deny "main")
(policy "main"
  (allow (exec "git" *)))
"#,
        );

        // command -v is a query, not transparent — evaluates as bin="command"
        let decision = tree.evaluate(
            "Bash",
            &json!({"command": "command -v git"}),
            "/home/user/project",
        );
        assert_eq!(decision.effect, Effect::Deny);
    }

    // ── skip_flags unit tests ─────────────────────────────────────────

    #[test]
    fn skip_flags_no_flags() {
        assert_eq!(super::skip_flags(&["cargo", "build"], &[]), 0);
    }

    #[test]
    fn skip_flags_simple_flags() {
        assert_eq!(super::skip_flags(&["-p", "-v", "cargo"], &[]), 2);
    }

    #[test]
    fn skip_flags_with_value() {
        assert_eq!(super::skip_flags(&["-f", "fmt", "cargo"], &["-f"]), 2);
    }

    #[test]
    fn skip_flags_long_with_equals() {
        assert_eq!(
            super::skip_flags(&["--format=fmt", "cargo"], &["--format"]),
            1
        );
    }

    #[test]
    fn skip_flags_double_dash_separator() {
        // -- starts with - so it's consumed as a flag, correctly stopping before the command
        assert_eq!(super::skip_flags(&["--", "cargo"], &[]), 1);
    }

    // ── transparent_prefix_skip unit tests ────────────────────────────

    #[test]
    fn prefix_skip_unknown_command() {
        assert_eq!(super::transparent_prefix_skip("cargo", &["build"]), None);
    }

    #[test]
    fn prefix_skip_time_no_args() {
        assert_eq!(super::transparent_prefix_skip("time", &[]), Some(0));
    }

    #[test]
    fn prefix_skip_timeout_duration() {
        assert_eq!(
            super::transparent_prefix_skip("timeout", &["30s", "cargo"]),
            Some(1)
        );
    }

    #[test]
    fn prefix_skip_timeout_flags_and_duration() {
        assert_eq!(
            super::transparent_prefix_skip("timeout", &["-s", "KILL", "30s", "cargo"]),
            Some(3)
        );
    }
}
