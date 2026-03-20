//! Generate clester YAML test scripts from a compiled policy.
//!
//! Walks the match tree, synthesises tool invocations that exercise every
//! rule, and emits a valid clester test script.

use std::path::Path;

use anyhow::{Context, Result};

use crate::policy::format::{format_condition, format_decision};
use crate::policy::match_tree::{CompiledPolicy, Decision, Node, Observable, Pattern, Value};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run the `clash policy test-gen` command.
pub fn run(file: &Path, output: Option<&Path>) -> Result<()> {
    let source = crate::settings::evaluate_policy_file(file)
        .with_context(|| format!("failed to evaluate policy: {}", file.display()))?;

    let policy = crate::policy::compile::compile_to_tree(&source)
        .with_context(|| format!("failed to compile policy: {}", file.display()))?;

    let star_source = if file.extension().is_some_and(|ext| ext == "star") {
        std::fs::read_to_string(file)
            .with_context(|| format!("failed to read: {}", file.display()))?
    } else {
        // For JSON policies we embed the compiled JSON directly via policy_raw
        source.clone()
    };

    let steps = generate_steps(&policy);

    if steps.is_empty() {
        println!("No rules found in the policy — nothing to generate.");
        return Ok(());
    }

    let yaml = render_yaml(&star_source, file, &steps, &policy);

    match output {
        Some(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create directory: {}", parent.display()))?;
            }
            std::fs::write(path, &yaml)
                .with_context(|| format!("failed to write: {}", path.display()))?;
            println!(
                "Generated {} test steps \u{2192} {}",
                steps.len(),
                path.display()
            );
        }
        None => {
            print!("{yaml}");
        }
    }

    for step in &steps {
        println!(
            "  - {} \u{2192} expect {} ({})",
            step.name, step.expected_decision, step.rule_description
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Step representation
// ---------------------------------------------------------------------------

/// A generated test step.
struct TestStep {
    /// Human-readable step name.
    name: String,
    /// Tool name (e.g. "Bash", "Read").
    tool_name: String,
    /// Tool input fields as (key, value) pairs.
    tool_input: Vec<(String, String)>,
    /// Expected decision: "allow", "deny", or "ask".
    expected_decision: String,
    /// Description of the rule this step exercises.
    rule_description: String,
}

// ---------------------------------------------------------------------------
// Step generation
// ---------------------------------------------------------------------------

/// Generate test steps from a compiled policy.
fn generate_steps(policy: &CompiledPolicy) -> Vec<TestStep> {
    let mut steps = Vec::new();

    for node in &policy.tree {
        walk_node(node, &mut Vec::new(), &mut steps);
    }

    // Add a default-effect test with an unmatched input.
    steps.push(TestStep {
        name: "unmatched command falls through to default".into(),
        tool_name: "Bash".into(),
        tool_input: vec![("command".into(), "__clash_unmatched_test_cmd".into())],
        expected_decision: policy.default_effect.to_string(),
        rule_description: format!("default: {}", policy.default_effect),
    });

    steps
}

/// Walk a node tree, accumulating the observation context and emitting steps
/// at each leaf decision.
fn walk_node(node: &Node, ctx: &mut Vec<ObsCtx>, steps: &mut Vec<TestStep>) {
    match node {
        Node::Decision(decision) => {
            if let Some(step) = synthesise_step(ctx, decision) {
                steps.push(step);
            }
        }
        Node::Condition {
            observe,
            pattern,
            children,
            ..
        } => {
            let example = example_for_pattern(pattern);
            ctx.push(ObsCtx {
                observable: observe.clone(),
                pattern: pattern.clone(),
                example,
            });
            for child in children {
                walk_node(child, ctx, steps);
            }
            ctx.pop();
        }
    }
}

/// Accumulated observation context while walking the tree.
struct ObsCtx {
    observable: Observable,
    pattern: Pattern,
    example: String,
}

/// Synthesise a test step from the accumulated observation context.
fn synthesise_step(ctx: &[ObsCtx], decision: &Decision) -> Option<TestStep> {
    if ctx.is_empty() {
        return None;
    }

    // Build a human-readable rule description from the observation path.
    let rule_parts: Vec<String> = ctx
        .iter()
        .map(|c| format_condition(&c.observable, &c.pattern))
        .collect();
    let rule_desc = format!(
        "{} (rule: {})",
        format_decision(decision),
        rule_parts.join(", ")
    );

    // Determine tool_name and tool_input from the observation context.
    let (tool_name, tool_input, name) = build_invocation(ctx, decision);

    Some(TestStep {
        name,
        tool_name,
        tool_input,
        expected_decision: decision.effect().to_string(),
        rule_description: rule_desc,
    })
}

/// Build a concrete tool invocation from the observation context.
fn build_invocation(
    ctx: &[ObsCtx],
    decision: &Decision,
) -> (String, Vec<(String, String)>, String) {
    let mut tool_name: Option<String> = None;
    let mut positional_args: Vec<(i32, String)> = Vec::new();
    let mut has_arg_example: Option<String> = None;
    let mut named_args: Vec<(String, String)> = Vec::new();
    let mut _fs_op: Option<String> = None;
    let mut fs_path: Option<String> = None;
    let mut net_domain: Option<String> = None;

    for c in ctx {
        match &c.observable {
            Observable::ToolName => {
                tool_name = Some(c.example.clone());
            }
            Observable::PositionalArg(i) => {
                positional_args.push((*i, c.example.clone()));
            }
            Observable::HasArg => {
                has_arg_example = Some(c.example.clone());
            }
            Observable::NamedArg(key) => {
                named_args.push((key.clone(), c.example.clone()));
            }
            Observable::FsOp => {
                _fs_op = Some(c.example.clone());
            }
            Observable::FsPath => {
                fs_path = Some(c.example.clone());
            }
            Observable::NetDomain => {
                net_domain = Some(c.example.clone());
            }
            _ => {}
        }
    }

    let effect = decision.effect();
    let effect_str = effect.to_string();

    // Determine the final tool name; default to "Bash" for exec rules.
    let final_tool = tool_name.clone().unwrap_or_else(|| "Bash".into());

    match final_tool.as_str() {
        "Bash" => {
            // Build a command string from positional args.
            positional_args.sort_by_key(|(i, _)| *i);
            let mut cmd_parts: Vec<String> =
                positional_args.iter().map(|(_, v)| v.clone()).collect();
            if let Some(ha) = &has_arg_example
                && !cmd_parts.iter().any(|p| p == ha)
            {
                cmd_parts.push(ha.clone());
            }
            let command = if cmd_parts.is_empty() {
                "echo test".into()
            } else {
                cmd_parts.join(" ")
            };
            let name = format!("{command} \u{2192} expect {effect_str}");
            ("Bash".into(), vec![("command".into(), command)], name)
        }
        "Read" | "Glob" | "Grep" => {
            let path = fs_path
                .clone()
                .unwrap_or_else(|| "/tmp/test-file.txt".into());
            let name = format!("{final_tool} {path} \u{2192} expect {effect_str}");
            match final_tool.as_str() {
                "Read" => (final_tool, vec![("file_path".into(), path)], name),
                "Glob" => (final_tool, vec![("pattern".into(), path)], name),
                "Grep" => (
                    final_tool,
                    vec![("pattern".into(), "test".into()), ("path".into(), path)],
                    name,
                ),
                _ => unreachable!(),
            }
        }
        "Write" | "Edit" => {
            let path = fs_path
                .clone()
                .unwrap_or_else(|| "/tmp/test-file.txt".into());
            let name = format!("{final_tool} {path} \u{2192} expect {effect_str}");
            if final_tool == "Edit" {
                (
                    final_tool,
                    vec![
                        ("file_path".into(), path),
                        ("old_string".into(), "old".into()),
                        ("new_string".into(), "new".into()),
                    ],
                    name,
                )
            } else {
                (
                    final_tool,
                    vec![
                        ("file_path".into(), path),
                        ("content".into(), "test content".into()),
                    ],
                    name,
                )
            }
        }
        "WebFetch" => {
            let domain = net_domain.clone().unwrap_or_else(|| "example.com".into());
            let url = if domain == "*" {
                "https://example.com/page".into()
            } else {
                format!("https://{domain}/page")
            };
            let name = format!("WebFetch {domain} \u{2192} expect {effect_str}");
            ("WebFetch".into(), vec![("url".into(), url)], name)
        }
        "WebSearch" => {
            let name = format!("WebSearch \u{2192} expect {effect_str}");
            (
                "WebSearch".into(),
                vec![("query".into(), "test query".into())],
                name,
            )
        }
        _ => {
            // Generic tool — provide minimal input using any named args we collected.
            let name = format!("{final_tool} \u{2192} expect {effect_str}");
            let mut input: Vec<(String, String)> = named_args.clone();
            if input.is_empty() {
                input.push(("input".into(), "test".into()));
            }
            (final_tool, input, name)
        }
    }
}

/// Generate a concrete example string that matches a pattern.
fn example_for_pattern(pattern: &Pattern) -> String {
    match pattern {
        Pattern::Wildcard => "*".into(),
        Pattern::Literal(value) => resolve_value(value),
        Pattern::Regex(re) => example_from_regex(re.as_str()),
        Pattern::AnyOf(pats) => {
            // Use the first sub-pattern's example.
            pats.first()
                .map(example_for_pattern)
                .unwrap_or_else(|| "example".into())
        }
        Pattern::Not(_) => {
            // For NOT patterns, produce a value that does NOT match — hard in general,
            // so we use a generic example.
            "__not_matched__".into()
        }
        Pattern::Prefix(value) => {
            let prefix = resolve_value(value);
            format!("{prefix}/test-file.txt")
        }
    }
}

/// Resolve a Value to a concrete string.
fn resolve_value(value: &Value) -> String {
    match value {
        Value::Literal(s) => s.clone(),
        Value::Env(var) => {
            // Use a placeholder — actual env vars won't be available in tests.
            format!("/tmp/{var}_placeholder")
        }
        Value::Path(parts) => parts
            .iter()
            .map(resolve_value)
            .collect::<Vec<_>>()
            .join("/"),
    }
}

/// Generate a simple example from a regex pattern.
///
/// Tries to extract literal-ish content; falls back to a generic string.
fn example_from_regex(re_str: &str) -> String {
    // Strip common anchors.
    let s = re_str.trim_start_matches('^').trim_end_matches('$');

    // If the pattern is simple enough (mostly literals), use it.
    let has_special = s.contains('(')
        || s.contains('[')
        || s.contains('{')
        || s.contains('|')
        || s.contains('+')
        || s.contains('?');

    if !has_special {
        // Replace .* and .+ with a simple literal.
        let cleaned = s
            .replace(".*", "example")
            .replace(".+", "example")
            .replace('.', "x");
        if !cleaned.is_empty() {
            return cleaned;
        }
    }

    format!("regex_match_{}", re_str.len())
}

// ---------------------------------------------------------------------------
// YAML rendering
// ---------------------------------------------------------------------------

/// Render the test script as YAML.
fn render_yaml(
    star_source: &str,
    policy_path: &Path,
    steps: &[TestStep],
    _policy: &CompiledPolicy,
) -> String {
    let mut out = String::new();

    let file_name = policy_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("policy");

    out.push_str(&format!(
        "meta:\n  name: generated test for {file_name}\n  description: Auto-generated from {}\n\n",
        policy_path.display()
    ));

    // Emit policy configuration.
    let is_star = policy_path.extension().is_some_and(|ext| ext == "star");
    if is_star {
        out.push_str("clash:\n  policy_star: |\n");
        for line in star_source.lines() {
            out.push_str(&format!("    {line}\n"));
        }
    } else {
        out.push_str("clash:\n  policy_raw: |\n");
        for line in star_source.lines() {
            out.push_str(&format!("    {line}\n"));
        }
    }

    out.push_str("\nsteps:\n");

    for step in steps {
        out.push_str(&format!("  - name: {}\n", yaml_escape(&step.name)));
        out.push_str("    hook: pre-tool-use\n");
        out.push_str(&format!("    tool_name: {}\n", step.tool_name));
        out.push_str("    tool_input:\n");
        for (key, value) in &step.tool_input {
            out.push_str(&format!("      {}: {}\n", key, yaml_escape(value)));
        }
        out.push_str("    expect:\n");
        out.push_str(&format!("      decision: {}\n", step.expected_decision));
        out.push('\n');
    }

    out
}

/// Escape a string for safe YAML scalar output.
fn yaml_escape(s: &str) -> String {
    // Quote if the string contains special YAML characters.
    if s.contains(':')
        || s.contains('#')
        || s.contains('\'')
        || s.contains('"')
        || s.contains('\n')
        || s.contains('{')
        || s.contains('}')
        || s.contains('[')
        || s.contains(']')
        || s.contains('*')
        || s.contains('&')
        || s.contains('!')
        || s.contains('|')
        || s.contains('>')
        || s.contains('%')
        || s.contains('@')
        || s.starts_with(' ')
        || s.starts_with('-')
    {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Effect;
    use crate::policy::match_tree::{CompiledPolicy, Decision, Node, Observable, Pattern, Value};

    fn make_literal(s: &str) -> Pattern {
        Pattern::Literal(Value::Literal(s.to_string()))
    }

    fn make_policy(tree: Vec<Node>, default_effect: Effect) -> CompiledPolicy {
        CompiledPolicy {
            sandboxes: std::collections::HashMap::new(),
            tree,
            default_effect,
            default_sandbox: None,
        }
    }

    #[test]
    fn generates_steps_for_simple_exec_allow() {
        let policy = make_policy(
            vec![Node::Condition {
                observe: Observable::ToolName,
                pattern: make_literal("Bash"),
                children: vec![Node::Condition {
                    observe: Observable::PositionalArg(0),
                    pattern: make_literal("git"),
                    children: vec![Node::Decision(Decision::Allow(None))],
                    doc: None,
                    source: None,
                    terminal: false,
                }],
                doc: None,
                source: None,
                terminal: false,
            }],
            Effect::Deny,
        );

        let steps = generate_steps(&policy);
        // One rule step + one default step
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].tool_name, "Bash");
        assert_eq!(steps[0].expected_decision, "allow");
        assert!(steps[0].tool_input[0].1.contains("git"));
        // Default step
        assert_eq!(steps[1].expected_decision, "deny");
    }

    #[test]
    fn generates_steps_for_tool_rule() {
        let policy = make_policy(
            vec![Node::Condition {
                observe: Observable::ToolName,
                pattern: make_literal("Read"),
                children: vec![Node::Decision(Decision::Allow(None))],
                doc: None,
                source: None,
                terminal: false,
            }],
            Effect::Ask,
        );

        let steps = generate_steps(&policy);
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].tool_name, "Read");
        assert_eq!(steps[0].expected_decision, "allow");
        assert_eq!(steps[1].expected_decision, "ask");
    }

    #[test]
    fn generates_default_test() {
        let policy = make_policy(vec![], Effect::Ask);

        let steps = generate_steps(&policy);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].expected_decision, "ask");
        assert!(steps[0].rule_description.contains("default"));
    }

    #[test]
    fn example_for_literal_pattern() {
        let pat = make_literal("git");
        assert_eq!(example_for_pattern(&pat), "git");
    }

    #[test]
    fn example_for_wildcard_pattern() {
        assert_eq!(example_for_pattern(&Pattern::Wildcard), "*");
    }

    #[test]
    fn example_for_regex_pattern() {
        let re = regex::Regex::new("^cargo.*").unwrap();
        let pat = Pattern::Regex(std::sync::Arc::new(re));
        let example = example_for_pattern(&pat);
        assert!(example.contains("cargo"));
    }

    #[test]
    fn example_for_prefix_pattern() {
        let pat = Pattern::Prefix(Value::Literal("/home/user/project".into()));
        let example = example_for_pattern(&pat);
        assert!(example.starts_with("/home/user/project/"));
    }

    #[test]
    fn yaml_escape_special_chars() {
        assert_eq!(yaml_escape("simple"), "simple");
        assert_eq!(yaml_escape("has: colon"), "\"has: colon\"");
        assert_eq!(yaml_escape("has \"quotes\""), "\"has \\\"quotes\\\"\"");
    }

    #[test]
    fn generates_steps_for_deny_rule() {
        let policy = make_policy(
            vec![Node::Condition {
                observe: Observable::ToolName,
                pattern: make_literal("Bash"),
                children: vec![Node::Condition {
                    observe: Observable::PositionalArg(0),
                    pattern: make_literal("rm"),
                    children: vec![Node::Decision(Decision::Deny)],
                    doc: None,
                    source: None,
                    terminal: false,
                }],
                doc: None,
                source: None,
                terminal: false,
            }],
            Effect::Allow,
        );

        let steps = generate_steps(&policy);
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].expected_decision, "deny");
        assert!(steps[0].tool_input[0].1.contains("rm"));
    }

    #[test]
    fn generates_steps_with_args() {
        let policy = make_policy(
            vec![Node::Condition {
                observe: Observable::ToolName,
                pattern: make_literal("Bash"),
                children: vec![Node::Condition {
                    observe: Observable::PositionalArg(0),
                    pattern: make_literal("git"),
                    children: vec![Node::Condition {
                        observe: Observable::PositionalArg(1),
                        pattern: make_literal("push"),
                        children: vec![Node::Decision(Decision::Deny)],
                        doc: None,
                        source: None,
                        terminal: false,
                    }],
                    doc: None,
                    source: None,
                    terminal: false,
                }],
                doc: None,
                source: None,
                terminal: false,
            }],
            Effect::Allow,
        );

        let steps = generate_steps(&policy);
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].expected_decision, "deny");
        assert!(steps[0].tool_input[0].1.contains("git"));
        assert!(steps[0].tool_input[0].1.contains("push"));
    }

    #[test]
    fn generates_net_domain_step() {
        let policy = make_policy(
            vec![Node::Condition {
                observe: Observable::ToolName,
                pattern: make_literal("WebFetch"),
                children: vec![Node::Condition {
                    observe: Observable::NetDomain,
                    pattern: make_literal("github.com"),
                    children: vec![Node::Decision(Decision::Allow(None))],
                    doc: None,
                    source: None,
                    terminal: false,
                }],
                doc: None,
                source: None,
                terminal: false,
            }],
            Effect::Deny,
        );

        let steps = generate_steps(&policy);
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].tool_name, "WebFetch");
        assert!(steps[0].tool_input[0].1.contains("github.com"));
    }

    #[test]
    fn render_yaml_is_valid() {
        let policy = make_policy(
            vec![Node::Condition {
                observe: Observable::ToolName,
                pattern: make_literal("Bash"),
                children: vec![Node::Condition {
                    observe: Observable::PositionalArg(0),
                    pattern: make_literal("git"),
                    children: vec![Node::Decision(Decision::Allow(None))],
                    doc: None,
                    source: None,
                    terminal: false,
                }],
                doc: None,
                source: None,
                terminal: false,
            }],
            Effect::Deny,
        );

        let steps = generate_steps(&policy);
        let star_source = r#"load("@clash//std.star", "exe", "policy")
def main():
    return policy(default=deny, rules=[exe("git").allow()])
"#;
        let yaml = render_yaml(star_source, Path::new("test_policy.star"), &steps, &policy);

        // Verify it parses as valid YAML.
        let parsed: serde_yaml::Value =
            serde_yaml::from_str(&yaml).expect("generated YAML should be valid");
        assert!(parsed.get("meta").is_some());
        assert!(parsed.get("clash").is_some());
        assert!(parsed.get("steps").is_some());
    }
}
