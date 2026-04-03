//! Property-based tests for the match-tree policy evaluation engine.

use std::collections::HashMap;
use std::sync::Arc;

use proptest::prelude::*;
use regex::Regex;

use super::Effect;
use super::match_tree::{
    CompiledPolicy, Decision, Node, Observable, Pattern, QueryContext, Value, eval,
};

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// Generate a simple tool name.
fn arb_tool_name() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("Bash".to_string()),
        Just("Read".to_string()),
        Just("Write".to_string()),
        Just("Edit".to_string()),
        Just("Glob".to_string()),
        Just("Grep".to_string()),
    ]
}

/// Generate a simple identifier-like string for use in patterns and args.
fn arb_ident() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("git".to_string()),
        Just("cargo".to_string()),
        Just("echo".to_string()),
        Just("ls".to_string()),
        Just("cat".to_string()),
        Just("rm".to_string()),
        Just("npm".to_string()),
    ]
}

/// Generate an Effect.
fn arb_effect() -> impl Strategy<Value = Effect> {
    prop_oneof![Just(Effect::Allow), Just(Effect::Deny), Just(Effect::Ask),]
}

/// Generate a Decision from an Effect.
fn arb_decision() -> impl Strategy<Value = Decision> {
    arb_effect().prop_map(|e| match e {
        Effect::Allow => Decision::Allow(None),
        Effect::Deny => Decision::Deny,
        Effect::Ask => Decision::Ask(None),
    })
}

/// Generate a QueryContext for a Bash tool invocation.
fn arb_bash_query() -> impl Strategy<Value = QueryContext> {
    (arb_ident(), prop::collection::vec(arb_ident(), 0..3)).prop_map(|(bin, extra_args)| {
        let mut command_parts = vec![bin];
        command_parts.extend(extra_args);
        let command = command_parts.join(" ");
        let input = serde_json::json!({"command": command});
        QueryContext::from_tool("Bash", &input)
    })
}

/// Generate a QueryContext for any tool.
fn arb_query() -> impl Strategy<Value = QueryContext> {
    prop_oneof![
        // Bash with a command
        arb_bash_query(),
        // Non-Bash tool with simple JSON input
        arb_tool_name().prop_map(|name| {
            let input = serde_json::json!({});
            QueryContext::from_tool(&name, &input)
        }),
    ]
}

/// Build a policy with multiple rules at the root level.
fn arb_multi_rule_policy() -> impl Strategy<Value = CompiledPolicy> {
    (
        prop::collection::vec(
            (arb_tool_name(), arb_decision()).prop_map(|(tool_name, decision)| Node::Condition {
                observe: Observable::ToolName,
                pattern: Pattern::Literal(Value::Literal(tool_name)),
                children: vec![Node::Decision(decision)],
                doc: None,
                source: None,
                terminal: false,
            }),
            1..5,
        ),
        arb_effect(),
    )
        .prop_map(|(tree, default_effect)| CompiledPolicy {
            sandboxes: HashMap::new(),
            tree,
            default_effect,
            default_sandbox: None,
            on_sandbox_violation: Default::default(),
        })
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

proptest! {
    /// Invariant 1: Evaluating the same policy against the same input always
    /// produces the same effect. The evaluator is purely deterministic.
    #[test]
    fn eval_is_deterministic(
        policy in arb_multi_rule_policy(),
        query in arb_query(),
    ) {
        let r1 = policy.evaluate_ctx(&query);
        let r2 = policy.evaluate_ctx(&query);
        prop_assert_eq!(r1.effect, r2.effect);
    }

    /// Invariant 2: When no rules match, the policy's default effect is used.
    #[test]
    fn default_effect_when_no_rules_match(default_effect in arb_effect()) {
        let policy = CompiledPolicy {
            sandboxes: HashMap::new(),
            // A rule that matches tool name "NONEXISTENT" — will never fire
            tree: vec![Node::Condition {
                observe: Observable::ToolName,
                pattern: Pattern::Literal(Value::Literal("__nonexistent_tool__".into())),
                children: vec![Node::Decision(Decision::Deny)],
                doc: None,
                source: None,
                terminal: false,
            }],
            default_effect,
            default_sandbox: None,
            on_sandbox_violation: Default::default(),
        };
        // Query with a tool name that won't match any rule
        let input = serde_json::json!({});
        let ctx = QueryContext::from_tool("SomeOtherTool", &input);
        let result = policy.evaluate_ctx(&ctx);
        prop_assert_eq!(result.effect, default_effect);
    }

    /// Invariant 3: After compact(), a literal rule takes precedence over a
    /// wildcard rule when both match, regardless of original insertion order.
    #[test]
    fn literal_beats_wildcard_after_compact(
        literal_decision in arb_decision(),
        wildcard_decision in arb_decision(),
        tool_name in arb_tool_name(),
    ) {
        // Build tree with wildcard first, literal second (wrong specificity order)
        let nodes = vec![
            Node::Condition {
                observe: Observable::ToolName,
                pattern: Pattern::Wildcard,
                children: vec![Node::Decision(wildcard_decision.clone())],
                doc: None,
                source: None,
                terminal: false,
            },
            Node::Condition {
                observe: Observable::ToolName,
                pattern: Pattern::Literal(Value::Literal(tool_name.clone())),
                children: vec![Node::Decision(literal_decision.clone())],
                doc: None,
                source: None,
                terminal: false,
            },
        ];

        let compacted = Node::compact(nodes);
        let policy = CompiledPolicy {
            sandboxes: HashMap::new(),
            tree: compacted,
            default_effect: Effect::Ask,
            default_sandbox: None,
            on_sandbox_violation: Default::default(),
        };

        let input = serde_json::json!({});
        let ctx = QueryContext::from_tool(&tool_name, &input);
        let result = policy.evaluate_ctx(&ctx);

        // The literal rule should win because compact() sorts by specificity
        prop_assert_eq!(result.effect, literal_decision.effect());
    }

    /// Invariant 4: In a policy with two rules of equal specificity that both
    /// match, first-match semantics apply — the first rule wins.
    #[test]
    fn first_match_wins_at_equal_specificity(
        first_decision in arb_decision(),
        second_decision in arb_decision(),
        tool_name in arb_tool_name(),
    ) {
        // Two literal rules for the same tool name — same specificity
        let nodes = vec![
            Node::Condition {
                observe: Observable::ToolName,
                pattern: Pattern::Literal(Value::Literal(tool_name.clone())),
                children: vec![Node::Decision(first_decision.clone())],
                doc: None,
                source: None,
                terminal: false,
            },
            Node::Condition {
                observe: Observable::ToolName,
                pattern: Pattern::Literal(Value::Literal(tool_name.clone())),
                children: vec![Node::Decision(second_decision)],
                doc: None,
                source: None,
                terminal: false,
            },
        ];

        let ctx = {
            let input = serde_json::json!({});
            QueryContext::from_tool(&tool_name, &input)
        };

        // Without compact: first rule should win via DFS
        let result_raw = eval(&nodes, &ctx);
        prop_assert_eq!(result_raw.unwrap().effect(), first_decision.effect());

        // With compact: duplicate Condition siblings get merged, so the first
        // child's Decision still appears first
        let compacted = Node::compact(nodes);
        let policy = CompiledPolicy {
            sandboxes: HashMap::new(),
            tree: compacted,
            default_effect: Effect::Ask,
            default_sandbox: None,
            on_sandbox_violation: Default::default(),
        };
        let result = policy.evaluate_ctx(&ctx);
        prop_assert_eq!(result.effect, first_decision.effect());
    }

    /// Invariant 5: The `eval` function and `CompiledPolicy::evaluate_ctx`
    /// agree when there is a match (no sandbox complications).
    #[test]
    fn eval_and_evaluate_ctx_agree(
        policy in arb_multi_rule_policy(),
        query in arb_query(),
    ) {
        let direct = eval(&policy.tree, &query);
        let via_policy = policy.evaluate_ctx(&query);

        match direct {
            Some(d) => {
                // evaluate_ctx wraps the raw decision; effects should match
                // (unless sandbox enforcement changes Allow→Deny, which
                // doesn't happen here since we have no sandboxes).
                prop_assert_eq!(d.effect(), via_policy.effect);
            }
            None => {
                // No rule matched → default effect
                prop_assert_eq!(via_policy.effect, policy.default_effect);
            }
        }
    }

    /// Invariant 6: An empty tree always returns the default effect.
    #[test]
    fn empty_tree_returns_default(default_effect in arb_effect()) {
        let policy = CompiledPolicy {
            sandboxes: HashMap::new(),
            tree: vec![],
            default_effect,
            default_sandbox: None,
            on_sandbox_violation: Default::default(),
        };
        let input = serde_json::json!({"command": "anything"});
        let ctx = QueryContext::from_tool("Bash", &input);
        let result = policy.evaluate_ctx(&ctx);
        prop_assert_eq!(result.effect, default_effect);
    }

    /// Invariant 7: Pattern::Wildcard matches any tool name.
    #[test]
    fn wildcard_matches_everything(
        tool_name in arb_tool_name(),
        decision in arb_decision(),
    ) {
        let nodes = vec![Node::Condition {
            observe: Observable::ToolName,
            pattern: Pattern::Wildcard,
            children: vec![Node::Decision(decision.clone())],
            doc: None,
            source: None,
            terminal: false,
        }];
        let input = serde_json::json!({});
        let ctx = QueryContext::from_tool(&tool_name, &input);
        let result = eval(&nodes, &ctx);
        prop_assert_eq!(result.unwrap().effect(), decision.effect());
    }

    /// Invariant 8: Pattern::Not(Wildcard) matches nothing.
    #[test]
    fn not_wildcard_matches_nothing(tool_name in arb_tool_name()) {
        let nodes = vec![Node::Condition {
            observe: Observable::ToolName,
            pattern: Pattern::Not(Box::new(Pattern::Wildcard)),
            children: vec![Node::Decision(Decision::Allow(None))],
            doc: None,
            source: None,
            terminal: false,
        }];
        let input = serde_json::json!({});
        let ctx = QueryContext::from_tool(&tool_name, &input);
        let result = eval(&nodes, &ctx);
        prop_assert!(result.is_none());
    }

    /// Invariant 9: Specificity scores are consistent — Literal > Regex > Wildcard.
    #[test]
    fn specificity_ordering_is_consistent(ident in arb_ident()) {
        let literal = Pattern::Literal(Value::Literal(ident));
        let regex = Pattern::Regex(Arc::new(Regex::new(".*").unwrap()));
        let wildcard = Pattern::Wildcard;

        prop_assert!(literal.specificity() > regex.specificity());
        prop_assert!(regex.specificity() > wildcard.specificity());
    }

    /// Invariant 10: compact() is idempotent — compacting twice produces the
    /// same evaluation result as compacting once.
    #[test]
    fn compact_is_idempotent(
        policy in arb_multi_rule_policy(),
        query in arb_query(),
    ) {
        let once = Node::compact(policy.tree.clone());
        let twice = Node::compact(once.clone());

        let result_once = eval(&once, &query);
        let result_twice = eval(&twice, &query);

        match (result_once, result_twice) {
            (Some(a), Some(b)) => prop_assert_eq!(a.effect(), b.effect()),
            (None, None) => {} // both returned no match
            _ => prop_assert!(false, "compact idempotency violated"),
        }
    }
}
