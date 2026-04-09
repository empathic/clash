use clash_starlark::eval_policy_source_for_test;

#[test]
fn policy_default_key_sets_fallback() {
    let ctx = eval_policy_source_for_test(
        r#"
policy("x", {
    default(): deny(),
    mode("plan"): allow(),
    tool("Bash"): {"git push": deny()},
})
"#,
    )
    .unwrap();
    let pol = ctx.policy.borrow();
    let pol = pol.as_ref().expect("policy registered");
    assert_eq!(pol.name, "x");
    assert_eq!(pol.default_effect.as_deref(), Some("deny"));
    // Tree has 2 non-default root nodes (mode + tool)
    assert_eq!(pol.tree_nodes.len(), 2);
}

#[test]
fn policy_unified_signature_accepts_tree_and_doc() {
    eval_policy_source_for_test(
        r#"
policy("x", {
    mode("plan"): allow(),
}, default="deny", doc="demo")
"#,
    )
    .unwrap();
}
