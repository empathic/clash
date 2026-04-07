use clash_starlark::eval_policy_source_for_test;

#[test]
fn bare_string_at_policy_root_is_rejected() {
    let err = eval_policy_source_for_test(
        r#"
policy("x", {"Bash": allow()})
"#,
    )
    .unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("typed constructor"),
        "expected typed-constructor error, got: {msg}"
    );
}

#[test]
fn typed_root_key_is_accepted() {
    eval_policy_source_for_test(
        r#"
policy("x", {tool("Bash"): allow()})
"#,
    )
    .unwrap();
}
