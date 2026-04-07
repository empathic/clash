use clash_starlark::eval_policy_source_for_test;

#[test]
fn sandbox_tree_fs_and_net_round_trip() {
    let ctx = eval_policy_source_for_test(
        r#"
sandbox("rust-dev", {
    default(): deny(),
    path("$PWD"): allow("rwc"),
    glob("/tmp/**"): allow("rwc"),
    domain("crates.io"): allow(),
    localhost(): allow(),
})
"#,
    )
    .unwrap();
    let sandboxes = ctx.sandboxes.borrow();
    let sb = sandboxes
        .get("rust-dev")
        .expect("sandbox registered under name");

    // default: deny → default caps = ["execute"]
    assert_eq!(sb["default"], serde_json::json!(["execute"]));

    let rules = sb["rules"].as_array().unwrap();
    assert!(
        rules
            .iter()
            .any(|r| r["path"] == "$PWD" && r["effect"] == "allow" && r["path_match"] == "literal"),
        "expected $PWD literal allow rule, got: {rules:#?}"
    );
    assert!(
        rules
            .iter()
            .any(|r| r["path"] == "/tmp/**" && r["effect"] == "allow" && r["path_match"] == "glob"),
        "expected /tmp/** glob allow rule, got: {rules:#?}"
    );

    // Network: domain + localhost present → represented somehow.
    let net = &sb["network"];
    let net_str = serde_json::to_string(net).unwrap();
    assert!(
        net_str.contains("crates.io"),
        "expected crates.io in network, got: {net_str}"
    );
}
