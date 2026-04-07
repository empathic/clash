use clash_starlark::load_starlark_source_for_test;

#[test]
fn typed_constructors_produce_match_keys() {
    let out = load_starlark_source_for_test(
        r#"
result = [
    default()._match_key,
    tool("Bash")._match_key,
    path("$PWD")._match_key,
    glob("/tmp/**")._match_key,
    domain("github.com")._match_key,
    localhost()._match_key,
    mode("plan")._match_key,
]
"#,
    )
    .unwrap();
    assert_eq!(
        out.get_global_strings("result").unwrap(),
        vec![
            "default",
            "tool",
            "path",
            "glob",
            "domain",
            "localhost",
            "mode"
        ],
    );
}
