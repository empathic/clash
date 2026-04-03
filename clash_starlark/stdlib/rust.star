rust_safe = sandbox(
    name = "rust_safe",
    default = ask(),
    fs = {
        subpath("$PWD", follow_worktrees=True): allow("rx"),
        subpath("$PWD/target"): allow(),
        "$HOME": {
            glob(".cargo/**"): allow("rx"),
            glob(".rustup/**"): allow("rx"),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = deny(),
    doc = "Rust safe: check, clippy, test, doc, bench. Build artifacts writable, source read-only.",
)

rust_full = sandbox(
    name = "rust_full",
    default = ask(),
    fs = {
        subpath("$PWD", follow_worktrees=True): allow(FULL),
        "$HOME": {
            glob(".cargo/**"): allow(),
            glob(".rustup/**"): allow(),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
    doc = "Rust full: add, install, update. Full project + toolchain access, network enabled.",
)

rust = when({"Bash": {("cargo", "rustc", "rustup"): allow(sandbox = rust_full)}})
