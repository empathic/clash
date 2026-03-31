rust_sandbox = sandbox(
    name = "rust_dev",
    default = deny(),
    fs = {
        subpath("$PWD", follow_worktrees = True): allow(),
        "$HOME": {
            glob(".cargo/**"): allow(),
            glob(".rustup/**"): allow(),
        },
        glob("$TMPDIR/**"): allow(),
    },
    net = "allow",
    doc = "Rust development: project + cargo/rustup toolchains, full network",
)


rust = match({"Bash": {("rustc", "cargo"): allow(sandbox = rust_sandbox)}})
