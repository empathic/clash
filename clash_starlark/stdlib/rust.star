load("@clash//std.star", "allow", "deny", "match", "sandbox", "subpath")

rust_sandbox = sandbox(
    name = "rust_dev",
    default = deny(),
    fs = {
        subpath("$PWD", follow_worktrees = True): allow(),
        "$HOME": {
            ".cargo": allow(),
            ".rustup": allow(),
        },
        "$TMPDIR": allow(),
    },
    net = "allow",
    doc = "Rust development: project + cargo/rustup toolchains, full network",
)


rust = match({"Bash": {("rustc", "cargo"): allow(sandbox = rust_sandbox)}})
