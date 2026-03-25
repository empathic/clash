load("@clash//std.star", "allow", "deny", "match", "sandbox", "cwd", "home", "tempdir", "path")

rust_sandbox = sandbox(
    name = "rust_dev",
    default = deny(),
    fs = [
        cwd(follow_worktrees = True).allow(),
        home().child(".cargo").allow(),
        home().child(".rustup").allow(),
        tempdir().allow(),
    ],
    net = "allow",
    doc = "Rust development: project + cargo/rustup toolchains, full network",
)


rust = match({"Bash": {("rustc", "cargo"): allow(sandbox = rust_sandbox)}})
