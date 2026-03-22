load("@clash//std.star", "deny", "sandbox", "cwd", "home", "tempdir", "exe", "path")

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


rust = exe(["rustc", "cargo"]).sandbox(rust_sandbox).allow()
