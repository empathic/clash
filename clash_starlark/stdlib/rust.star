load("@clash//std.star", "sandbox", "cwd", "home", "tempdir", "domains", "exe", "path")

rust_sandbox = sandbox(
    name = "rust_dev",
    default = deny,
    fs = [
        cwd(follow_worktrees=True).recurse().allow(),
        cwd().child("target").recurse().allow(),
        home().child(".cargo").recurse().allow(),
        home().child(".rustup").recurse().allow(),
        tempdir().recurse().allow(),
        path("/").allow(),
    ],
    net = "allow",
)


rust = exe(["rustc", "cargo"]).sandbox(rust_sandbox).allow()
