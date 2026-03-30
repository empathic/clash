# Rust Development Policy
# Allows common Rust toolchain commands with filesystem sandboxing.
# Default: ask for anything not explicitly allowed.
load("@clash//std.star", "match", "policy", "settings", "sandbox", "subpath", "allow", "deny", "ask")

sandbox(
    name = "rust",
    default = deny(),
    fs = {
        subpath("$PWD", follow_worktrees = True): allow("rwc"),
        "$TMPDIR": allow(),
        "$HOME": {
            ".cargo": allow("rwc"),
            ".rustup": allow("r"),
        },
    },
    net = allow(),
)

settings(default = ask())

policy("rust-dev",
    rules = [
        match({"Bash": {
            "git": {"push": {"--force": deny()}},
        }}),
        match({"Bash": {
            ("cargo", "rustc", "rustfmt"): allow(sandbox = "rust"),
            "rustup": allow(),
            "git": allow(),
        }}),
        match({("Read", "Glob", "Grep"): allow()}),
    ],
)
