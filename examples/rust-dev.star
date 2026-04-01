# Rust Development Policy
# Allows common Rust toolchain commands with filesystem sandboxing.
# Default: ask for anything not explicitly allowed.

sandbox(
    name = "rust",
    default = deny(),
    fs = {
        subpath("$PWD", follow_worktrees = True): allow("rwc"),
        glob("$TMPDIR/**"): allow(),
        "$HOME": {
            glob(".cargo/**"): allow("rwc"),
            glob(".rustup/**"): allow("r"),
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
