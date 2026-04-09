# Rust Development Policy
# Allows common Rust toolchain commands with filesystem sandboxing.
# Default: ask for anything not explicitly allowed.

sandbox("rust", {
    default(): deny(),
    path("$PWD", worktree = True): allow("rwc"),
    glob("$TMPDIR/**"): allow(),
    glob("$HOME/.cargo/**"): allow("rwc"),
    glob("$HOME/.rustup/**"): allow("r"),
    network(): allow(),
}, doc = "Rust toolchain sandbox: project + cargo + rustup, network allowed.")

settings(default = ask())

policy("rust-dev", {
    tool("Bash"): {
        "git": {
            "push": {"--force": deny()},
            glob("**"): allow(),
        },
        ("cargo", "rustc", "rustfmt"): allow(sandbox = "rust"),
        "rustup": allow(),
    },
    tool(("Read", "Glob", "Grep")): allow(),
}, doc = "Rust development: cargo/rustc/rustfmt sandboxed; git push --force denied.")
