# Rust Development Policy
# Allows common Rust toolchain commands with filesystem sandboxing.
# Default: ask for anything not explicitly allowed.
load("@clash//std.star", "match", "policy", "sandbox", "subpath", "allow", "deny", "ask")

def main():
    rust_sandbox = sandbox(
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
    return policy(
        default = ask(),
        rules = [
            match({"Bash": {
                "git": {"push": {"--force": deny()}},
            }}),
            match({"Bash": {
                ("cargo", "rustc", "rustfmt"): allow(sandbox = rust_sandbox),
                "rustup": allow(),
                "git": allow(),
            }}),
            match({("Read", "Glob", "Grep"): allow()}),
        ],
    )
