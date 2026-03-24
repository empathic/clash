# Rust Development Policy
# Allows common Rust toolchain commands with filesystem sandboxing.
# Default: ask for anything not explicitly allowed.
load("@clash//std.star", "match", "tool", "policy", "sandbox", "cwd", "tempdir", "home", "allow", "deny", "ask")

def main():
    rust_sandbox = sandbox(
        name = "rust",
        default = deny(),
        fs = [
            cwd(follow_worktrees = True).allow(read = True, write = True),
            tempdir().allow(),
            home().child(".cargo").allow(read = True, write = True),
            home().child(".rustup").allow(read = True),
        ],
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
            tool("Read").allow(),
            tool("Glob").allow(),
            tool("Grep").allow(),
        ],
    )
