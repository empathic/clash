# Rust Development Policy
# Allows common Rust toolchain commands with filesystem sandboxing.
# Default: ask for anything not explicitly allowed.
load("@clash//std.star", "exe", "tool", "policy", "sandbox", "cwd", "tempdir", "home", "allow", "deny", "ask")

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
            exe("cargo").sandbox(rust_sandbox).allow(),
            exe("rustc").sandbox(rust_sandbox).allow(),
            exe("rustup").allow(),
            exe("rustfmt").sandbox(rust_sandbox).allow(),
            exe("git").allow(),
            exe("git", args = ["push", "--force"]).deny(),
            tool("Read").allow(),
            tool("Glob").allow(),
            tool("Grep").allow(),
        ],
    )
