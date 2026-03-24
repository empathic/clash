# Python Development Policy
# Allows python/pip/uv/pytest with sandboxed filesystem access.
load("@clash//std.star", "match", "tool", "policy", "sandbox", "cwd", "tempdir", "allow", "deny", "ask")

def main():
    py_sandbox = sandbox(
        name = "python",
        default = deny(),
        fs = [
            cwd(follow_worktrees = True).allow(read = True, write = True),
            tempdir().allow(),
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
                ("python", "python3", "pip", "uv", "pytest"): allow(sandbox = py_sandbox),
                "git": allow(),
            }}),
            tool("Read").allow(),
            tool("Glob").allow(),
            tool("Grep").allow(),
        ],
    )
