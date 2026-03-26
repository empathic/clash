# Python Development Policy
# Allows python/pip/uv/pytest with sandboxed filesystem access.
load("@clash//std.star", "match", "policy", "sandbox", "subpath", "allow", "deny", "ask")

def main():
    py_sandbox = sandbox(
        name = "python",
        default = deny(),
        fs = {
            subpath("$PWD", follow_worktrees = True): allow("rwc"),
            "$TMPDIR": allow(),
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
                ("python", "python3", "pip", "uv", "pytest"): allow(sandbox = py_sandbox),
                "git": allow(),
            }}),
            match({("Read", "Glob", "Grep"): allow()}),
        ],
    )
