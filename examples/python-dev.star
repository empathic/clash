# Python Development Policy
# Allows python/pip/uv/pytest with sandboxed filesystem access.
load("@clash//std.star", "match", "policy", "settings", "sandbox", "subpath", "allow", "deny", "ask")

sandbox(
    name = "python",
    default = deny(),
    fs = {
        subpath("$PWD", follow_worktrees = True): allow("rwc"),
        "$TMPDIR": allow(),
    },
    net = allow(),
)

settings(default = ask())

policy("python-dev",
    rules = [
        match({"Bash": {
            "git": {"push": {"--force": deny()}},
        }}),
        match({"Bash": {
            ("python", "python3", "pip", "uv", "pytest"): allow(sandbox = "python"),
            "git": allow(),
        }}),
        match({("Read", "Glob", "Grep"): allow()}),
    ],
)
