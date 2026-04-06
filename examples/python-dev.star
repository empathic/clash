# Python Development Policy
# Allows python/pip/uv/pytest with sandboxed filesystem access.

sandbox(
    name = "python",
    default = deny(),
    fs = {
        subpath("$PWD", follow_worktrees = True): allow("rwc"),
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
)

settings(default = ask())

policy("python-dev", {
    "Bash": {
        "git": {"push": {"--force": deny()}},
        ("python", "python3", "pip", "uv", "pytest"): allow(sandbox = "python"),
        "git": allow(),
    },
    ("Read", "Glob", "Grep"): allow(),
})
