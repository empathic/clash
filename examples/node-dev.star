# Node.js Development Policy
# Allows npm/bun/node with sandboxed filesystem access.

sandbox(
    name = "node",
    default = deny(),
    fs = {
        subpath("$PWD", follow_worktrees = True): allow("rwc"),
        glob("$TMPDIR/**"): allow(),
    },
    net = allow(),
)

settings(default = ask())

policy("node-dev", {
    "Bash": {
        "git": {"push": {"--force": deny()}},
        ("npm", "npx", "node", "bun"): allow(sandbox = "node"),
        "git": allow(),
    },
    ("Read", "Glob", "Grep"): allow(),
})
