# Node.js Development Policy
# Allows npm/bun/node with sandboxed filesystem access.
load("@clash//std.star", "match", "policy", "settings", "sandbox", "subpath", "allow", "deny", "ask")

sandbox(
    name = "node",
    default = deny(),
    fs = {
        subpath("$PWD", follow_worktrees = True): allow("rwc"),
        "$TMPDIR": allow(),
    },
    net = allow(),
)

settings(default = ask())

policy("node-dev",
    rules = [
        match({"Bash": {
            "git": {"push": {"--force": deny()}},
        }}),
        match({"Bash": {
            ("npm", "npx", "node", "bun"): allow(sandbox = "node"),
            "git": allow(),
        }}),
        match({("Read", "Glob", "Grep"): allow()}),
    ],
)
