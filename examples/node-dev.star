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

policy("node-dev",
    rules = [
        when({"Bash": {
            "git": {"push": {"--force": deny()}},
        }}),
        when({"Bash": {
            ("npm", "npx", "node", "bun"): allow(sandbox = "node"),
            "git": allow(),
        }}),
        when({("Read", "Glob", "Grep"): allow()}),
    ],
)
