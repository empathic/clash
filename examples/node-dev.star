# Node.js Development Policy
# Allows npm/bun/node with sandboxed filesystem access.
load("@clash//std.star", "match", "policy", "sandbox", "subpath", "allow", "deny", "ask")

def main():
    node_sandbox = sandbox(
        name = "node",
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
                ("npm", "npx", "node", "bun"): allow(sandbox = node_sandbox),
                "git": allow(),
            }}),
            match({("Read", "Glob", "Grep"): allow()}),
        ],
    )
