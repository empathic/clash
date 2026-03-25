# Node.js Development Policy
# Allows npm/bun/node with sandboxed filesystem access.
load("@clash//std.star", "match", "tool", "policy", "sandbox", "cwd", "tempdir", "allow", "deny", "ask")

def main():
    node_sandbox = sandbox(
        name = "node",
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
                ("npm", "npx", "node", "bun"): allow(sandbox = node_sandbox),
                "git": allow(),
            }}),
            tool("Read").allow(),
            tool("Glob").allow(),
            tool("Grep").allow(),
        ],
    )
