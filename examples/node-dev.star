# Node.js Development Policy
# Allows npm/bun/node with sandboxed filesystem access.
load("@clash//std.star", "exe", "tool", "policy", "sandbox", "cwd", "tempdir", "allow", "deny", "ask")

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
            exe("npm").sandbox(node_sandbox).allow(),
            exe("npx").sandbox(node_sandbox).allow(),
            exe("node").sandbox(node_sandbox).allow(),
            exe("bun").sandbox(node_sandbox).allow(),
            exe("git").allow(),
            exe("git", args = ["push", "--force"]).deny(),
            tool("Read").allow(),
            tool("Glob").allow(),
            tool("Grep").allow(),
        ],
    )
