# Node.js Development Policy
# Allows npm/bun/node with sandboxed filesystem access.

sandbox("node", {
    default(): deny(),
    path("$PWD", worktree = True): allow("rwc"),
    glob("$TMPDIR/**"): allow(),
    network(): allow(),
}, doc = "Node toolchain sandbox: project read/write, network allowed.")

settings(default = ask())

policy("node-dev", {
    tool("Bash"): {
        "git": {
            "push": {"--force": deny()},
            glob("**"): allow(),
        },
        ("npm", "npx", "node", "bun"): allow(sandbox = "node"),
    },
    tool(("Read", "Glob", "Grep")): allow(),
}, doc = "Node.js development: npm/npx/node/bun sandboxed; git push --force denied.")
