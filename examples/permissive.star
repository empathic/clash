# Permissive Policy
# Ask-all default with common dev tools auto-allowed.
# Denies only truly dangerous operations.

settings(default = ask())

policy("permissive", {
    tool("Bash"): {
        "git": {"push": {"--force": deny()}},
        ("git", "cargo", "npm", "npx", "node", "bun", "python", "pip", "uv", "make", "just"): allow(),
    },
    tool(("Read", "Write", "Edit", "Glob", "Grep")): allow(),
}, doc = "Permissive: ask-all default with common dev tools auto-allowed; denies only force-push.")
