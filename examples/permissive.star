# Permissive Policy
# Ask-all default with common dev tools auto-allowed.
# Denies only truly dangerous operations.

settings(default = ask())

policy("permissive", {
    "Bash": {
        "git": {"push": {"--force": deny()}},
        ("git", "cargo", "npm", "npx", "node", "bun", "python", "pip", "uv", "make", "just"): allow(),
    },
    ("Read", "Write", "Edit", "Glob", "Grep"): allow(),
})
