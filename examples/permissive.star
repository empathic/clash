# Permissive Policy
# Ask-all default with common dev tools auto-allowed.
# Denies only truly dangerous operations.
load("@clash//std.star", "match", "policy", "settings", "allow", "deny", "ask")

settings(default = ask())

policy("permissive",
    rules = [
        match({"Bash": {"git": {"push": {"--force": deny()}}}}),
        match({"Bash": {
            ("git", "cargo", "npm", "npx", "node", "bun", "python", "pip", "uv", "make", "just"): allow(),
        }}),
        match({("Read", "Write", "Edit", "Glob", "Grep"): allow()}),
    ],
)
