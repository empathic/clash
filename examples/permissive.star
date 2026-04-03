# Permissive Policy
# Ask-all default with common dev tools auto-allowed.
# Denies only truly dangerous operations.
load("@clash//std.star", "when", "policy", "settings", "allow", "deny", "ask")

settings(default = ask())

policy("permissive",
    rules = [
        when({"Bash": {"git": {"push": {"--force": deny()}}}}),
        when({"Bash": {
            ("git", "cargo", "npm", "npx", "node", "bun", "python", "pip", "uv", "make", "just"): allow(),
        }}),
        when({("Read", "Write", "Edit", "Glob", "Grep"): allow()}),
    ],
)
