# Permissive Policy
# Ask-all default with common dev tools auto-allowed.
# Denies only truly dangerous operations.
load("@clash//std.star", "match", "tool", "policy", "allow", "deny", "ask")

def main():
    return policy(
        default = ask(),
        rules = [
            match({"Bash": {"git": {"push": {"--force": deny()}}}}),
            match({"Bash": {
                ("git", "cargo", "npm", "npx", "node", "bun", "python", "pip", "uv", "make", "just"): allow(),
            }}),
            tool("Read").allow(),
            tool("Write").allow(),
            tool("Edit").allow(),
            tool("Glob").allow(),
            tool("Grep").allow(),
        ],
    )
