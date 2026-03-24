# Maximum Security Policy
# Deny-all default. Only read-only git and file reading tools allowed.
# Use this when security is more important than convenience.
load("@clash//std.star", "allow", "match", "tool", "policy", "deny")

def main():
    return policy(
        default = deny(),
        rules = [
            match({"Bash": {"git": {
                ("status", "diff", "log"): allow(),
            }}}),
            tool("Read").allow(),
            tool("Glob").allow(),
            tool("Grep").allow(),
        ],
    )
