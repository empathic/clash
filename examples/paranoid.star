# Maximum Security Policy
# Deny-all default. Only read-only git and file reading tools allowed.
# Use this when security is more important than convenience.
load("@clash//std.star", "exe", "tool", "policy", "deny")

def main():
    return policy(
        default = deny(),
        rules = [
            exe("git", args = ["status"]).allow(),
            exe("git", args = ["diff"]).allow(),
            exe("git", args = ["log"]).allow(),
            tool("Read").allow(),
            tool("Glob").allow(),
            tool("Grep").allow(),
        ],
    )
