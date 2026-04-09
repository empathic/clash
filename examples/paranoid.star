# Maximum Security Policy
# Deny-all default. Only read-only git and file reading tools allowed.
# Use this when security is more important than convenience.

settings(default = deny())

policy("paranoid", {
    tool("Bash"): {
        "git": {("status", "diff", "log"): allow()},
    },
    tool(("Read", "Glob", "Grep")): allow(),
}, doc = "Maximum security: deny-all default, only read-only git and file reading tools allowed.")
