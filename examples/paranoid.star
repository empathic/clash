# Maximum Security Policy
# Deny-all default. Only read-only git and file reading tools allowed.
# Use this when security is more important than convenience.

settings(default = deny())

policy("paranoid", {
    "Bash": {
        "git": {("status", "diff", "log"): allow()},
    },
    ("Read", "Glob", "Grep"): allow(),
})
