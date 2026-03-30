# Maximum Security Policy
# Deny-all default. Only read-only git and file reading tools allowed.
# Use this when security is more important than convenience.
load("@clash//std.star", "allow", "match", "policy", "settings", "deny")

settings(default = deny())

policy("paranoid",
    rules = [
        match({"Bash": {"git": {
            ("status", "diff", "log"): allow(),
        }}}),
        match({("Read", "Glob", "Grep"): allow()}),
    ],
)
