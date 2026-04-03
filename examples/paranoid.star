# Maximum Security Policy
# Deny-all default. Only read-only git and file reading tools allowed.
# Use this when security is more important than convenience.
load("@clash//std.star", "allow", "when", "policy", "settings", "deny")

settings(default = deny())

policy("paranoid",
    rules = [
        when({"Bash": {"git": {
            ("status", "diff", "log"): allow(),
        }}}),
        when({("Read", "Glob", "Grep"): allow()}),
    ],
)
