load("@clash//builtin.star", "builtins")
load("@clash//sandboxes.star", "readonly", "workspace", "git_safe", "git_full")

policy("default",
    {
        mode("plan"): {
            glob("**"): allow(sandbox=readonly),
            Tool("Bash"): {
                "git": {
                    glob("**"): allow(sandbox=git_safe)
                }
            }
        },
        (mode("edit"), mode("default")): {
            Tool("Bash"): {
                "git": {
                    glob("**"): allow(sandbox=git_full)
                }
            }
        },
        mode("unrestricted"): {
            glob("**"): allow(sandbox=workspace),
        },
    },
)
