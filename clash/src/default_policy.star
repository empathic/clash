load("@clash//builtin.star", "builtins")
load("@clash//sandboxes.star", "readonly", "workspace", "git_ro", "git_rw")

policy("default",
    {
        mode("plan"): {
            glob("**"): allow(sandbox=readonly),
            Tool("Bash"): {
                "git": {
                    glob("**"): allow(sandbox=git_ro)
                }
            }
        },
        (mode("edit"), mode("default")): {
            Tool("Bash"): {
                "git": {
                    glob("**"): allow(sandbox=git_rw)
                }
            }
        },
        mode("unrestricted"): {
            glob("**"): allow(sandbox=workspace),
        },
    },
)
