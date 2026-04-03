load("@clash//builtin.star", "builtins")
load("@clash//sandboxes.star", "readonly", "project", "workspace")

policy("default",
    {
        mode("plan"): {
            glob("**"): allow(sandbox=readonly),
        },
        (mode("edit"), mode("default")): {
            Tool("Bash"): {
                "git": {
                    glob("**"): allow(sandbox=project)
                }
            }
        },
        mode("unrestricted"): {
            glob("**"): allow(sandbox=workspace),
        },
    },
)
