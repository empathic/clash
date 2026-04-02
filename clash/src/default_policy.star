load("@clash//builtin.star", "builtins")
load("@clash//sandboxes.star", "readonly", "project", "workspace")

policy("default",
    {
        mode("plan"): {
            glob("**"): allow(sandbox=readonly),
        },
        (mode("edit"), mode("default")): {
            tool("Bash"): {
                "git": {
                    glob("**"): allow(sandbox=git)
                }
            }
        },
        mode("unrestricted"): {
            glob("**"): allow(sandbox=workspace),
        },
    },
)
