load("@clash//builtin.star", "builtins")
load("@clash//sandboxes.star", "plan", "edit", "safe_yolo")

policy("default",
    {
        mode("plan"): {
            glob("**"): allow(sandbox=plan),
        },
        (mode("edit"), mode("default")): {
            tool("Bash"): {
                "git": {
                    glob("**"): allow(sandbox=git)
                }
            }
        },
        mode("unrestricted"): {
            glob("**"): allow(sandbox=safe_yolo),
        },
    },
)
