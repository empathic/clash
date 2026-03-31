load("@clash//builtin.star", "builtins")
load("@clash//sandboxes.star", "plan", "edit", "safe_yolo")


policy("default",
    {
        mode("plan"): {
            glob("**"): allow(sandbox=plan),
        },
        (mode("edit"), mode("default")): {
            glob("**"): allow(sandbox=edit),
        },
        mode("unrestricted"): {
            glob("**"): allow(sandbox=safe_yolo),
        },
    },
)
