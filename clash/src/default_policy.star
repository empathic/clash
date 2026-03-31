load("@clash//builtin.star", "builtins")
load("@clash//sandboxes.star", "plan", "edit", "safe_yolo")


policy("default",
    {
        mode("plan"): allow(sandbox=plan),
        mode("edit"): allow(sandbox=edit),
        mode("dangerously_skip_permissions"): allow(sandbox=safe_yolo),
    }
)
