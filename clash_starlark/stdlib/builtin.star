
clashbox = sandbox(
    name="clash_box",
    default=deny(),
    fs={
        "$HOME/.clash": allow("r"),
        "$HOME": allow("rx"),
    },
    net=allow(),
)

clash = match({
    "Bash": {
        "clash": {
            ("bug", "status"): allow(sandbox=clashbox),
            "policy": {
                ("list", "show", "explain"): allow(sandbox=clashbox),
                "schema": allow(),
                "edit": ask(sandbox=clashbox),
            },
        },
    },
})

_claude_fs = sandbox(
    name="claude_fs",
    fs={
        "$HOME/.claude": allow("rwc"),
        "$TRANSCRIPT_DIR": allow("r"),
    },
)

claude = match({
    (
        "Agent",
        "AskUserQuestion",
        "EnterPlanMode",
        "ExitPlanMode",
        "Skill",
        "ToolSearch",
        "EnterWorktree",
        "TaskCreate",
        "TaskGet",
        "TaskList",
        "TaskOutput",
        "TaskStop",
        "TaskUpdate",
    ): allow(sandbox=_claude_fs),
})

# Flat list of all builtin rule nodes
builtins = clash + claude
