
clashbox = sandbox(
    name="clash_box",
    default=deny(),
    fs={
        glob("$HOME/.clash/**"): allow("r"),
        glob("$HOME/**"): allow("rx"),
    },
    net=allow(),
)

clash = when({
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
        glob("$HOME/.claude/**"): allow("rwc"),
        glob("$TRANSCRIPT_DIR/**"): allow("r"),
    },
)

claude = when({
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
