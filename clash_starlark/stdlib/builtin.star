
clashbox = sandbox(
    name="clash_box",
    default=deny(),
    fs={
        glob("$HOME/.clash/**"): allow("r"),
        glob("$HOME/**"): allow("rx"),
    },
    net=allow(),
)

clash = {
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
}

_claude_fs = sandbox(
    name="claude_fs",
    fs={
        glob("$HOME/.claude/**"): allow("rwc"),
        glob("$TRANSCRIPT_DIR/**"): allow("r"),
    },
)

claude = {
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
}

# Merged dict of all builtin rules
builtins = merge(clash, claude)
