load("@clash//std.star", "allow", "ask", "cmd", "deny", "home", "path", "sandbox", "tools")

clashbox = sandbox(
    name="clash_box",
    default=deny(),
    fs=[
        home().child(".clash").recurse().allow(read=True),
        home().recurse().allow(read=True, execute=True),
    ],
    net=allow(),
)

clash = cmd(
    "clash",
    {
        ("bug", "status"): allow(sandbox=clashbox),
        "policy": {
            ("list", "show", "explain"): allow(sandbox=clashbox),
            "schema": allow(),
            "edit": ask(sandbox=clashbox),
        },
    },
)

_claude_fs = sandbox(
    name="claude_fs",
    fs=[
        home().child(".claude").allow(read=True, write=True),
        path(env="TRANSCRIPT_DIR").allow(read=True),
    ],
)

claude = tools({
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
builtins = [clash] + claude
