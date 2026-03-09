load("@clash//std.star", "exe", "policy", "sandbox", "home", "path", "tool")

clashbox = sandbox(
    name = "clash_box",
    default = deny,
    fs = [
        home().child(".clash").allow(read = True),
    ],
    net = allow,
)

clash = policy(
    default = deny,
    rules = [
        exe("clash", args = ["bug"]).sandbox(clashbox).allow(),
        exe("clash", args = ["status"]).sandbox(clashbox).allow(),
        exe("clash", args = ["policy", "list"]).sandbox(clashbox).allow(),
        exe("clash", args = ["policy", "show"]).sandbox(clashbox).allow(),
        exe("clash", args = ["policy", "explain"]).sandbox(clashbox).allow(),
        exe("clash", args = ["policy", "schema"]).allow(),
        exe("clash", args = ["policy", "setup"]).sandbox(clashbox).ask(),
    ],
)

_claude_fs = sandbox(name = "claude_fs", fs = [
    home().child(".claude").allow(read = True, write = True),
    path(env = "TRANSCRIPT_DIR").allow(read = True),
])

claude = policy(default = deny, rules = [
    tool([
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
        "ToolSearch",
    ]).sandbox(_claude_fs).allow(),
])

base = clash.merge(claude)
