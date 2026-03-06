load("@clash//std.star", "tool", "policy", "sandbox", "home", "path")

_claude_fs = sandbox(fs = [
    home().child(".claude", read = allow, write = allow),
    path(env = "TRANSCRIPT_DIR", read = allow),
])

def main():
    return policy(default = deny, rules = [
        tool(["AskUserQuestion", "EnterPlanMode", "ExitPlanMode", "Skill", "ToolSearch", "EnterWorktree", "TaskCreate", "TaskGet", "TaskList", "TaskOutput", "TaskStop", "TaskUpdate"]).allow(),
    ])
