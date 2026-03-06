load("@clash//std.star", "tool", "policy", "home", "path")

def main():
    return policy(default = deny, rules = [
        home().child(".claude", read = allow, write = allow),
        path(env = "TRANSCRIPT_DIR", read = allow),
        tool(["Read", "Write", "Edit", "AskUserQuestion", "EnterPlanMode", "ExitPlanMode", "Skill", "ToolSearch", "EnterWorktree", "NotebookEdit", "TaskCreate", "TaskGet", "TaskList", "TaskOutput", "TaskStop", "TaskUpdate"]).allow(),
    ])
