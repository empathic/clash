load("@clash//builtin.star", "builtins")
load("@clash//std.star", "allow", "ask", "deny", "exe", "tool", "policy", "sandbox", "cwd", "home")
load("@clash//sandboxes.star", "{preset}")

# Tighter sandbox for Claude fs tools (no execute, scoped to cwd + ~/.claude)
_fs_box = sandbox(
    name = "cwd",
    fs = [
        cwd(follow_worktrees = True).recurse().allow(read = True, write = True),
        home().child(".claude").recurse().allow(read = True, write = True),
    ],
)

def main():
    return policy(
        default = ask(),
        default_sandbox = {preset},
        rules = builtins + [
            # Claude fs tools
            tool(["Read", "Glob", "Grep"]).sandbox(_fs_box).allow(),
            tool(["Write", "Edit", "NotebookEdit"]).sandbox(_fs_box).allow(),

            # Network tools — prompt user
            tool(["WebFetch", "WebSearch"]).ask(),

            # Deny destructive git ops
            exe("git", args=["push", "--force"]).deny(),
            exe("git", args=["push", "--force-with-lease"]).deny(),
            exe("git", args=["reset", "--hard"]).deny(),

            # All other commands — sandboxed
            exe().sandbox({preset}).allow(),
        ],
    )
